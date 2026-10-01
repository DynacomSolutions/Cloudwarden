import { type Context, Hono } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { html } from 'hono/html'
import { authenticateAccessToken } from '../auth/middleware'
import { isReservedBlobKey } from '../blob-keys'
import { createEmailTransport, type EmailTransport, inviteEmail, magicLinkEmail } from '../email'
import type { Bindings } from '../env'
import { log } from '../log'
import { SERVER_VERSION } from '../routes/config'
import {
  isAdminEmail,
  isPlausibleEmail,
  normaliseEmail,
  randomToken,
  rateLimit,
  safeEqual,
  sha256Hex,
  verifyAdminToken,
} from './security'
import {
  badge,
  confirmPage,
  flash,
  fmtBytes,
  fmtDate,
  kvTable,
  landingPage,
  layout,
  linkSentPage,
  loginPage,
  magicConfirmPage,
  statsGrid,
} from './views'

const MAGIC_TTL_MS = 15 * 60_000
const SESSION_TTL_MS = 8 * 3600_000
const WINDOW_MS = 15 * 60_000
const COOKIE = 'cw_admin'
const PAGE_SIZE = 50
const TFA_NAMES: Record<number, string> = {
  0: 'Authenticator',
  1: 'Email',
  2: 'Duo',
  3: 'YubiKey',
  6: 'Duo (organisation)',
  7: 'Passkey',
}

interface Session {
  hash: string
  subject: string
  csrf: string
}

type AdminEnv = { Bindings: Bindings; Variables: { nonce: string; session: Session } }
type Ctx = Context<AdminEnv>

export interface AdminDeps {
  /** Override the email transport (tests inject a fake). */
  emailTransport?: (env: Bindings) => EmailTransport
  now?: () => number
}

const MESSAGES: Record<string, string> = {
  disabled: 'User disabled.',
  enabled: 'User enabled.',
  deauth: 'Sessions deauthorised.',
  deleted: 'Deleted.',
  '2fa-removed': 'Two-factor authentication removed and sessions deauthorised.',
  invited: 'Invitation recorded.',
  'invited-nomail': 'Invitation recorded. No email transport is configured, so nothing was sent.',
  'invite-failed': 'Invitation recorded, but the email could not be sent.',
  'invite-bad': 'Enter a valid email address.',
}

const base = (env: Bindings) => env.DOMAIN.replace(/\/+$/, '')

export function createAdmin(deps: AdminDeps = {}) {
  const app = new Hono<AdminEnv>()
  const now = () => (deps.now ? deps.now() : Date.now())
  const transportFor = (env: Bindings) => (deps.emailTransport ?? createEmailTransport)(env)
  const page = (c: Ctx, title: string, body: unknown, nav = true) =>
    c.html(layout(title, c.get('nonce'), body, nav ? navOf(c) : undefined))

  const navOf = (c: Ctx) => ({ subject: c.get('session').subject, csrf: c.get('session').csrf })
  const flashOf = (c: Ctx) => {
    const code = c.req.query('m')
    return flash(code ? MESSAGES[code] : undefined)
  }

  // Gate: 404 unless enabled; security headers; Origin check on every POST.
  const gate = async (c: Ctx, next: () => Promise<void>) => {
    if (c.env.ADMIN_ENABLED !== 'true') {
      return c.json({ message: 'Not found', validationErrors: null, object: 'error' }, 404)
    }
    // One nonce per request, shared by the CSP header and every <style> tag.
    const nonce = c.get('nonce') ?? randomToken(16)
    c.set('nonce', nonce)
    if (c.req.method === 'POST' && !originOk(c)) {
      c.header('Cache-Control', 'no-store')
      return csp(c, nonce).html(
        layout(
          'Forbidden',
          nonce,
          html`<div class="card"><h1>Forbidden</h1><p>Cross-origin request refused.</p></div>`,
        ),
        403,
      )
    }
    await next()
    csp(c, nonce)
  }
  // `/admin/*` also matches `/admin`; registering both ran the gate twice and produced two nonces.
  app.use('/admin/*', gate)

  const csp = (c: Ctx, nonce: string) => {
    c.header(
      'Content-Security-Policy',
      `default-src 'none'; style-src 'nonce-${nonce}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
    )
    c.header('Cache-Control', 'no-store')
    c.header('Referrer-Policy', 'no-referrer')
    c.header('X-Frame-Options', 'DENY')
    return c
  }

  function originOk(c: Ctx): boolean {
    const origin = c.req.header('Origin')
    if (!origin) return false
    const allowed = new Set([new URL(c.req.url).origin, new URL(c.env.DOMAIN).origin])
    return allowed.has(origin)
  }

  async function loadSession(c: Ctx): Promise<Session | null> {
    const raw = getCookie(c, COOKIE, 'host')
    if (!raw) return null
    const hash = await sha256Hex(raw)
    const row = await c.env.DB.prepare(
      `SELECT s.subject, s.csrf_token, s.user_uuid, s.security_stamp, u.security_stamp AS current_stamp,
        u.enabled, u.email
       FROM admin_sessions s LEFT JOIN users u ON u.uuid = s.user_uuid
       WHERE s.session_hash = ?1 AND s.expires_at > ?2`,
    )
      .bind(hash, now())
      .first<{
        subject: string
        csrf_token: string
        user_uuid: string | null
        security_stamp: string | null
        current_stamp: string | null
        enabled: number | null
        email: string | null
      }>()
    if (!row) return null
    // Vault-derived sessions end when the user's stamp rotates, the account is disabled or
    // deleted, or the address leaves ADMIN_EMAILS.
    if (
      row.user_uuid !== null &&
      (!row.enabled ||
        !row.current_stamp ||
        !(await safeEqual(row.security_stamp ?? '', row.current_stamp)) ||
        !isAdminEmail(c.env.ADMIN_EMAILS, normaliseEmail(row.email)))
    ) {
      await c.env.DB.prepare('DELETE FROM admin_sessions WHERE session_hash = ?1').bind(hash).run()
      return null
    }
    return { hash, subject: row.subject, csrf: row.csrf_token }
  }

  async function startSession(
    c: Ctx,
    subject: string,
    user?: { uuid: string; securityStamp: string },
  ) {
    const raw = randomToken()
    const t = now()
    await c.env.DB.batch([
      c.env.DB.prepare('DELETE FROM admin_sessions WHERE expires_at <= ?1').bind(t),
      c.env.DB.prepare('DELETE FROM admin_login_tokens WHERE expires_at <= ?1').bind(
        t - 86_400_000,
      ),
      c.env.DB.prepare(
        `INSERT INTO admin_sessions (session_hash, subject, csrf_token, expires_at, created_at, user_uuid, security_stamp)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
      ).bind(
        await sha256Hex(raw),
        subject,
        randomToken(24),
        t + SESSION_TTL_MS,
        t,
        user?.uuid ?? null,
        user?.securityStamp ?? null,
      ),
    ])
    setCookie(c, COOKIE, raw, {
      prefix: 'host',
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      maxAge: SESSION_TTL_MS / 1000,
    })
  }

  const clientIp = (c: Ctx) => c.req.header('CF-Connecting-IP') ?? 'unknown'

  // Authenticated routes: require a session, and a matching CSRF field on POST.
  const authed = async (c: Ctx, next: () => Promise<void>) => {
    const session = await loadSession(c)
    if (!session) return c.redirect('/admin', 303)
    c.set('session', session)
    if (c.req.method === 'POST') {
      const body = await c.req.parseBody()
      const sent = typeof body.csrf === 'string' ? body.csrf : ''
      if (!(await safeEqual(sent, session.csrf))) {
        return c.html(
          layout(
            'Forbidden',
            c.get('nonce'),
            html`<div class="card"><h1>Forbidden</h1><p>Invalid CSRF token.</p></div>`,
            navOf(c),
          ),
          403,
        )
      }
    }
    await next()
  }
  for (const p of [
    '/admin/users',
    '/admin/users/*',
    '/admin/orgs',
    '/admin/orgs/*',
    '/admin/diagnostics',
    '/admin/logout',
  ]) {
    app.use(p, authed)
  }

  // Login ---------------------------------------------------------------
  app.get('/admin', async (c) => {
    const session = await loadSession(c)
    if (!session) return c.html(landingPage(c.get('nonce')))
    c.set('session', session)
    const db = c.env.DB
    const count = async (sql: string) => (await db.prepare(sql).first<{ n: number }>())?.n ?? 0
    const [users, orgs, ciphers, sends] = await Promise.all([
      count('SELECT COUNT(*) AS n FROM users'),
      count('SELECT COUNT(*) AS n FROM organizations'),
      count('SELECT COUNT(*) AS n FROM ciphers'),
      count('SELECT COUNT(*) AS n FROM sends'),
    ])
    return page(
      c,
      'Dashboard',
      html`<h1>Dashboard</h1>
${statsGrid([
  { label: 'Users', value: users },
  { label: 'Organisations', value: orgs },
  { label: 'Ciphers', value: ciphers },
  { label: 'Sends', value: sends },
])}
<div class="card"><h2>Server</h2></div>
${kvTable(await serverRows(c))}`,
    )
  })

  async function serverRows(c: Ctx): Promise<[string, string | number | boolean][]> {
    const env = c.env
    const transport = transportFor(env)
    return [
      ['Version', SERVER_VERSION],
      ['Domain', env.DOMAIN],
      ['Signups allowed', env.SIGNUPS_ALLOWED === 'true'],
      ['Admin UI enabled', env.ADMIN_ENABLED === 'true'],
      ['Email transport configured', transport.configured],
      ['Magic-link admins configured', Boolean(env.ADMIN_EMAILS?.trim())],
      ['Admin token configured', Boolean(env.ADMIN_TOKEN_HASH)],
      ['JWT secret configured', Boolean(env.JWT_SECRET)],
    ]
  }

  // Vault login exchange ------------------------------------------------
  // The injected web vault script posts the vault's own access token here (never in a URL).
  app.post('/admin/session/exchange', async (c) => {
    const fail = (status: 401 | 403 | 429, message: string) =>
      c.json({ message, validationErrors: null, object: 'error' }, status)
    const fetchSite = c.req.header('Sec-Fetch-Site')
    if (
      c.req.header('Origin') !== new URL(c.env.DOMAIN).origin ||
      (fetchSite !== undefined && fetchSite !== 'same-origin')
    ) {
      return fail(403, 'Cross-origin request refused')
    }
    if (!(await rateLimit(c.env.DB, `ex:ip:${clientIp(c)}`, 30, WINDOW_MS, now()))) {
      return fail(429, 'Too many attempts')
    }
    const match = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')
    const authed = match?.[1] ? await authenticateAccessToken(c.env, match[1]) : null
    if (!authed) return fail(401, 'Unauthorized')
    const email = normaliseEmail(authed.user.email)
    if (!isAdminEmail(c.env.ADMIN_EMAILS, email)) return fail(403, 'Not an admin')
    await startSession(c, email, authed.user)
    return c.body(null, 204)
  })

  // Break-glass recovery ------------------------------------------------
  app.get('/admin/recovery', (c) => c.html(loginPage(c.get('nonce'))))

  app.post('/admin/recovery/magic-link', async (c) => {
    const body = await c.req.parseBody()
    const email = normaliseEmail(body.email)
    const t = now()
    const emailKey = `ml:email:${await sha256Hex(email)}`
    const [ipOk, emailOk] = [
      await rateLimit(c.env.DB, `ml:ip:${clientIp(c)}`, 20, WINDOW_MS, t),
      await rateLimit(c.env.DB, emailKey, 5, WINDOW_MS, t),
    ]
    if (ipOk && emailOk && isPlausibleEmail(email) && isAdminEmail(c.env.ADMIN_EMAILS, email)) {
      const token = randomToken()
      await c.env.DB.prepare(
        'INSERT INTO admin_login_tokens (token_hash, email, expires_at, created_at) VALUES (?1, ?2, ?3, ?4)',
      )
        .bind(await sha256Hex(token), email, t + MAGIC_TTL_MS, t)
        .run()
      const url = `${base(c.env)}/admin/recovery/magic?token=${token}`
      try {
        await transportFor(c.env).send({ to: email, ...magicLinkEmail(url, MAGIC_TTL_MS / 60_000) })
      } catch {
        // Same response either way. Never log the address or link.
        log('error', 'admin.magic_link_delivery_failed', {}, c.env)
      }
    }
    return c.html(linkSentPage(c.get('nonce')))
  })

  // GET never consumes the token: mail scanners prefetch links.
  app.get('/admin/recovery/magic', (c) => {
    const token = c.req.query('token') ?? ''
    return c.html(magicConfirmPage(c.get('nonce'), token.slice(0, 200)))
  })

  app.post('/admin/recovery/magic', async (c) => {
    const body = await c.req.parseBody()
    const token = typeof body.token === 'string' ? body.token : ''
    const t = now()
    const row = token
      ? await c.env.DB.prepare(
          `UPDATE admin_login_tokens SET used_at = ?1
           WHERE token_hash = ?2 AND used_at IS NULL AND expires_at > ?1 RETURNING email`,
        )
          .bind(t, await sha256Hex(token))
          .first<{ email: string }>()
      : null
    if (!row) {
      return c.html(
        loginPage(c.get('nonce'), 'That link is invalid, expired or already used.'),
        400,
      )
    }
    await startSession(c, row.email)
    return c.redirect('/admin', 303)
  })

  app.post('/admin/recovery/token', async (c) => {
    const body = await c.req.parseBody()
    const token = typeof body.token === 'string' ? body.token : ''
    const ok = await rateLimit(c.env.DB, `tk:ip:${clientIp(c)}`, 10, WINDOW_MS, now())
    if (!ok) {
      return c.html(loginPage(c.get('nonce'), 'Too many attempts. Try again later.'), 429)
    }
    if (!(await verifyAdminToken(token, c.env.ADMIN_TOKEN_HASH).catch(() => false))) {
      return c.html(loginPage(c.get('nonce'), 'Invalid token.'), 401)
    }
    await startSession(c, 'token')
    return c.redirect('/admin', 303)
  })

  app.post('/admin/logout', async (c) => {
    await c.env.DB.prepare('DELETE FROM admin_sessions WHERE session_hash = ?1')
      .bind(c.get('session').hash)
      .run()
    deleteCookie(c, COOKIE, { prefix: 'host', secure: true, path: '/' })
    return c.redirect('/admin', 303)
  })

  // Users ---------------------------------------------------------------
  app.get('/admin/users', async (c) => {
    const pageNo = Math.max(1, Number(c.req.query('page')) || 1)
    const { results } = await c.env.DB.prepare(
      `SELECT u.uuid, u.email, u.name, u.created_at, u.enabled,
        (SELECT MAX(d.updated_at) FROM devices d WHERE d.user_uuid = u.uuid) AS last_active,
        (SELECT COUNT(*) FROM ciphers x WHERE x.user_uuid = u.uuid) AS items,
        (SELECT GROUP_CONCAT(t.atype) FROM twofactor t WHERE t.user_uuid = u.uuid AND t.enabled = 1 AND t.atype != 8) AS tfa
       FROM users u ORDER BY u.created_at DESC LIMIT ?1 OFFSET ?2`,
    )
      .bind(PAGE_SIZE + 1, (pageNo - 1) * PAGE_SIZE)
      .all<{
        uuid: string
        email: string
        name: string
        created_at: number
        enabled: number
        last_active: number | null
        items: number
        tfa: string | null
      }>()
    const rows = results.slice(0, PAGE_SIZE)
    const csrf = c.get('session').csrf
    const act = (uuid: string, action: string, label: string) =>
      html`<form class="inline" method="post" action="/admin/users/${uuid}/${action}"><input type="hidden" name="csrf" value="${csrf}"><button class="sm" type="submit">${label}</button></form>`
    const providers = (tfa: string | null) =>
      tfa
        ? tfa
            .split(',')
            .map((n) => TFA_NAMES[Number(n)] ?? `Type ${n}`)
            .join(', ')
        : ''
    const tfaCell = (tfa: string | null) =>
      tfa
        ? html`${badge('ok', '2FA on')} <span class="muted">${providers(tfa)}</span>`
        : badge('off', '2FA off')
    const { results: invites } = await c.env.DB.prepare(
      'SELECT email, created_at FROM invitations ORDER BY created_at DESC LIMIT 50',
    ).all<{ email: string; created_at: number }>()
    return page(
      c,
      'Users',
      html`<h1>Users</h1>${flashOf(c)}
<div class="card wrap"><table><thead><tr><th>User</th><th>Created</th><th>Last active</th><th>Items</th><th>2FA</th><th>Status</th><th>Actions</th></tr></thead><tbody>
${rows.map(
  (
    u,
  ) => html`<tr><td>${u.email}<br><span class="muted">${u.name}</span></td><td>${fmtDate(u.created_at)}</td><td>${fmtDate(u.last_active)}</td><td>${u.items}</td>
<td>${tfaCell(u.tfa)}</td><td>${u.enabled ? badge('ok', 'Enabled') : badge('bad', 'Disabled')}</td>
<td><div class="actions">${u.enabled ? act(u.uuid, 'disable', 'Disable') : act(u.uuid, 'enable', 'Enable')}${act(u.uuid, 'deauth', 'Deauthorise sessions')}${u.tfa ? html`<a class="btn sm" href="/admin/users/${u.uuid}/remove-2fa">Remove 2FA</a>` : ''}<a class="btn sm danger" href="/admin/users/${u.uuid}/delete">Delete</a></div></td></tr>`,
)}
</tbody></table></div>
<p>${pageNo > 1 ? html`<a href="/admin/users?page=${pageNo - 1}">Previous</a> ` : ''}${results.length > PAGE_SIZE ? html`<a href="/admin/users?page=${pageNo + 1}">Next</a>` : ''}</p>
<div class="card"><h2>Invite a user</h2>
<form method="post" action="/admin/users/invite"><input type="hidden" name="csrf" value="${csrf}">
<label for="invite-email">Email address</label><input id="invite-email" type="email" name="email" required>
<p><button class="primary" type="submit">Send invitation</button></p></form></div>
${
  invites.length
    ? html`<div class="card wrap"><h2>Pending invitations</h2><table><tbody>${invites.map((i) => html`<tr><td>${i.email}</td><td>${fmtDate(i.created_at)}</td></tr>`)}</tbody></table></div>`
    : ''
}`,
    )
  })

  const setEnabled = (enabled: 0 | 1, msg: string) => async (c: Ctx) => {
    await c.env.DB.prepare('UPDATE users SET enabled = ?1, updated_at = ?2 WHERE uuid = ?3')
      .bind(enabled, now(), c.req.param('id'))
      .run()
    return c.redirect(`/admin/users?m=${msg}`, 303)
  }
  app.post('/admin/users/:id/disable', setEnabled(0, 'disabled'))
  app.post('/admin/users/:id/enable', setEnabled(1, 'enabled'))

  app.post('/admin/users/:id/deauth', async (c) => {
    await c.env.DB.prepare('UPDATE users SET security_stamp = ?1, updated_at = ?2 WHERE uuid = ?3')
      .bind(crypto.randomUUID(), now(), c.req.param('id'))
      .run()
    return c.redirect('/admin/users?m=deauth', 303)
  })

  app.post('/admin/users/invite', async (c) => {
    const body = await c.req.parseBody()
    const email = normaliseEmail(body.email)
    if (!isPlausibleEmail(email)) return c.redirect('/admin/users?m=invite-bad', 303)
    await c.env.DB.prepare(
      `INSERT INTO invitations (uuid, email, invited_by, created_at) VALUES (?1, ?2, ?3, ?4)
       ON CONFLICT (email) DO NOTHING`,
    )
      .bind(crypto.randomUUID(), email, c.get('session').subject, now())
      .run()
    const transport = transportFor(c.env)
    if (!transport.configured) return c.redirect('/admin/users?m=invited-nomail', 303)
    try {
      await transport.send({
        to: email,
        ...inviteEmail(`${base(c.env)}/#/signup?email=${encodeURIComponent(email)}`),
      })
    } catch {
      log('error', 'admin.invite_delivery_failed', {}, c.env)
      return c.redirect('/admin/users?m=invite-failed', 303)
    }
    return c.redirect('/admin/users?m=invited', 303)
  })

  app.get('/admin/users/:id/remove-2fa', async (c) => {
    const id = c.req.param('id')
    const u = await c.env.DB.prepare('SELECT email FROM users WHERE uuid = ?1')
      .bind(id)
      .first<{ email: string }>()
    if (!u) return c.redirect('/admin/users', 303)
    return c.html(
      confirmPage(
        c.get('nonce'),
        navOf(c),
        'Remove 2FA',
        `Remove every two-factor provider and remembered device for ${u.email}, and sign them out everywhere. They can then log in with their password alone.`,
        `/admin/users/${id}/remove-2fa`,
        '/admin/users',
        'Remove 2FA',
      ),
    )
  })

  app.post('/admin/users/:id/remove-2fa', async (c) => {
    const id = c.req.param('id')
    await c.env.DB.batch([
      c.env.DB.prepare('DELETE FROM twofactor WHERE user_uuid = ?1').bind(id),
      c.env.DB.prepare('UPDATE devices SET twofactor_remember = NULL WHERE user_uuid = ?1').bind(
        id,
      ),
      c.env.DB.prepare(
        'UPDATE users SET totp_recover = NULL, security_stamp = ?2, updated_at = ?3 WHERE uuid = ?1',
      ).bind(id, crypto.randomUUID(), now()),
    ])
    return c.redirect('/admin/users?m=2fa-removed', 303)
  })

  app.get('/admin/users/:id/delete', async (c) => {
    const id = c.req.param('id')
    const u = await c.env.DB.prepare('SELECT email FROM users WHERE uuid = ?1')
      .bind(id)
      .first<{ email: string }>()
    if (!u) return c.redirect('/admin/users', 303)
    return c.html(
      confirmPage(
        c.get('nonce'),
        navOf(c),
        'Delete user',
        `Permanently delete ${u.email} and all of their vault data, sends and attachments. This cannot be undone.`,
        `/admin/users/${id}/delete`,
        '/admin/users',
      ),
    )
  })

  app.post('/admin/users/:id/delete', async (c) => {
    const id = c.req.param('id')
    const { results } = await c.env.DB.prepare(
      `SELECT a.r2_key AS k FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid WHERE c.user_uuid = ?1
       UNION SELECT r2_key FROM sends WHERE user_uuid = ?1 AND r2_key IS NOT NULL`,
    )
      .bind(id)
      .all<{ k: string }>()
    await deleteBlobs(
      c.env,
      results.map((r) => r.k),
    )
    await c.env.DB.prepare('DELETE FROM users WHERE uuid = ?1').bind(id).run()
    return c.redirect('/admin/users?m=deleted', 303)
  })

  // Organisations -------------------------------------------------------
  app.get('/admin/orgs', async (c) => {
    const { results } = await c.env.DB.prepare(
      `SELECT o.uuid, o.name, o.created_at,
        (SELECT COUNT(*) FROM users_organizations m WHERE m.organization_uuid = o.uuid) AS members,
        (SELECT COUNT(*) FROM ciphers x WHERE x.organization_uuid = o.uuid) AS ciphers
       FROM organizations o ORDER BY o.created_at DESC LIMIT 200`,
    ).all<{ uuid: string; name: string; created_at: number; members: number; ciphers: number }>()
    return page(
      c,
      'Organisations',
      html`<h1>Organisations</h1>${flashOf(c)}
<div class="card wrap"><table><thead><tr><th>Name</th><th>Members</th><th>Ciphers</th><th>Created</th><th></th></tr></thead><tbody>
${results.map((o) => html`<tr><td>${o.name}</td><td>${o.members}</td><td>${o.ciphers}</td><td>${fmtDate(o.created_at)}</td><td><a class="btn sm danger" href="/admin/orgs/${o.uuid}/delete">Delete</a></td></tr>`)}
</tbody></table></div>`,
    )
  })

  app.get('/admin/orgs/:id/delete', async (c) => {
    const id = c.req.param('id')
    const o = await c.env.DB.prepare('SELECT name FROM organizations WHERE uuid = ?1')
      .bind(id)
      .first<{ name: string }>()
    if (!o) return c.redirect('/admin/orgs', 303)
    return c.html(
      confirmPage(
        c.get('nonce'),
        navOf(c),
        'Delete organisation',
        `Permanently delete ${o.name}, its collections and its shared items. Member accounts are kept. This cannot be undone.`,
        `/admin/orgs/${id}/delete`,
        '/admin/orgs',
      ),
    )
  })

  app.post('/admin/orgs/:id/delete', async (c) => {
    const id = c.req.param('id')
    const { results } = await c.env.DB.prepare(
      `SELECT a.r2_key AS k FROM attachments a JOIN ciphers c ON c.uuid = a.cipher_uuid WHERE c.organization_uuid = ?1
       UNION SELECT r2_key FROM sends WHERE organization_uuid = ?1 AND r2_key IS NOT NULL`,
    )
      .bind(id)
      .all<{ k: string }>()
    await deleteBlobs(
      c.env,
      results.map((r) => r.k),
    )
    await c.env.DB.prepare('DELETE FROM organizations WHERE uuid = ?1').bind(id).run()
    return c.redirect('/admin/orgs?m=deleted', 303)
  })

  // Diagnostics ---------------------------------------------------------
  app.get('/admin/diagnostics', async (c) => {
    const db = c.env.DB
    const started = Date.now()
    const one = async (sql: string) => (await db.prepare(sql).first<Record<string, number>>()) ?? {}
    const att = await one(
      'SELECT COUNT(*) AS n, COALESCE(SUM(file_size),0) AS bytes FROM attachments',
    )
    const fileSends = await one('SELECT COUNT(*) AS n FROM sends WHERE r2_key IS NOT NULL')
    const inv = await one('SELECT COUNT(*) AS n FROM invitations')
    const sess = await one(`SELECT COUNT(*) AS n FROM admin_sessions WHERE expires_at > ${now()}`)
    const dbMs = Date.now() - started
    return page(
      c,
      'Diagnostics',
      html`<h1>Diagnostics</h1>
<div class="card"><h2>Storage</h2></div>
${kvTable([
  ['Attachments', att.n ?? 0],
  ['Attachment bytes (recorded)', fmtBytes(att.bytes ?? 0)],
  ['File sends', fileSends.n ?? 0],
  ['R2 bucket bound', Boolean(c.env.ATTACHMENTS)],
  ['D1 round trips timing (ms)', dbMs],
])}
<div class="card"><h2>Server and configuration</h2></div>
${kvTable([
  ...(await serverRows(c)),
  ['Pending invitations', inv.n ?? 0],
  ['Active admin sessions', sess.n ?? 0],
])}`,
    )
  })

  async function deleteBlobs(env: Bindings, keys: string[]) {
    const safe = keys.filter((k) => !isReservedBlobKey(k))
    for (let i = 0; i < safe.length; i += 1000)
      await env.ATTACHMENTS.delete(safe.slice(i, i + 1000))
  }

  // Used by the injected web vault script to decide whether to show the admin link.
  app.get('/api/cloudwarden/me', async (c) => {
    c.header('Cache-Control', 'no-store')
    const match = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')
    const authed = match?.[1] ? await authenticateAccessToken(c.env, match[1]) : null
    if (!authed) {
      return c.json({ message: 'Unauthorized', validationErrors: null, object: 'error' }, 401)
    }
    const isAdmin =
      c.env.ADMIN_ENABLED === 'true' &&
      isAdminEmail(c.env.ADMIN_EMAILS, normaliseEmail(authed.user.email))
    return c.json({ isAdmin })
  })

  return app
}

export const admin = createAdmin()
