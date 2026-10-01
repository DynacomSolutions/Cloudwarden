import { env } from 'cloudflare:workers'
import { Hono } from 'hono'
import { beforeEach, describe, expect, it } from 'vitest'
import { createAdmin } from '../src/admin/app'
import { sha256Hex, verifyAdminToken } from '../src/admin/security'
import type { EmailMessage, EmailTransport } from '../src/email'
import { bindingTransport, buildMime, createEmailTransport } from '../src/email'
import type { Bindings } from '../src/env'

const ORIGIN = 'https://vault.example.com'
const ADMIN = 'admin@example.com'
const TOKEN = 'correct horse battery staple'

let sent: EmailMessage[] = []
let clock = 1_800_000_000_000
const fake: EmailTransport = {
  configured: true,
  async send(m) {
    sent.push(m)
  },
}

function bindings(over: Partial<Bindings> = {}): Bindings {
  return {
    DB: env.DB,
    ATTACHMENTS: env.ATTACHMENTS,
    NOTIFICATIONS: env.NOTIFICATIONS,
    DOMAIN: ORIGIN,
    SIGNUPS_ALLOWED: 'false',
    ADMIN_ENABLED: 'true',
    ADMIN_EMAILS: `Other@example.com, ${ADMIN.toUpperCase()}`,
    ...over,
  }
}

function client(over: Partial<Bindings> = {}) {
  const app = new Hono()
  app.route('/', createAdmin({ emailTransport: () => fake, now: () => clock }))
  const e = bindings(over)
  const call = (path: string, init: RequestInit = {}) => app.request(`${ORIGIN}${path}`, init, e)
  const post = (
    path: string,
    fields: Record<string, string>,
    headers: Record<string, string> = {},
  ) =>
    call(path, {
      method: 'POST',
      headers: { Origin: ORIGIN, 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
      body: new URLSearchParams(fields),
    })
  return { call, post }
}

const cookieOf = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0] ?? ''
const linkIn = (m: EmailMessage) =>
  /https:\/\/\S+\/admin\/recovery\/magic\?token=[\w-]+/.exec(m.text)?.[0] ?? ''

async function loginViaMagic(c: ReturnType<typeof client>) {
  await c.post('/admin/recovery/magic-link', { email: ADMIN })
  const link = linkIn(sent[0] as EmailMessage)
  const token = new URL(link).searchParams.get('token') ?? ''
  const res = await c.post('/admin/recovery/magic', { token })
  return { res, token }
}

async function csrfOf(c: ReturnType<typeof client>, cookie: string) {
  const html = await (await c.call('/admin/users', { headers: { Cookie: cookie } })).text()
  return /name="csrf" value="([^"]+)"/.exec(html)?.[1] ?? ''
}

beforeEach(async () => {
  sent = []
  clock += 3_600_000 * 24 // fresh rate-limit windows per test
  await env.DB.batch([
    env.DB.prepare('DELETE FROM admin_login_tokens'),
    env.DB.prepare('DELETE FROM admin_sessions'),
    env.DB.prepare('DELETE FROM admin_rate_limits'),
    env.DB.prepare('DELETE FROM invitations'),
    env.DB.prepare('DELETE FROM users'),
  ])
})

describe('admin gating', () => {
  it('returns 404 when disabled', async () => {
    const c = client({ ADMIN_ENABLED: 'false' })
    expect((await c.call('/admin')).status).toBe(404)
    expect((await c.post('/admin/recovery/token', { token: TOKEN })).status).toBe(404)
  })

  it('serves the login page with a strict CSP when enabled', async () => {
    const res = await client().call('/admin')
    expect(res.status).toBe(200)
    const csp = res.headers.get('content-security-policy') ?? ''
    expect(csp).toContain("default-src 'none'")
    expect(csp).not.toContain('unsafe-inline')
    expect(csp).not.toContain('script-src')
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.text()).not.toMatch(/<script|https?:\/\/(?!vault\.example\.com)/)
  })
})

describe('magic link', () => {
  it('happy path: emails a link, GET does not consume, POST signs in', async () => {
    const c = client()
    const res = await c.post('/admin/recovery/magic-link', { email: ADMIN })
    expect(await res.text()).toContain('If that address is an admin, a link was sent')
    expect(sent).toHaveLength(1)
    expect(sent[0]?.to).toBe(ADMIN)
    const link = linkIn(sent[0] as EmailMessage)
    expect(link.startsWith(`${ORIGIN}/admin/recovery/magic?token=`)).toBe(true)
    const token = new URL(link).searchParams.get('token') ?? ''

    // Only the hash is stored.
    const stored = await env.DB.prepare('SELECT token_hash FROM admin_login_tokens').first<{
      token_hash: string
    }>()
    expect(stored?.token_hash).toBe(await sha256Hex(token))
    expect(stored?.token_hash).not.toBe(token)

    // Prefetch via GET twice, then the POST still works.
    for (let i = 0; i < 2; i++) {
      const get = await c.call(`/admin/recovery/magic?token=${token}`)
      expect(get.status).toBe(200)
      expect(await get.text()).toContain('method="post"')
    }
    const login = await c.post('/admin/recovery/magic', { token })
    expect(login.status).toBe(303)
    const dash = await c.call('/admin', { headers: { Cookie: cookieOf(login) } })
    expect(await dash.text()).toContain('Dashboard')
  })

  it('sets a hardened session cookie', async () => {
    const { res } = await loginViaMagic(client())
    const raw = res.headers.get('set-cookie') ?? ''
    expect(raw).toMatch(/^__Host-cw_admin=/)
    expect(raw).toContain('HttpOnly')
    expect(raw).toContain('Secure')
    expect(raw).toContain('SameSite=Strict')
    expect(raw).toContain('Path=/')
    expect(raw).not.toContain('Domain')
    const sessions = await env.DB.prepare('SELECT session_hash FROM admin_sessions').all<{
      session_hash: string
    }>()
    expect(raw).not.toContain(sessions.results[0]?.session_hash ?? 'x')
  })

  it('rejects token reuse', async () => {
    const c = client()
    const { token } = await loginViaMagic(c)
    const again = await c.post('/admin/recovery/magic', { token })
    expect(again.status).toBe(400)
    expect(again.headers.get('set-cookie')).toBeNull()
  })

  it('rejects an expired token', async () => {
    const c = client()
    await c.post('/admin/recovery/magic-link', { email: ADMIN })
    const token = new URL(linkIn(sent[0] as EmailMessage)).searchParams.get('token') ?? ''
    clock += 16 * 60_000
    const res = await c.post('/admin/recovery/magic', { token })
    expect(res.status).toBe(400)
  })

  it('treats non-admin emails identically and sends nothing', async () => {
    const c = client()
    const a = await c.post('/admin/recovery/magic-link', { email: ADMIN })
    const b = await c.post('/admin/recovery/magic-link', { email: 'stranger@example.com' })
    expect(sent).toHaveLength(1)
    expect(b.status).toBe(a.status)
    const strip = (t: string) => t.replace(/nonce="[^"]+"/g, '')
    expect(strip(await b.text())).toBe(strip(await a.text()))
    const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM admin_login_tokens').first<{
      n: number
    }>()
    expect(n?.n).toBe(1)
  })

  it('rate limits per email without changing the response', async () => {
    const c = client()
    for (let i = 0; i < 8; i++) await c.post('/admin/recovery/magic-link', { email: ADMIN })
    expect(sent).toHaveLength(5)
  })

  it('rate limits per IP', async () => {
    const c = client()
    for (let i = 0; i < 25; i++) {
      await c.post(
        '/admin/recovery/magic-link',
        { email: `user${i}@example.com` },
        { 'CF-Connecting-IP': '192.0.2.7' },
      )
    }
    const n = await env.DB.prepare(
      "SELECT count FROM admin_rate_limits WHERE key = 'ml:ip:192.0.2.7'",
    ).first<{ count: number }>()
    expect(n?.count).toBe(25)
    // The limit blocks even an admin address from that IP.
    await c.post(
      '/admin/recovery/magic-link',
      { email: ADMIN },
      { 'CF-Connecting-IP': '192.0.2.7' },
    )
    expect(sent).toHaveLength(0)
  })
})

describe('token login', () => {
  it('accepts a SHA-256 hash and rejects a wrong token', async () => {
    const c = client({ ADMIN_TOKEN_HASH: await sha256Hex(TOKEN) })
    expect((await c.post('/admin/recovery/token', { token: 'nope' })).status).toBe(401)
    const ok = await c.post('/admin/recovery/token', { token: TOKEN })
    expect(ok.status).toBe(303)
    expect(ok.headers.get('set-cookie')).toContain('__Host-cw_admin=')
  })

  it('accepts the PBKDF2 format', async () => {
    const salt = '00112233445566778899aabbccddeeff'
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(TOKEN),
      'PBKDF2',
      false,
      ['deriveBits'],
    )
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: Uint8Array.from(salt.match(/../g) as string[], (h) => Number.parseInt(h, 16)),
        iterations: 1000,
      },
      key,
      256,
    )
    const hex = [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, '0')).join('')
    const stored = `pbkdf2$1000$${salt}$${hex}`
    expect(await verifyAdminToken(TOKEN, stored)).toBe(true)
    expect(await verifyAdminToken('wrong', stored)).toBe(false)
    expect(await verifyAdminToken(TOKEN, `pbkdf2$900000$${salt}$${hex}`)).toBe(false)
    expect(await verifyAdminToken(TOKEN, undefined)).toBe(false)
  })

  it('refuses when no hash is configured', async () => {
    const res = await client().post('/admin/recovery/token', { token: TOKEN })
    expect(res.status).toBe(401)
  })
})

describe('csrf and origin', () => {
  it('rejects a cross-origin or originless POST', async () => {
    const c = client()
    const bad = await c.post(
      '/admin/recovery/magic-link',
      { email: ADMIN },
      { Origin: 'https://evil.example.net' },
    )
    expect(bad.status).toBe(403)
    const none = await c.call('/admin/recovery/magic-link', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ email: ADMIN }),
    })
    expect(none.status).toBe(403)
    expect(sent).toHaveLength(0)
  })

  it('requires the per-session CSRF token on authenticated POSTs', async () => {
    const c = client()
    const { res } = await loginViaMagic(c)
    const cookie = cookieOf(res)
    await env.DB.prepare(
      "INSERT INTO users (uuid,email,name,password_hash,salt,password_iterations,akey,security_stamp,created_at,updated_at) VALUES ('u1','a@example.com','A','h','s',1,'k','stamp1',1,1)",
    ).run()
    const noToken = await c.post('/admin/users/u1/disable', {}, { Cookie: cookie })
    expect(noToken.status).toBe(403)
    const wrong = await c.post('/admin/users/u1/disable', { csrf: 'x' }, { Cookie: cookie })
    expect(wrong.status).toBe(403)
    const u = await env.DB.prepare("SELECT enabled FROM users WHERE uuid='u1'").first<{
      enabled: number
    }>()
    expect(u?.enabled).toBe(1)
    const csrf = await csrfOf(c, cookie)
    const ok = await c.post('/admin/users/u1/disable', { csrf }, { Cookie: cookie })
    expect(ok.status).toBe(303)
    const u2 = await env.DB.prepare("SELECT enabled FROM users WHERE uuid='u1'").first<{
      enabled: number
    }>()
    expect(u2?.enabled).toBe(0)
  })

  it('redirects unauthenticated access to login', async () => {
    const res = await client().call('/admin/users')
    expect(res.status).toBe(303)
  })

  it('expires sessions after 8 hours', async () => {
    const c = client()
    const { res } = await loginViaMagic(c)
    const cookie = cookieOf(res)
    expect((await c.call('/admin/users', { headers: { Cookie: cookie } })).status).toBe(200)
    clock += 8 * 3600_000 + 1
    expect((await c.call('/admin/users', { headers: { Cookie: cookie } })).status).toBe(303)
  })

  it('logout invalidates the session', async () => {
    const c = client()
    const { res } = await loginViaMagic(c)
    const cookie = cookieOf(res)
    const csrf = await csrfOf(c, cookie)
    const out = await c.post('/admin/logout', { csrf }, { Cookie: cookie })
    expect(out.status).toBe(303)
    expect((await c.call('/admin/users', { headers: { Cookie: cookie } })).status).toBe(303)
  })
})

describe('user and org management', () => {
  async function session() {
    const c = client()
    const { res } = await loginViaMagic(c)
    const cookie = cookieOf(res)
    return { c, cookie, csrf: await csrfOf(c, cookie) }
  }
  const seedUser = () =>
    env.DB.prepare(
      "INSERT INTO users (uuid,email,name,password_hash,salt,password_iterations,akey,security_stamp,created_at,updated_at) VALUES ('u1','a@example.com','Alice','h','s',1,'k','stamp1',1,1)",
    ).run()

  it('lists users, rotates security stamp, deletes with cascade', async () => {
    const { c, cookie, csrf } = await session()
    await seedUser()
    await env.DB.prepare(
      "INSERT INTO folders (uuid,user_uuid,name,created_at,updated_at) VALUES ('f1','u1','x',1,1)",
    ).run()
    const list = await (await c.call('/admin/users', { headers: { Cookie: cookie } })).text()
    expect(list).toContain('a@example.com')
    await c.post('/admin/users/u1/deauth', { csrf }, { Cookie: cookie })
    const u = await env.DB.prepare("SELECT security_stamp FROM users WHERE uuid='u1'").first<{
      security_stamp: string
    }>()
    expect(u?.security_stamp).not.toBe('stamp1')
    const confirm = await c.call('/admin/users/u1/delete', { headers: { Cookie: cookie } })
    expect(await confirm.text()).toContain('Delete permanently')
    await c.post('/admin/users/u1/delete', { csrf }, { Cookie: cookie })
    expect(await env.DB.prepare('SELECT 1 FROM users').first()).toBeNull()
    expect(await env.DB.prepare('SELECT 1 FROM folders').first()).toBeNull()
  })

  it('escapes user-controlled values', async () => {
    const { c, cookie } = await session()
    await env.DB.prepare(
      "INSERT INTO users (uuid,email,name,password_hash,salt,password_iterations,akey,security_stamp,created_at,updated_at) VALUES ('u2','b@example.com','<img src=x onerror=1>','h','s',1,'k','s',1,1)",
    ).run()
    const body = await (await c.call('/admin/users', { headers: { Cookie: cookie } })).text()
    expect(body).not.toContain('<img src=x')
    expect(body).toContain('&lt;img')
  })

  it('invites a user by email with a register link', async () => {
    const { c, cookie, csrf } = await session()
    sent = []
    const res = await c.post(
      '/admin/users/invite',
      { csrf, email: 'New.User@example.com' },
      { Cookie: cookie },
    )
    expect(res.headers.get('location')).toContain('m=invited')
    expect(sent).toHaveLength(1)
    expect(sent[0]?.text).toContain(`${ORIGIN}/#/signup?email=new.user%40example.com`)
    const row = await env.DB.prepare('SELECT email FROM invitations').first<{ email: string }>()
    expect(row?.email).toBe('new.user@example.com')
  })

  it('deletes organisations and renders dashboard and diagnostics', async () => {
    const { c, cookie, csrf } = await session()
    await env.DB.prepare(
      "INSERT INTO organizations (uuid,name,billing_email,created_at,updated_at) VALUES ('o1','Acme','b@example.com',1,1)",
    ).run()
    expect(await (await c.call('/admin/orgs', { headers: { Cookie: cookie } })).text()).toContain(
      'Acme',
    )
    await c.post('/admin/orgs/o1/delete', { csrf }, { Cookie: cookie })
    expect(await env.DB.prepare('SELECT 1 FROM organizations').first()).toBeNull()
    for (const p of ['/admin', '/admin/diagnostics']) {
      const res = await c.call(p, { headers: { Cookie: cookie } })
      expect(res.status).toBe(200)
      expect(await res.text()).toContain('Version')
    }
  })
})

describe('email transport', () => {
  it('is a no-op when unbound', async () => {
    const t = createEmailTransport(bindings())
    expect(t.configured).toBe(false)
    await expect(
      t.send({ to: 'a@example.com', subject: 's', text: 't', html: 'h' }),
    ).resolves.toBeUndefined()
  })

  it('calls the Email Service builder form', async () => {
    const calls: unknown[] = []
    const binding = { send: async (m: unknown) => void calls.push(m) } as unknown as SendEmail
    const t = createEmailTransport(bindings({ EMAIL: binding, MAIL_FROM: 'noreply@example.com' }))
    await t.send({ to: 'a@example.com', subject: 'Hi', text: 'T', html: '<p>T</p>' })
    expect(calls).toEqual([
      {
        to: 'a@example.com',
        from: 'noreply@example.com',
        subject: 'Hi',
        html: '<p>T</p>',
        text: 'T',
      },
    ])
  })

  it('does not swallow non-TypeError failures', async () => {
    const binding = {
      send: async () => {
        throw new Error('boom')
      },
    } as unknown as SendEmail
    const t = bindingTransport(binding, 'noreply@example.com')
    await expect(
      t.send({ to: 'a@example.com', subject: 's', text: 't', html: 'h' }),
    ).rejects.toThrow('boom')
  })

  it('builds MIME and refuses header injection', () => {
    const mime = buildMime('noreply@example.com', {
      to: 'a@example.com',
      subject: 'Hi',
      text: 'T',
      html: 'H',
    })
    expect(mime).toContain('multipart/alternative')
    expect(() =>
      buildMime('noreply@example.com', {
        to: 'a@example.com\r\nBcc: x@example.com',
        subject: 'Hi',
        text: 'T',
        html: 'H',
      }),
    ).toThrow()
  })
})

describe('nonce and 2FA removal', () => {
  const nonceOf = (res: Response, html: string) => {
    const header = /style-src 'nonce-([^']+)'/.exec(
      res.headers.get('content-security-policy') ?? '',
    )?.[1]
    const tags = [...html.matchAll(/<style nonce="([^"]+)"/g)].map((m) => m[1])
    expect(header).toBeTruthy()
    expect(tags.length).toBeGreaterThan(0)
    for (const t of tags) expect(t).toBe(header)
  }

  it('uses one nonce for the CSP header and every style tag on every page', async () => {
    const c = client()
    const anon = ['/admin', '/admin/recovery', '/admin/recovery/magic?token=abc']
    for (const path of anon) {
      const res = await c.call(path)
      nonceOf(res, await res.text())
    }
    const link = await c.post('/admin/recovery/magic-link', { email: ADMIN })
    nonceOf(link, await link.text())
    const { res } = await loginViaMagic(c)
    const cookie = cookieOf(res)
    for (const path of ['/admin', '/admin/users', '/admin/orgs', '/admin/diagnostics']) {
      const r = await c.call(path, { headers: { Cookie: cookie } })
      expect(r.status).toBe(200)
      const body = await r.text()
      nonceOf(r, body)
    }
  })

  it('removes 2FA with confirm step and CSRF, rotating the stamp', async () => {
    const c = client()
    const { res } = await loginViaMagic(c)
    const cookie = cookieOf(res)
    const csrf = await csrfOf(c, cookie)
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO users (uuid,email,name,password_hash,salt,password_iterations,akey,security_stamp,totp_recover,created_at,updated_at) VALUES ('u9','z@example.com','Zed','h','s',1,'k','stamp9','RC',1000,1)",
      ),
      env.DB.prepare(
        "INSERT INTO twofactor (uuid,user_uuid,atype,enabled,data,last_used) VALUES ('t1','u9',0,1,'x',0),('t2','u9',1,1,'x',0),('t3','u9',8,1,'x',0)",
      ),
      env.DB.prepare(
        "INSERT INTO devices (uuid,user_uuid,name,type,identifier,refresh_token,twofactor_remember,created_at,updated_at) VALUES ('d9','u9','dev',1,'i9','r','REM',1,5000)",
      ),
      env.DB.prepare(
        "INSERT INTO ciphers (uuid,user_uuid,atype,name,data,created_at,updated_at) VALUES ('c9','u9',1,'n','{}',1,1)",
      ),
    ])
    const list = await (await c.call('/admin/users', { headers: { Cookie: cookie } })).text()
    expect(list).toContain('2FA on')
    expect(list).toContain('Authenticator, Email')
    expect(list).toContain('/admin/users/u9/remove-2fa')

    const confirm = await c.call('/admin/users/u9/remove-2fa', { headers: { Cookie: cookie } })
    expect(await confirm.text()).toContain('name="csrf"')

    const bad = await c.post('/admin/users/u9/remove-2fa', { csrf: 'x' }, { Cookie: cookie })
    expect(bad.status).toBe(403)
    expect(await env.DB.prepare('SELECT 1 FROM twofactor').first()).not.toBeNull()

    const ok = await c.post('/admin/users/u9/remove-2fa', { csrf }, { Cookie: cookie })
    expect(ok.status).toBe(303)
    expect(await env.DB.prepare('SELECT 1 FROM twofactor').first()).toBeNull()
    const dev = await env.DB.prepare(
      "SELECT twofactor_remember AS r FROM devices WHERE uuid='d9'",
    ).first<{ r: string | null }>()
    expect(dev?.r).toBeNull()
    const u = await env.DB.prepare(
      "SELECT security_stamp, totp_recover FROM users WHERE uuid='u9'",
    ).first<{ security_stamp: string; totp_recover: string | null }>()
    expect(u?.security_stamp).not.toBe('stamp9')
    expect(u?.totp_recover).toBeNull()
    const after = await (await c.call('/admin/users', { headers: { Cookie: cookie } })).text()
    expect(after).toContain('2FA off')
    expect(after).not.toContain('/remove-2fa')
  })
})
