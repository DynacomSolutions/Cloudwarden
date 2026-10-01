import { env } from 'cloudflare:workers'
import { Validator } from '@cfworker/json-schema'
import { describe, expect, it } from 'vitest'
import { parse } from 'yaml'
import raw from '../docs/api/openapi.yaml?raw'
import { AdminEventType } from '../src/admin/service'
import { BASE, createSession, login, withEnv } from './helpers'
import { actor, createOrg, mailbox } from './org-helpers'

const P = '/api/cloudwarden/admin'

// Responses must match the documented schemas.
const spec = parse(raw) as any
const SPEC_URI = 'https://spec.example.com/openapi'
const absolute = (node: any): any => {
  if (Array.isArray(node)) return node.map(absolute)
  if (node && typeof node === 'object') {
    return Object.fromEntries(
      Object.entries(node).map(([k, v]) => [
        k,
        k === '$ref' && typeof v === 'string' && v.startsWith('#/') ? SPEC_URI + v : absolute(v),
      ]),
    )
  }
  return node
}
function matchesSpec(method: string, path: string, status: number, body: unknown) {
  const response = spec.paths[path]?.[method]?.responses?.[String(status)]
  expect(response, `${method} ${path} documents ${status}`).toBeDefined()
  const schema = response.content?.['application/json']?.schema
  const validator = new Validator(absolute(schema), '2020-12', false)
  validator.addSchema({ $id: SPEC_URI, components: absolute(spec.components) })
  const result = validator.validate(body)
  expect(result.valid, JSON.stringify(result.errors.slice(0, 3))).toBe(true)
}
let n = 0
const unique = (local: string) => `${local}${++n}@example.com`

interface Who {
  email: string
  token: string
  id: string
  over: Record<string, unknown>
  call(path: string, method?: string, body?: unknown): Promise<Response>
}

async function person(
  local: string,
  admin: boolean,
  extra: Record<string, unknown> = {},
): Promise<Who> {
  const email = unique(local)
  const s = await createSession(email)
  const over = {
    ADMIN_ENABLED: 'true',
    ADMIN_EMAILS: admin ? email : 'nobody@example.com',
    ...extra,
  }
  const call = (path: string, method = 'GET', body?: unknown) =>
    withEnv(over, path, {
      method,
      headers: {
        Authorization: `Bearer ${s.access_token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
  const profile = (await (await call('/api/accounts/profile')).json()) as { id: string }
  return { email, token: s.access_token, id: profile.id, over, call }
}

async function createSessionFor(email: string) {
  const res = await login(email)
  return ((await res.json()) as { access_token: string }).access_token
}

const events = async (type: number) =>
  (
    await env.DB.prepare('SELECT * FROM events WHERE event_type = ?1').bind(type).all<{
      user_uuid: string | null
      organization_uuid: string | null
      acting_user_uuid: string | null
    }>()
  ).results

describe('admin API access control', () => {
  const routes: [string, string][] = [
    ['GET', '/overview'],
    ['GET', '/users'],
    ['GET', '/invitations'],
    ['GET', '/organizations'],
    ['GET', '/diagnostics'],
    ['POST', '/users/x/disable'],
    ['POST', '/users/x/enable'],
    ['POST', '/users/x/deauthorize'],
    ['POST', '/users/x/remove-2fa'],
    ['DELETE', '/users/x'],
    ['POST', '/invitations'],
    ['DELETE', '/invitations/a%40example.com'],
    ['DELETE', '/organizations/x'],
  ]

  it('answers 401 in the standard error shape without a bearer token', async () => {
    for (const [method, path] of routes) {
      const res = await withEnv({ ADMIN_ENABLED: 'true' }, `${P}${path}`, { method })
      expect(res.status, `${method} ${path}`).toBe(401)
      expect(await res.json()).toEqual({
        message: 'Unauthorized',
        validationErrors: null,
        object: 'error',
      })
    }
  })

  it('answers 403 for a signed-in user who is not an admin, on every route', async () => {
    const u = await person('plain', false)
    for (const [method, path] of routes) {
      const res = await u.call(`${P}${path}`, method, method === 'POST' ? {} : undefined)
      expect(res.status, `${method} ${path}`).toBe(403)
      expect(res.headers.get('cache-control')).toBe('no-store')
      expect(await res.json()).toEqual({
        message: 'Forbidden',
        validationErrors: null,
        object: 'error',
      })
    }
  })

  it('answers 403 for a listed admin when ADMIN_ENABLED is not true', async () => {
    const a = await person('off', true)
    const res = await withEnv({ ...a.over, ADMIN_ENABLED: 'false' }, `${P}/overview`, {
      headers: { Authorization: `Bearer ${a.token}` },
    })
    expect(res.status).toBe(403)
  })

  it('matches admin addresses case-insensitively', async () => {
    const a = await person('case', true)
    const res = await a.call(`${P}/overview`)
    expect(res.status).toBe(200)
    const upper = await withEnv(
      { ...a.over, ADMIN_EMAILS: ` ${a.email.toUpperCase()} ` },
      `${P}/overview`,
      {
        headers: { Authorization: `Bearer ${a.token}` },
      },
    )
    expect(upper.status).toBe(200)
  })

  it('rate limits per admin and does not count other admins', async () => {
    const a = await person('rl', true)
    const b = await person('rl', true)
    await env.DB.prepare(
      'INSERT INTO admin_rate_limits (key, window_start, count) VALUES (?1, ?2, 1000)',
    )
      .bind(`adminapi:${a.id}`, Math.floor(Date.now() / 60_000) * 60_000)
      .run()
    const limited = await a.call(`${P}/overview`)
    expect(limited.status).toBe(429)
    expect(limited.headers.get('retry-after')).toBe('60')
    expect((await limited.json()) as { object: string }).toMatchObject({ object: 'error' })
    expect((await b.call(`${P}/overview`)).status).toBe(200)
  })
})

describe('admin API hardening', () => {
  it('refuses an admin address that is not email verified, on the API and /me', async () => {
    const a = await person('unver', true)
    await env.DB.prepare('UPDATE users SET verified_at = NULL WHERE uuid = ?1').bind(a.id).run()
    expect((await a.call(`${P}/overview`)).status).toBe(403)
    expect(await (await a.call('/api/cloudwarden/me')).json()).toEqual({
      isAdmin: false,
      email: a.email,
    })
  })

  it('rate limits before the admin check, so non-admins are counted too', async () => {
    const u = await person('rlplain', false)
    await env.DB.prepare(
      'INSERT INTO admin_rate_limits (key, window_start, count) VALUES (?1, ?2, 1000)',
    )
      .bind(`adminapi:${u.id}`, Math.floor(Date.now() / 60_000) * 60_000)
      .run()
    expect((await u.call(`${P}/overview`)).status).toBe(429)
  })

  it('refuses destructive actions against other admin accounts but allows enabling', async () => {
    const a = await person('boss', true)
    const other = await person('boss2', true)
    // Make the first admin list both addresses.
    a.over.ADMIN_EMAILS = `${a.email},${other.email}`
    for (const [method, path] of [
      ['POST', 'disable'],
      ['POST', 'deauthorize'],
      ['POST', 'remove-2fa'],
      ['DELETE', ''],
    ] as const) {
      const res = await a.call(`${P}/users/${other.id}${path ? `/${path}` : ''}`, method)
      expect(res.status, `${method} ${path}`).toBe(400)
      expect(await res.json()).toMatchObject({
        message: expect.stringMatching(/admin account/),
        object: 'error',
      })
    }
    expect((await other.call('/api/accounts/profile')).status).toBe(200)
    expect((await a.call(`${P}/users/${other.id}/enable`, 'POST')).status).toBe(204)
    // Self deauthorize is refused for the same reason.
    expect((await a.call(`${P}/users/${a.id}/deauthorize`, 'POST')).status).toBe(400)
  })

  it('keeps admin audit events out of the affected user feed', async () => {
    const a = await person('feedadmin', true)
    const t = await person('feedtarget', false)
    expect((await a.call(`${P}/users/${t.id}/deauthorize`, 'POST')).status).toBe(204)
    // The stamp rotated, so sign the target in again for a fresh token.
    const fresh = await createSessionFor(t.email)
    await env.DB.prepare(
      'INSERT INTO events (uuid, event_type, user_uuid, event_date) VALUES (?1, 1000, ?2, ?3)',
    )
      .bind(crypto.randomUUID(), t.id, Date.now())
      .run()
    const res = await withEnv({}, '/api/events', { headers: { Authorization: `Bearer ${fresh}` } })
    expect(res.status).toBe(200)
    const body = (await res.json()) as { data: { type: number }[] }
    expect(body.data.map((e) => e.type)).toContain(1000)
    expect(body.data.every((e) => e.type < 9001 || e.type > 9008)).toBe(true)
    const rows = await events(AdminEventType.UserDeauthorized)
    expect(rows.some((e) => e.user_uuid === t.id)).toBe(true)
  })
})

describe('GET /api/cloudwarden/me', () => {
  it('reports isAdmin and email', async () => {
    const a = await person('me', true)
    const u = await person('me', false)
    expect(await (await a.call('/api/cloudwarden/me')).json()).toEqual({
      isAdmin: true,
      email: a.email,
    })
    expect(await (await u.call('/api/cloudwarden/me')).json()).toEqual({
      isAdmin: false,
      email: u.email,
    })
    const res = await a.call('/api/cloudwarden/me')
    expect(res.headers.get('cache-control')).toBe('no-store')
  })
})

describe('admin API reads', () => {
  it('overview returns counts, version and config flags', async () => {
    const a = await person('ov', true)
    const res = await a.call(`${P}/overview`)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const body = (await res.json()) as any
    expect(body.counts.users).toBeGreaterThanOrEqual(1)
    expect(Object.keys(body.counts).sort()).toEqual(['ciphers', 'organizations', 'sends', 'users'])
    expect(typeof body.version).toBe('string')
    expect(body).toMatchObject({
      domain: BASE,
      signupsAllowed: true,
      adminEnabled: true,
      emailConfigured: false,
      magicLinkAdminsConfigured: true,
      jwtSecretConfigured: true,
    })
    expect(JSON.stringify(body)).not.toMatch(/secret-test/)
    matchesSpec('get', `${P}/overview`, 200, body)
  })

  it('lists users with the documented fields and paginates', async () => {
    const a = await person('list', true)
    const b = await person('list', false)
    await env.DB.prepare(
      "INSERT INTO twofactor (uuid,user_uuid,atype,enabled,data,last_used) VALUES ('tf-a',?1,0,1,'x',0),('tf-b',?1,8,1,'x',0)",
    )
      .bind(b.id)
      .run()
    const res = await a.call(`${P}/users?pageSize=100`)
    expect(res.status).toBe(200)
    const body = (await res.json()) as any
    matchesSpec('get', `${P}/users`, 200, body)
    expect(body).toMatchObject({ object: 'list', page: 1, pageSize: 100 })
    expect(body.total).toBeGreaterThanOrEqual(2)
    const row = body.data.find((u: any) => u.id === b.id)
    expect(row).toEqual({
      id: b.id,
      email: b.email,
      name: 'Test User',
      createdAt: expect.stringMatching(/^\d{4}-\d\d-\d\dT/),
      lastActive: expect.stringMatching(/^\d{4}-\d\d-\d\dT/),
      itemCount: 0,
      twoFactorProviders: [{ type: 0, name: 'Authenticator' }],
      enabled: true,
      emailVerified: true,
    })
    await env.DB.prepare('UPDATE users SET verified_at = NULL WHERE uuid = ?1').bind(b.id).run()
    const again = (await (await a.call(`${P}/users?pageSize=100`)).json()) as any
    expect(again.data.find((u: any) => u.id === b.id).emailVerified).toBe(false)
    // Pagination: pages do not overlap and hasMore is accurate.
    const p1 = (await (await a.call(`${P}/users?pageSize=1&page=1`)).json()) as any
    const p2 = (await (await a.call(`${P}/users?pageSize=1&page=2`)).json()) as any
    expect(p1.data).toHaveLength(1)
    expect(p2.data).toHaveLength(1)
    expect(p1.data[0].id).not.toBe(p2.data[0].id)
    expect(p1.hasMore).toBe(true)
    const last = (await (await a.call(`${P}/users?pageSize=1&page=${body.total}`)).json()) as any
    expect(last.hasMore).toBe(false)
  })

  it('rejects bad pagination and clamps pageSize', async () => {
    const a = await person('pg', true)
    const bad = await a.call(`${P}/users?page=0`)
    expect(bad.status).toBe(400)
    expect(await bad.json()).toMatchObject({
      object: 'error',
      validationErrors: { page: [expect.any(String)] },
    })
    expect((await a.call(`${P}/users?pageSize=abc`)).status).toBe(400)
    const big = (await (await a.call(`${P}/users?pageSize=100000`)).json()) as any
    expect(big.pageSize).toBe(100)
  })

  it('lists organisations with counts and diagnostics', async () => {
    const a = await person('orgs', true)
    const owner = await actor(unique('owner'))
    const org = await createOrg(owner, 'Counted')
    const list = (await (await a.call(`${P}/organizations`)).json()) as any
    const row = list.data.find((o: any) => o.id === org.id)
    expect(row).toMatchObject({ name: 'Counted', memberCount: 1, itemCount: 0 })
    const diag = (await (await a.call(`${P}/diagnostics`)).json()) as any
    matchesSpec('get', `${P}/diagnostics`, 200, diag)
    matchesSpec('get', `${P}/organizations`, 200, list)
    expect(diag.storage).toMatchObject({ attachments: expect.any(Number), r2Bound: true })
    expect(diag.server.version).toEqual(expect.any(String))
    expect(diag).toMatchObject({
      pendingInvitations: expect.any(Number),
      activeAdminSessions: expect.any(Number),
    })
  })
})

describe('admin API user actions', () => {
  it('disables and enables a user, and a disabled user is locked out', async () => {
    const a = await person('act', true)
    const t = await person('target', false)
    const r = await a.call(`${P}/users/${t.id}/disable`, 'POST')
    expect(r.status).toBe(204)
    expect((await t.call('/api/accounts/profile')).status).toBe(401)
    const row = (await (await a.call(`${P}/users?pageSize=100`)).json()) as any
    expect(row.data.find((u: any) => u.id === t.id).enabled).toBe(false)
    expect((await a.call(`${P}/users/${t.id}/enable`, 'POST')).status).toBe(204)
    expect((await t.call('/api/accounts/profile')).status).toBe(200)
    expect(
      (await events(AdminEventType.UserDisabled)).some(
        (e) => e.user_uuid === t.id && e.acting_user_uuid === a.id,
      ),
    ).toBe(true)
    expect(
      (await events(AdminEventType.UserEnabled)).some(
        (e) => e.user_uuid === t.id && e.acting_user_uuid === a.id,
      ),
    ).toBe(true)
  })

  it('refuses to disable yourself', async () => {
    const a = await person('selfdis', true)
    const res = await a.call(`${P}/users/${a.id}/disable`, 'POST')
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ object: 'error' })
    expect((await a.call('/api/accounts/profile')).status).toBe(200)
  })

  it('deauthorizes a user by rotating the security stamp', async () => {
    const a = await person('deauth', true)
    const t = await person('target', false)
    expect((await a.call(`${P}/users/${t.id}/deauthorize`, 'POST')).status).toBe(204)
    expect((await t.call('/api/accounts/profile')).status).toBe(401)
    expect((await events(AdminEventType.UserDeauthorized)).some((e) => e.user_uuid === t.id)).toBe(
      true,
    )
  })

  it('removes two-factor providers and recovery code and signs the user out', async () => {
    const a = await person('rm2fa', true)
    const t = await person('target', false)
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO twofactor (uuid,user_uuid,atype,enabled,data,last_used) VALUES (?1,?2,0,1,'x',0)",
      ).bind(crypto.randomUUID(), t.id),
      env.DB.prepare("UPDATE users SET totp_recover = 'code' WHERE uuid = ?1").bind(t.id),
    ])
    expect((await a.call(`${P}/users/${t.id}/remove-2fa`, 'POST')).status).toBe(204)
    const left = await env.DB.prepare('SELECT COUNT(*) n FROM twofactor WHERE user_uuid = ?1')
      .bind(t.id)
      .first<{ n: number }>()
    expect(left?.n).toBe(0)
    const u = await env.DB.prepare('SELECT totp_recover r FROM users WHERE uuid = ?1')
      .bind(t.id)
      .first<{ r: string | null }>()
    expect(u?.r).toBeNull()
    expect((await t.call('/api/accounts/profile')).status).toBe(401)
    expect(
      (await events(AdminEventType.UserTwoFactorRemoved)).some((e) => e.user_uuid === t.id),
    ).toBe(true)
  })

  it('answers 404 for an unknown user on every action', async () => {
    const a = await person('nf', true)
    for (const [m, p] of [
      ['POST', 'disable'],
      ['POST', 'enable'],
      ['POST', 'deauthorize'],
      ['POST', 'remove-2fa'],
    ]) {
      const res = await a.call(`${P}/users/nope/${p}`, m)
      expect(res.status, p).toBe(404)
      expect(await res.json()).toMatchObject({ object: 'error', validationErrors: null })
    }
    expect((await a.call(`${P}/users/nope`, 'DELETE')).status).toBe(404)
  })

  it('deletes a user and audits it', async () => {
    const a = await person('del', true)
    const t = await person('target', false)
    expect((await a.call(`${P}/users/${t.id}`, 'DELETE')).status).toBe(204)
    const gone = await env.DB.prepare('SELECT COUNT(*) n FROM users WHERE uuid = ?1')
      .bind(t.id)
      .first<{ n: number }>()
    expect(gone?.n).toBe(0)
    expect((await a.call(`${P}/users/${t.id}`, 'DELETE')).status).toBe(404)
    expect(
      (await events(AdminEventType.UserDeleted)).some(
        (e) => e.user_uuid === t.id && e.acting_user_uuid === a.id,
      ),
    ).toBe(true)
  })

  it('refuses to delete yourself', async () => {
    const a = await person('selfdel', true)
    const res = await a.call(`${P}/users/${a.id}`, 'DELETE')
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({
      message: expect.stringMatching(/own account/),
      object: 'error',
    })
    expect((await a.call('/api/accounts/profile')).status).toBe(200)
  })

  it('refuses to delete the sole owner of an organisation, as account deletion does', async () => {
    const a = await person('solo', true)
    const mb = mailbox()
    const owner = await actor(unique('soleowner'), mb)
    await createOrg(owner, 'Sole')
    const res = await a.call(`${P}/users/${owner.uuid}`, 'DELETE')
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({
      message: expect.stringMatching(/only owner/),
      object: 'error',
    })
    const still = await env.DB.prepare('SELECT COUNT(*) n FROM users WHERE uuid = ?1')
      .bind(owner.uuid)
      .first<{ n: number }>()
    expect(still?.n).toBe(1)
  })
})

describe('admin API invitations', () => {
  it('creates, lists, de-duplicates and deletes invitations', async () => {
    const a = await person('inv', true)
    const addr = unique('invitee')
    const created = await a.call(`${P}/invitations`, 'POST', { email: `  ${addr.toUpperCase()} ` })
    expect(created.status).toBe(201)
    const createdBody = await created.clone().json()
    matchesSpec('post', `${P}/invitations`, 201, createdBody)
    expect(await created.json()).toEqual({
      email: addr,
      createdAt: expect.any(String),
      emailStatus: 'not-configured',
    })
    const again = await a.call(`${P}/invitations`, 'POST', { email: addr })
    expect(again.status).toBe(200)
    const list = (await (await a.call(`${P}/invitations`)).json()) as any
    matchesSpec('get', `${P}/invitations`, 200, list)
    expect(list.data.filter((i: any) => i.email === addr)).toHaveLength(1)
    const inv = await env.DB.prepare('SELECT invited_by FROM invitations WHERE email = ?1')
      .bind(addr)
      .first<{ invited_by: string }>()
    expect(inv?.invited_by).toBe(a.email)
    expect(
      (await events(AdminEventType.InvitationCreated)).some((e) => e.acting_user_uuid === a.id),
    ).toBe(true)
    // No address in the audit trail.
    const raw = await env.DB.prepare('SELECT * FROM events').all()
    expect(JSON.stringify(raw.results)).not.toContain(addr)

    expect((await a.call(`${P}/invitations/${encodeURIComponent(addr)}`, 'DELETE')).status).toBe(
      204,
    )
    expect((await a.call(`${P}/invitations/${encodeURIComponent(addr)}`, 'DELETE')).status).toBe(
      404,
    )
    expect(
      (await events(AdminEventType.InvitationDeleted)).some((e) => e.acting_user_uuid === a.id),
    ).toBe(true)
  })

  it('emails the invitation when a transport is configured', async () => {
    const mb = mailbox()
    const a = await person('invmail', true, { EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM })
    const addr = unique('mailed')
    const res = await a.call(`${P}/invitations`, 'POST', { email: addr })
    expect(res.status).toBe(201)
    expect(((await res.json()) as any).emailStatus).toBe('sent')
    expect(mb.sent.map((m) => m.to)).toContain(addr)
  })

  it('reports a failed delivery without failing the request', async () => {
    const a = await person('invfail', true, {
      EMAIL: {
        send: async () => {
          throw new Error('boom')
        },
      },
      MAIL_FROM: 'Cloudwarden <noreply@example.com>',
    })
    const res = await a.call(`${P}/invitations`, 'POST', { email: unique('failed') })
    expect(res.status).toBe(201)
    expect(((await res.json()) as any).emailStatus).toBe('failed')
  })

  it('validates the address', async () => {
    const a = await person('invbad', true)
    for (const body of [{ email: 'nope' }, {}, { email: 5 }]) {
      const res = await a.call(`${P}/invitations`, 'POST', body)
      expect(res.status).toBe(400)
      expect(await res.json()).toMatchObject({
        object: 'error',
        validationErrors: { email: [expect.any(String)] },
      })
    }
    const notJson = await withEnv(a.over, `${P}/invitations`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${a.token}`, 'Content-Type': 'application/json' },
      body: '{',
    })
    expect(notJson.status).toBe(400)
  })
})

describe('admin API organisations', () => {
  it('deletes an organisation but keeps its members, and audits it', async () => {
    const a = await person('delorg', true)
    const owner = await actor(unique('orgowner'))
    const org = await createOrg(owner, 'Doomed')
    expect((await a.call(`${P}/organizations/${org.id}`, 'DELETE')).status).toBe(204)
    const row = await env.DB.prepare('SELECT COUNT(*) n FROM organizations WHERE uuid = ?1')
      .bind(org.id)
      .first<{ n: number }>()
    expect(row?.n).toBe(0)
    expect((await owner.call('/api/accounts/profile')).status).toBe(200)
    expect((await a.call(`${P}/organizations/${org.id}`, 'DELETE')).status).toBe(404)
    expect(
      (await events(AdminEventType.OrganizationDeleted)).some(
        (e) => e.organization_uuid === org.id && e.acting_user_uuid === a.id,
      ),
    ).toBe(true)
  })
})
