// Instance roles (TASKS #360): owner (ADMIN_EMAILS), admin (granted in D1) and user.
import { env } from 'cloudflare:workers'
import { describe, expect, it } from 'vitest'
import { AdminEventType } from '../src/admin/service'
import { createSession, freezeRateLimitWindow, login, withEnv } from './helpers'

const P = '/api/cloudwarden/admin'
let n = 0
const unique = (local: string) => `${local}${++n}@example.com`

interface Who {
  email: string
  token: string
  id: string
  over: Record<string, unknown>
  call(path: string, method?: string, body?: unknown): Promise<Response>
}

/** `owner` puts the address in ADMIN_EMAILS; otherwise the list names someone else. */
async function person(local: string, owner = false, extra: Record<string, unknown> = {}) {
  const email = unique(local)
  const s = await createSession(email)
  const over: Record<string, unknown> = {
    ADMIN_ENABLED: 'true',
    ADMIN_EMAILS: owner ? email : 'nobody@example.com',
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
  const who: Who = { email, token: s.access_token, id: profile.id, over, call }
  return who
}

const roleOf = async (id: string) =>
  (
    await env.DB.prepare('SELECT instance_role AS r FROM users WHERE uuid = ?1').bind(id).first<{
      r: string
    }>()
  )?.r

const listed = async (viewer: Who, id: string) => {
  const body = (await (await viewer.call(`${P}/users?pageSize=100`)).json()) as {
    data: { id: string; role: string }[]
  }
  return body.data.find((u) => u.id === id)
}

/** Makes `target` an admin the way the API does, listing `owner` as the instance owner. */
const grant = async (owner: Who, target: Who) => {
  const res = await owner.call(`${P}/users/${target.id}/role`, 'PUT', { role: 'admin' })
  expect(res.status).toBe(204)
}

describe('role in the users list and /me', () => {
  it('lists owner, admin and user, and /me reports the same', async () => {
    const owner = await person('own', true)
    const admin = await person('adm')
    const plain = await person('usr')
    await grant(owner, admin)
    expect((await listed(owner, owner.id))?.role).toBe('owner')
    expect((await listed(owner, admin.id))?.role).toBe('admin')
    expect((await listed(owner, plain.id))?.role).toBe('user')
    // The granted admin sees the same list but ADMIN_EMAILS (its own env) still names an owner elsewhere.
    expect(await (await admin.call('/api/cloudwarden/me')).json()).toMatchObject({
      isAdmin: true,
      role: 'admin',
    })
    expect(await (await plain.call('/api/cloudwarden/me')).json()).toMatchObject({
      isAdmin: false,
      role: 'user',
    })
  })

  it('shows an address in ADMIN_EMAILS as owner even if a stale granted role is stored', async () => {
    const owner = await person('own', true)
    await env.DB.prepare("UPDATE users SET instance_role = 'user' WHERE uuid = ?1")
      .bind(owner.id)
      .run()
    expect((await listed(owner, owner.id))?.role).toBe('owner')
  })
})

describe('granting and revoking', () => {
  it('lets an owner grant and revoke admin, which takes effect on the next request', async () => {
    const owner = await person('own', true)
    const target = await person('tgt')
    expect((await target.call(`${P}/overview`)).status).toBe(403)
    await grant(owner, target)
    expect(await roleOf(target.id)).toBe('admin')
    expect((await target.call(`${P}/overview`)).status).toBe(200)
    const res = await owner.call(`${P}/users/${target.id}/role`, 'PUT', { role: 'user' })
    expect(res.status).toBe(204)
    expect(await roleOf(target.id)).toBe('user')
    expect((await target.call(`${P}/overview`)).status).toBe(403)
  })

  it('also accepts POST', async () => {
    const owner = await person('own', true)
    const target = await person('tgt')
    const res = await owner.call(`${P}/users/${target.id}/role`, 'POST', { role: 'admin' })
    expect(res.status).toBe(204)
    expect(await roleOf(target.id)).toBe('admin')
  })

  it('lets a granted admin change other users', async () => {
    const owner = await person('own', true)
    const admin = await person('adm')
    const target = await person('tgt')
    await grant(owner, admin)
    const res = await admin.call(`${P}/users/${target.id}/role`, 'PUT', { role: 'admin' })
    expect(res.status).toBe(204)
    expect(await roleOf(target.id)).toBe('admin')
    // And can revoke another admin.
    expect((await admin.call(`${P}/users/${target.id}/role`, 'PUT', { role: 'user' })).status).toBe(
      204,
    )
  })

  it('is idempotent and writes no audit event when nothing changes', async () => {
    const owner = await person('own', true)
    const target = await person('tgt')
    expect((await owner.call(`${P}/users/${target.id}/role`, 'PUT', { role: 'user' })).status).toBe(
      204,
    )
    const rows = await env.DB.prepare(
      'SELECT COUNT(*) AS c FROM events WHERE event_type = ?1 AND user_uuid = ?2',
    )
      .bind(AdminEventType.UserRoleChanged, target.id)
      .first<{ c: number }>()
    expect(rows?.c).toBe(0)
  })

  it('returns 404 for an unknown user', async () => {
    const owner = await person('own', true)
    const res = await owner.call(`${P}/users/${crypto.randomUUID()}/role`, 'PUT', { role: 'admin' })
    expect(res.status).toBe(404)
  })

  it('records an audit event naming the actor and the target', async () => {
    const owner = await person('own', true)
    const target = await person('tgt')
    await grant(owner, target)
    await owner.call(`${P}/users/${target.id}/role`, 'PUT', { role: 'user' })
    const { results } = await env.DB.prepare(
      'SELECT user_uuid, acting_user_uuid FROM events WHERE event_type = ?1 AND user_uuid = ?2',
    )
      .bind(AdminEventType.UserRoleChanged, target.id)
      .all<{ user_uuid: string; acting_user_uuid: string }>()
    expect(results).toHaveLength(2)
    expect(results.every((e) => e.acting_user_uuid === owner.id)).toBe(true)
  })
})

describe('refusals', () => {
  it('answers 403 to a non-admin, who cannot promote themselves or others', async () => {
    const plain = await person('usr')
    const other = await person('oth')
    for (const id of [plain.id, other.id]) {
      for (const method of ['PUT', 'POST']) {
        const res = await plain.call(`${P}/users/${id}/role`, method, { role: 'admin' })
        expect(res.status, `${method} ${id}`).toBe(403)
      }
    }
    expect(await roleOf(plain.id)).toBe('user')
    expect(await roleOf(other.id)).toBe('user')
  })

  it('answers 403 to a granted admin when ADMIN_ENABLED is not true', async () => {
    const owner = await person('own', true)
    const admin = await person('adm')
    await grant(owner, admin)
    const res = await withEnv({ ...admin.over, ADMIN_ENABLED: 'false' }, `${P}/users/x/role`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${admin.token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'user' }),
    })
    expect(res.status).toBe(403)
  })

  it('refuses to change an owner, by an owner or an admin', async () => {
    const owner = await person('own', true)
    const other = await person('own2', true)
    const admin = await person('adm')
    await grant(owner, admin)
    // Both owners are listed in ADMIN_EMAILS of the server.
    const both = `${owner.email},${other.email}`
    owner.over.ADMIN_EMAILS = both
    admin.over.ADMIN_EMAILS = both
    for (const who of [owner, admin]) {
      for (const role of ['user', 'admin']) {
        const res = await who.call(`${P}/users/${other.id}/role`, 'PUT', { role })
        expect(res.status).toBe(400)
        expect(await res.json()).toMatchObject({ message: expect.stringMatching(/ADMIN_EMAILS/) })
      }
    }
    expect(await roleOf(other.id)).toBe('user')
  })

  it('refuses a role change on your own account, owner or admin', async () => {
    const owner = await person('own', true)
    const admin = await person('adm')
    await grant(owner, admin)
    const demote = await admin.call(`${P}/users/${admin.id}/role`, 'PUT', { role: 'user' })
    expect(demote.status).toBe(400)
    expect(await demote.json()).toMatchObject({ message: 'You cannot change your own role.' })
    expect(await roleOf(admin.id)).toBe('admin')
    // An owner is refused as an owner, which is also a refusal.
    expect((await owner.call(`${P}/users/${owner.id}/role`, 'PUT', { role: 'user' })).status).toBe(
      400,
    )
  })

  it('refuses to make an unverified user an admin', async () => {
    const owner = await person('own', true)
    const target = await person('tgt')
    await env.DB.prepare('UPDATE users SET verified_at = NULL WHERE uuid = ?1')
      .bind(target.id)
      .run()
    const res = await owner.call(`${P}/users/${target.id}/role`, 'PUT', { role: 'admin' })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ message: expect.stringMatching(/verified/) })
    expect(await roleOf(target.id)).toBe('user')
  })

  it('refuses to make a disabled user an admin', async () => {
    const owner = await person('own', true)
    const target = await person('tgt')
    await env.DB.prepare('UPDATE users SET enabled = 0 WHERE uuid = ?1').bind(target.id).run()
    const res = await owner.call(`${P}/users/${target.id}/role`, 'PUT', { role: 'admin' })
    expect(res.status).toBe(400)
    expect(await res.json()).toMatchObject({ message: expect.stringMatching(/disabled/) })
    expect(await roleOf(target.id)).toBe('user')
  })

  it('still allows revoking admin from an unverified or disabled user', async () => {
    const owner = await person('own', true)
    const target = await person('tgt')
    await grant(owner, target)
    await env.DB.prepare('UPDATE users SET verified_at = NULL, enabled = 0 WHERE uuid = ?1')
      .bind(target.id)
      .run()
    const res = await owner.call(`${P}/users/${target.id}/role`, 'PUT', { role: 'user' })
    expect(res.status).toBe(204)
    expect(await roleOf(target.id)).toBe('user')
  })

  it('validates the role value: never owner, never unknown, never missing', async () => {
    const owner = await person('own', true)
    const target = await person('tgt')
    for (const body of [
      { role: 'owner' },
      { role: 'root' },
      { role: 'ADMIN' },
      { role: 1 },
      { role: null },
      {},
    ]) {
      const res = await owner.call(`${P}/users/${target.id}/role`, 'PUT', body)
      expect(res.status, JSON.stringify(body)).toBe(400)
    }
    expect(
      (
        await withEnv(owner.over, `${P}/users/${target.id}/role`, {
          method: 'PUT',
          headers: { Authorization: `Bearer ${owner.token}`, 'Content-Type': 'application/json' },
          body: 'not json',
        })
      ).status,
    ).toBe(400)
    expect(await roleOf(target.id)).toBe('user')
  })

  it('rate limits the role endpoint like the other admin endpoints', async () => {
    const restore = freezeRateLimitWindow()
    try {
      const owner = await person('own', true)
      const target = await person('tgt')
      await env.DB.prepare(
        'INSERT INTO admin_rate_limits (key, window_start, count) VALUES (?1, ?2, 1000)',
      )
        .bind(`adminapi:${owner.id}`, Math.floor(Date.now() / 60_000) * 60_000)
        .run()
      const res = await owner.call(`${P}/users/${target.id}/role`, 'PUT', { role: 'admin' })
      expect(res.status).toBe(429)
      expect(res.headers.get('retry-after')).toBe('60')
      expect(await roleOf(target.id)).toBe('user')
    } finally {
      restore()
    }
  })
})

describe('what a granted admin keeps', () => {
  it('needs a verified address to act as admin', async () => {
    const owner = await person('own', true)
    const admin = await person('adm')
    await grant(owner, admin)
    await env.DB.prepare('UPDATE users SET verified_at = NULL WHERE uuid = ?1').bind(admin.id).run()
    expect((await admin.call(`${P}/overview`)).status).toBe(403)
    expect(await (await admin.call('/api/cloudwarden/me')).json()).toMatchObject({
      isAdmin: false,
      role: 'admin',
    })
  })

  it('loses the granted role when the email address changes, with or without mail', async () => {
    const owner = await person('own', true)
    const admin = await person('adm')
    await grant(owner, admin)
    const to = unique('moved')
    const req = await admin.call('/api/accounts/email-token', 'POST', {
      newEmail: to,
      masterPasswordHash: 'client-derived-hash',
    })
    expect(req.status).toBe(204)
    const done = await admin.call('/api/accounts/email', 'POST', {
      newEmail: to,
      masterPasswordHash: 'client-derived-hash',
      newMasterPasswordHash: 'client-derived-hash',
      key: '2.newKey',
    })
    expect(done.status).toBe(200)
    expect(await roleOf(admin.id)).toBe('user')
    // Even if the new address is verified later, the admin role does not come back.
    await env.DB.prepare('UPDATE users SET verified_at = ?1 WHERE uuid = ?2')
      .bind(Date.now(), admin.id)
      .run()
    const fresh = (await (await login(to)).json()) as { access_token: string }
    const res = await withEnv(admin.over, `${P}/overview`, {
      headers: { Authorization: `Bearer ${fresh.access_token}` },
    })
    expect(res.status).toBe(403)
  })
})

describe('federation admin checks follow isAdminUser', () => {
  const FED = '/api/cloudwarden/federation'
  const status = (who: Who) =>
    withEnv({ ...who.over, FEDERATION_ENABLED: 'true' }, `${FED}/status`, {
      headers: { Authorization: `Bearer ${who.token}` },
    })

  it('reports isInstanceAdmin for owners and granted admins only, and gates admin routes', async () => {
    const owner = await person('own', true)
    const admin = await person('adm')
    const plain = await person('usr')
    await grant(owner, admin)
    const flag = async (w: Who) => ((await (await status(w)).json()) as any).isInstanceAdmin
    expect(await flag(owner)).toBe(true)
    expect(await flag(admin)).toBe(true)
    expect(await flag(plain)).toBe(false)
    const identity = (w: Who) =>
      withEnv({ ...w.over, FEDERATION_ENABLED: 'true' }, `${FED}/admin/identity`, {
        headers: { Authorization: `Bearer ${w.token}` },
      })
    expect((await identity(plain)).status).toBe(403)
    expect((await identity(admin)).status).toBe(200)
    // Revoking removes access at once.
    await owner.call(`${P}/users/${admin.id}/role`, 'PUT', { role: 'user' })
    expect((await identity(admin)).status).toBe(403)
  })
})
