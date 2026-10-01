import { env } from 'cloudflare:workers'
import { describe, expect, it } from 'vitest'
import { signingSecret, signJwt } from '../src/auth/jwt'
import { BASE, createSession, withEnv } from './helpers'

const ADMIN_ENV = { ADMIN_ENABLED: 'true', ADMIN_EMAILS: 'boss@example.com, Chief@Example.com' }
let n = 0
const unique = (local: string) => `${local}${++n}@example.com`

const exchange = (token: string, headers: Record<string, string> = {}, over = {}) =>
  withEnv({ ...ADMIN_ENV, ...over }, '/admin/session/exchange', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      Origin: BASE,
      'Sec-Fetch-Site': 'same-origin',
      'CF-Connecting-IP': `198.51.100.${n % 250}`,
      ...headers,
    },
  })
const me = (token: string, over = {}) =>
  withEnv({ ...ADMIN_ENV, ...over }, '/api/cloudwarden/me', {
    headers: { Authorization: `Bearer ${token}` },
  })
const get = (path: string, cookie: string) =>
  withEnv(ADMIN_ENV, path, { headers: { Cookie: cookie }, redirect: 'manual' })
const cookieOf = (res: Response) => (res.headers.get('set-cookie') ?? '').split(';')[0] ?? ''

/** Registers a user whose address is on the admin list (one address per test via ADMIN_EMAILS). */
async function adminSession() {
  const email = unique('admin')
  const s = await createSession(email)
  return {
    email,
    token: s.access_token,
    over: { ADMIN_EMAILS: `x@example.com,${email.toUpperCase()}` },
  }
}

describe('admin session exchange', () => {
  it('exchanges a vault access token for a hardened admin session', async () => {
    const { email, token, over } = await adminSession()
    const res = await exchange(token, {}, over)
    expect(res.status).toBe(204)
    const raw = res.headers.get('set-cookie') ?? ''
    expect(raw).toMatch(/^__Host-cw_admin=/)
    for (const flag of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/', 'Max-Age=3600']) {
      expect(raw).toContain(flag)
    }
    expect(raw).not.toContain('Domain')
    const row = await env.DB.prepare(
      'SELECT s.subject, s.user_uuid FROM admin_sessions s JOIN users u ON u.uuid = s.user_uuid WHERE u.email = ?1',
    )
      .bind(email)
      .first<{ subject: string; user_uuid: string }>()
    expect(row?.subject).toBe(email)
    const users = await withEnv({ ...ADMIN_ENV, ...over }, '/admin/users', {
      headers: { Cookie: cookieOf(res) },
      redirect: 'manual',
    })
    expect(users.status).toBe(200)
    const body = await users.text()
    expect(body).toContain(`Signed in as ${email}`)
    expect(body).toContain('Back to vault')
  })

  it('refuses a non-admin with 403 and no cookie', async () => {
    const s = await createSession(unique('plain'))
    const res = await exchange(s.access_token)
    expect(res.status).toBe(403)
    expect(res.headers.get('set-cookie')).toBeNull()
  })

  it('refuses bad, expired and stamp-rotated tokens with 401', async () => {
    expect((await exchange('not-a-jwt')).status).toBe(401)
    const { token, over } = await adminSession()
    const claims = JSON.parse(
      atob((token.split('.')[1] ?? '').replace(/-/g, '+').replace(/_/g, '/')),
    )
    const expired = await signJwt(
      { ...claims, nbf: 1_000, exp: 2_000 },
      signingSecret(env as never),
    )
    expect((await exchange(expired, {}, over)).status).toBe(401)
    await env.DB.prepare("UPDATE users SET security_stamp = 'rotated' WHERE uuid = ?1")
      .bind(claims.sub)
      .run()
    expect((await exchange(token, {}, over)).status).toBe(401)
  })

  it('rejects cross-origin and cross-site requests', async () => {
    const { token, over } = await adminSession()
    expect((await exchange(token, { Origin: 'https://evil.example.org' }, over)).status).toBe(403)
    expect((await exchange(token, { 'Sec-Fetch-Site': 'same-site' }, over)).status).toBe(403)
    const noOrigin = await withEnv({ ...ADMIN_ENV, ...over }, '/admin/session/exchange', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    })
    expect(noOrigin.status).toBe(403)
  })

  it('is 404 when the admin UI is disabled', async () => {
    const { token, over } = await adminSession()
    expect((await exchange(token, {}, { ...over, ADMIN_ENABLED: 'false' })).status).toBe(404)
  })

  it('ends the admin session when the security stamp rotates', async () => {
    const { token, over } = await adminSession()
    const res = await exchange(token, {}, over)
    const cookie = cookieOf(res)
    const call = () =>
      withEnv({ ...ADMIN_ENV, ...over }, '/admin/users', {
        headers: { Cookie: cookie },
        redirect: 'manual',
      })
    expect((await call()).status).toBe(200)
    const sub = JSON.parse(
      atob((token.split('.')[1] ?? '').replace(/-/g, '+').replace(/_/g, '/')),
    ).sub
    await env.DB.prepare("UPDATE users SET security_stamp = 'new-stamp' WHERE uuid = ?1")
      .bind(sub)
      .run()
    expect((await call()).status).toBe(303)
    const left = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM admin_sessions WHERE user_uuid = ?1',
    )
      .bind(sub)
      .first<{ n: number }>()
    expect(left?.n).toBe(0)
  })

  it('ends the admin session when the address leaves ADMIN_EMAILS', async () => {
    const { token, over } = await adminSession()
    const cookie = cookieOf(await exchange(token, {}, over))
    expect((await get('/admin/users', cookie)).status).toBe(303)
  })
})

describe('exchanged session lifecycle', () => {
  const sessions = async (uuid: string) =>
    (
      await env.DB.prepare(
        'SELECT session_hash, expires_at FROM admin_sessions WHERE user_uuid = ?1',
      )
        .bind(uuid)
        .all<{ session_hash: string; expires_at: number }>()
    ).results
  const subOf = (token: string) =>
    JSON.parse(atob((token.split('.')[1] ?? '').replace(/-/g, '+').replace(/_/g, '/'))).sub

  it('renews the one hour TTL on activity', async () => {
    const { token, over } = await adminSession()
    const cookie = cookieOf(await exchange(token, {}, over))
    const sub = subOf(token)
    await env.DB.prepare('UPDATE admin_sessions SET expires_at = ?1 WHERE user_uuid = ?2')
      .bind(Date.now() + 60_000, sub)
      .run()
    const res = await withEnv({ ...ADMIN_ENV, ...over }, '/admin/users', {
      headers: { Cookie: cookie },
      redirect: 'manual',
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toContain('Max-Age=3600')
    const [row] = await sessions(sub)
    expect(row?.expires_at).toBeGreaterThan(Date.now() + 3_500_000)
  })

  it('replaces the browser prior session on a new exchange', async () => {
    const { token, over } = await adminSession()
    const first = cookieOf(await exchange(token, {}, over))
    await exchange(token, { Cookie: first }, over)
    expect(await sessions(subOf(token))).toHaveLength(1)
  })

  it('ends the session from the vault with a strict same-origin check', async () => {
    const { token, over } = await adminSession()
    const cookie = cookieOf(await exchange(token, {}, over))
    const end = (headers: Record<string, string>) =>
      withEnv({ ...ADMIN_ENV, ...over }, '/admin/session/end', {
        method: 'POST',
        headers: { Cookie: cookie, ...headers },
      })
    expect((await end({ Origin: 'https://evil.example.org' })).status).toBe(403)
    expect((await end({ Origin: BASE, 'Sec-Fetch-Site': 'cross-site' })).status).toBe(403)
    expect(await sessions(subOf(token))).toHaveLength(1)
    const ok = await end({ Origin: BASE, 'Sec-Fetch-Site': 'same-origin' })
    expect(ok.status).toBe(204)
    expect(ok.headers.get('set-cookie')).toContain('__Host-cw_admin=;')
    expect(await sessions(subOf(token))).toHaveLength(0)
  })
})

describe('GET /api/cloudwarden/me', () => {
  it('reports admin status for the bearer', async () => {
    const { token, over } = await adminSession()
    const res = await me(token, over)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(await res.json()).toEqual({ isAdmin: true })
    expect(await (await me(token, { ...over, ADMIN_ENABLED: 'false' })).json()).toEqual({
      isAdmin: false,
    })
    const plain = await createSession(unique('plain'))
    expect(await (await me(plain.access_token)).json()).toEqual({ isAdmin: false })
  })

  it('requires a valid bearer', async () => {
    expect((await me('bogus')).status).toBe(401)
    const res = await withEnv(ADMIN_ENV, '/api/cloudwarden/me', {})
    expect(res.status).toBe(401)
  })
})

describe('admin landing', () => {
  it('points unauthenticated visitors to the vault login and recovery', async () => {
    const body = await (await withEnv(ADMIN_ENV, '/admin', {})).text()
    expect(body).toContain('href="/#/login"')
    expect(body).toContain('href="/admin/recovery"')
    const recovery = await (await withEnv(ADMIN_ENV, '/admin/recovery', {})).text()
    expect(recovery).toContain('action="/admin/recovery/token"')
    expect(recovery).toContain('action="/admin/recovery/magic-link"')
  })
})
