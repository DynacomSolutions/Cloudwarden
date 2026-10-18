import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { vi } from 'vitest'

export const BASE = 'https://vault.example.com'

/**
 * Freezes time to prevent rate limiter window boundary races.
 * The D1 rate limiter uses fixed 60s windows calculated from Date.now().
 * Returns a cleanup function to restore real timers.
 * Preserves JWT validity by setting system time to current moment.
 */
export function freezeRateLimitWindow() {
  vi.useFakeTimers({ toFake: ['Date'] })
  const now = Date.now()
  vi.setSystemTime(now)
  return () => vi.useRealTimers()
}

/**
 * Alternative using try/finally for convenience.
 * Usage: await runWithFrozenTime(async () => { ... test code ... })
 */
export async function runWithFrozenTime<T>(fn: () => Promise<T>): Promise<T> {
  const restore = freezeRateLimitWindow()
  try {
    return await fn()
  } finally {
    restore()
  }
}

export const json = (path: string, body: unknown, init: RequestInit = {}) =>
  SELF.fetch(`${BASE}${path}`, {
    method: 'POST',
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init.headers as object) },
    body: JSON.stringify(body),
  })

export const authed = (path: string, token: string, method = 'GET', body?: unknown) =>
  SELF.fetch(`${BASE}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })

export const form = (path: string, fields: Record<string, string>) =>
  SELF.fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(fields).toString(),
  })

export const registerBody = (email: string, extra: Record<string, unknown> = {}) => ({
  email,
  name: 'Test User',
  masterPasswordHash: 'client-derived-hash',
  masterPasswordHint: 'hint',
  key: '2.encryptedSymmetricKey',
  keys: { publicKey: 'public-key', encryptedPrivateKey: '2.pk' },
  kdf: 0,
  kdfIterations: 600000,
  ...extra,
})

export const registerUser = (email: string, extra: Record<string, unknown> = {}) =>
  json('/identity/accounts/register', registerBody(email, extra))

export const login = (
  email: string,
  password = 'client-derived-hash',
  extra: Record<string, string> = {},
) =>
  form('/identity/connect/token', {
    grant_type: 'password',
    username: email,
    password,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceName: 'chrome',
    deviceIdentifier: 'device-1',
    ...extra,
  })

export interface Session {
  access_token: string
  refresh_token: string
  [k: string]: unknown
}

/** Registers (signups must be open) and logs in. */
export async function createSession(email: string, extra: Record<string, string> = {}) {
  const reg = await registerUser(email)
  if (reg.status !== 200) throw new Error(`register failed: ${reg.status}`)
  const res = await login(email, 'client-derived-hash', extra)
  if (res.status !== 200) throw new Error(`login failed: ${res.status}`)
  return (await res.json()) as Session
}

/** Calls the app directly with some bindings overridden (for closed signups, limiters). */
export async function withEnv(overrides: Record<string, unknown>, path: string, init: RequestInit) {
  const { env } = await import('cloudflare:workers')
  const { default: app } = await import('../src/index')
  return app.fetch(new Request(`${BASE}${path}`, init), { ...env, ...overrides })
}

/**
 * Polls `fn` until it returns something other than `undefined`/`false`, then returns it.
 * Use this for work that finishes in the background (ctx.waitUntil, websocket pushes, mail),
 * instead of a fixed sleep. The default timeout is generous on purpose: it only costs time
 * when the condition is never met, and the shared CI host can stall a worker for many seconds.
 */
export async function waitFor<T>(
  fn: () => T | undefined | false | Promise<T | undefined | false>,
  { timeout = 20_000, interval = 10, message = 'condition' } = {},
): Promise<T> {
  const end = Date.now() + timeout
  for (;;) {
    const v = await fn()
    if (v !== undefined && v !== false) return v
    if (Date.now() > end) throw new Error(`timed out after ${timeout}ms waiting for ${message}`)
    await new Promise((r) => setTimeout(r, interval))
  }
}

/**
 * Session-revocation fixtures: a refresh token and an approved login-with-device request
 * that exist before the revocation under test. `expectRevoked` then proves both are dead.
 */
export async function liveSessionArtefacts(email: string, accessToken: string) {
  const refresh = ((await (await login(email, 'client-derived-hash')).json()) as Session)
    .refresh_token
  await env.DB.prepare(
    'UPDATE devices SET twofactor_remember = ?2 WHERE user_uuid = (SELECT uuid FROM users WHERE email = ?1)',
  )
    .bind(email, 'remembered')
    .run()
  const created = (await (
    await json('/api/auth-requests/', {
      email,
      deviceIdentifier: 'revoked-device',
      publicKey: 'pub',
      type: 0,
      accessCode: 'revoke-code',
    })
  ).json()) as { id: string }
  const put = await authed(`/api/auth-requests/${created.id}`, accessToken, 'PUT', {
    key: 'k',
    masterPasswordHash: 'h',
    deviceIdentifier: 'device-1',
    requestApproved: true,
  })
  if (put.status !== 200) throw new Error(`approve failed: ${put.status}`)
  return {
    refresh,
    expectRevoked: async () => {
      const r = await form('/identity/connect/token', {
        grant_type: 'refresh_token',
        refresh_token: refresh,
      })
      if (r.status !== 400) throw new Error(`refresh token still usable: ${r.status}`)
      const d = await form('/identity/connect/token', {
        grant_type: 'password',
        username: email,
        password: 'revoke-code',
        authRequest: created.id,
        scope: 'api offline_access',
        client_id: 'web',
        deviceType: '9',
        deviceName: 'new',
        deviceIdentifier: 'revoked-device',
      })
      if (d.status !== 400) throw new Error(`approved request still redeemable: ${d.status}`)
      const left = await env.DB.prepare(
        'SELECT COUNT(*) n FROM devices WHERE twofactor_remember IS NOT NULL AND user_uuid = (SELECT uuid FROM users WHERE email = ?1)',
      )
        .bind(email)
        .first<{ n: number }>()
      if (left?.n !== 0) throw new Error('twofactor_remember not cleared')
    },
  }
}

/**
 * D1 binding that runs `hook` once, just before the first write whose SQL matches `sql` (a single
 * statement or a batch), to simulate another request landing between a read and that write.
 */
export function dbWithRace(db: D1Database, sql: RegExp, hook: () => Promise<void>): D1Database {
  let fired = false
  const fire = async () => {
    if (fired) return
    fired = true
    await hook()
  }
  return new Proxy(db, {
    get(target, prop) {
      if (prop === 'prepare') {
        return (query: string) => {
          const stmt = target.prepare(query)
          if (!sql.test(query)) return stmt
          return new Proxy(stmt, {
            get(s, p) {
              if (p === 'bind') return (...a: unknown[]) => wrap(s.bind(...a))
              return Reflect.get(s, p, s)
            },
          })
        }
      }
      if (prop === 'batch') {
        return async (stmts: D1PreparedStatement[]) => {
          if (stmts.some((s) => (s as any).__race)) await fire()
          return target.batch(stmts.map((s) => (s as any).__race ?? s))
        }
      }
      const v = Reflect.get(target, prop, target)
      return typeof v === 'function' ? v.bind(target) : v
    },
  })
  function wrap(bound: D1PreparedStatement) {
    return new Proxy(bound, {
      get(s, p) {
        if (p === '__race') return bound
        if (p === 'run' || p === 'all' || p === 'raw' || p === 'first')
          return async (...a: unknown[]) => {
            await fire()
            return (s as any)[p](...a)
          }
        return Reflect.get(s, p, s)
      },
    })
  }
}
