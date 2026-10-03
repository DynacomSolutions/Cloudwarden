import { SELF } from 'cloudflare:test'
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
