import { expect, it } from 'vitest'
import { registerBody, withEnv } from './helpers'

const post = (path: string, body: BodyInit, type: string, limiter: unknown) =>
  withEnv({ LOGIN_LIMITER: limiter }, path, {
    method: 'POST',
    headers: { 'Content-Type': type, 'CF-Connecting-IP': '203.0.113.9' },
    body,
  })

const makeLimiter = (allowed: number) => {
  const keys: string[] = []
  return {
    keys,
    limit: async ({ key }: { key: string }) => {
      keys.push(key)
      return { success: keys.length <= allowed }
    },
  }
}

it('returns 429 from prelogin, token and register once the limiter trips', async () => {
  const cases: [string, string, string][] = [
    ['/identity/accounts/prelogin', JSON.stringify({ email: 'a@example.com' }), 'application/json'],
    ['/identity/connect/token', 'grant_type=password', 'application/x-www-form-urlencoded'],
    [
      '/identity/accounts/register',
      JSON.stringify(registerBody('rl@example.com')),
      'application/json',
    ],
  ]
  for (const [path, body, type] of cases) {
    const limiter = makeLimiter(0)
    const res = await post(path, body, type, limiter)
    expect(res.status).toBe(429)
    expect(res.headers.get('Retry-After')).toBeTruthy()
    expect(limiter.keys[0]).toContain('203.0.113.9')
  }
})

it('lets requests through while under the limit', async () => {
  const limiter = makeLimiter(5)
  const res = await post(
    '/identity/accounts/prelogin',
    JSON.stringify({ email: 'a@example.com' }),
    'application/json',
    limiter,
  )
  expect(res.status).toBe(200)
})
