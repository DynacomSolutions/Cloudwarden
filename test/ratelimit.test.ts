import { expect, it } from 'vitest'
import { ipKey } from '../src/ratelimit'
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

it('keys IPv4 unchanged and IPv6 by its /64 prefix', () => {
  expect(ipKey('203.0.113.9')).toBe('203.0.113.9')
  expect(ipKey('2001:0DB8:0000:0001:aaaa:bbbb:cccc:dddd')).toBe('2001:db8:0:1::/64')
  expect(ipKey('2001:db8:0:1::5')).toBe('2001:db8:0:1::/64')
  expect(ipKey('2001:db8::1')).toBe('2001:db8:0:0::/64')
  expect(ipKey('::1')).toBe('0:0:0:0::/64')
  expect(ipKey('::ffff:203.0.113.9')).toBe('203.0.113.9')
  expect(ipKey('::ffff:cb00:7109')).toBe('203.0.113.9')
  expect(ipKey('not-an-ip')).toBe('not-an-ip')
  expect(ipKey('1:2:3::4::5')).toBe('1:2:3::4::5')
  expect(ipKey('1:2:3:4:5:6:7:8:9')).toBe('1:2:3:4:5:6:7:8:9')
  expect(ipKey('::ffff:999.1.1.1')).toBe('::ffff:999.1.1.1')
})

it('counts two addresses in one /64 as one bucket', async () => {
  const limiter = makeLimiter(5)
  for (const ip of ['2001:db8:0:1::1', '2001:db8:0:1:ffff::2']) {
    await withEnv({ LOGIN_LIMITER: limiter }, '/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': ip },
      body: JSON.stringify({ email: 'a@example.com' }),
    })
  }
  expect(limiter.keys).toHaveLength(2)
  expect(limiter.keys[0]).toBe(limiter.keys[1])
})
