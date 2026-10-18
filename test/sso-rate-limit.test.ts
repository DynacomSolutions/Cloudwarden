import { env } from 'cloudflare:workers'
import { beforeEach, describe, expect, it } from 'vitest'
import { AdminEventType } from '../src/admin/service'
import { invalidateSsoRateLimit, ssoRateLimitView } from '../src/admin/sso-rate-limit'
import { createSession, freezeRateLimitWindow, withEnv } from './helpers'

const P = '/api/cloudwarden/admin/sso-rate-limit'
const PREVALIDATE = '/identity/sso/prevalidate?domainHint=nope'

let n = 0
async function person(admin: boolean) {
  const email = `ssorl${++n}@example.com`
  const s = await createSession(email)
  const over = {
    ADMIN_ENABLED: 'true',
    ADMIN_EMAILS: admin ? email : 'nobody@example.com',
    LOGIN_LIMITER: { limit: async () => ({ success: true }) },
  }
  return (path: string, method = 'GET', body?: unknown) =>
    withEnv(over, path, {
      method,
      headers: {
        Authorization: `Bearer ${s.access_token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
}

const hit = (ip: string, over: Record<string, unknown> = {}) =>
  withEnv(over, PREVALIDATE, { headers: { 'CF-Connecting-IP': ip } })

beforeEach(async () => {
  invalidateSsoRateLimit()
  await env.DB.prepare('DELETE FROM instance_settings WHERE key = ?1').bind('sso-rate-limit').run()
})

describe('sso rate limit setting API', () => {
  it('defaults to 20 and stores a valid value with an audit event', async () => {
    const call = await person(true)
    expect(await (await call(P)).json()).toEqual({ ssoRateLimitPerMinute: 20, custom: false })
    const put = await call(P, 'PUT', { ssoRateLimitPerMinute: 50 })
    expect(put.status).toBe(200)
    expect(await put.json()).toEqual({ ssoRateLimitPerMinute: 50, custom: true })
    expect(await (await call(P)).json()).toEqual({ ssoRateLimitPerMinute: 50, custom: true })
    const row = await env.DB.prepare('SELECT COUNT(*) AS c FROM events WHERE event_type = ?1')
      .bind(AdminEventType.SsoRateLimitUpdated)
      .first<{ c: number }>()
    expect(row?.c).toBeGreaterThan(0)
  })

  it('reports the effective default: 20 with the binding, 30 without', async () => {
    const call = await person(true)
    expect(
      (await ssoRateLimitView({ ...env, LOGIN_LIMITER: undefined } as any)).ssoRateLimitPerMinute,
    ).toBe(30)
    expect(
      (await ssoRateLimitView({ ...env, LOGIN_LIMITER: {} } as any)).ssoRateLimitPerMinute,
    ).toBe(20)
  })

  it('DELETE returns to unset and the binding decides again', async () => {
    const call = await person(true)
    await call(P, 'PUT', { ssoRateLimitPerMinute: 50 })
    const del = await call(P, 'DELETE')
    expect(del.status).toBe(200)
    expect(await del.json()).toEqual({ ssoRateLimitPerMinute: 20, custom: false })
    expect(await (await call(P)).json()).toEqual({ ssoRateLimitPerMinute: 20, custom: false })
    const limiter = { limit: async () => ({ success: false }) }
    expect((await hit('198.51.100.90', { LOGIN_LIMITER: limiter })).status).toBe(429)
    const user = await person(false)
    expect((await user(P, 'DELETE')).status).toBe(403)
  })

  it('rejects out of range and non integer values with a field error', async () => {
    const call = await person(true)
    for (const bad of [4, 1001, 0, -1, 20.5, '50', null, undefined]) {
      const res = await call(P, 'PUT', { ssoRateLimitPerMinute: bad })
      expect(res.status, String(bad)).toBe(400)
      const body = (await res.json()) as any
      expect(JSON.stringify(body)).toContain('ssoRateLimitPerMinute')
    }
    expect((await call(P, 'PUT', { ssoRateLimitPerMinute: 5 })).status).toBe(200)
    expect((await call(P, 'PUT', { ssoRateLimitPerMinute: 1000 })).status).toBe(200)
  })

  it('refuses anonymous callers and non-admins', async () => {
    for (const method of ['GET', 'PUT'] as const) {
      const anon = await withEnv({ ADMIN_ENABLED: 'true' }, P, { method })
      expect(anon.status).toBe(401)
      const user = await person(false)
      expect(
        (await user(P, method, method === 'PUT' ? { ssoRateLimitPerMinute: 50 } : undefined))
          .status,
      ).toBe(403)
    }
    expect(
      await env.DB.prepare("SELECT 1 FROM instance_settings WHERE key = 'sso-rate-limit'").first(),
    ).toBeNull()
  })
})

describe('sso rate limit enforcement', () => {
  it('allows 50 requests per /64 then limits when set to 50, ignoring the binding', async () => {
    const restore = freezeRateLimitWindow()
    try {
      const call = await person(true)
      await call(P, 'PUT', { ssoRateLimitPerMinute: 50 })
      const blocked = { limit: async () => ({ success: false }) }
      for (let i = 0; i < 50; i++) {
        const res = await hit(`2001:db8:50:1::${i + 1}`, { LOGIN_LIMITER: blocked })
        expect(res.status, `request ${i + 1}`).toBe(400)
      }
      const over = await hit('2001:db8:50:1::ffff', { LOGIN_LIMITER: blocked })
      expect(over.status).toBe(429)
      expect(over.headers.get('Retry-After')).toBe('60')
      expect((await hit('2001:db8:50:2::1', { LOGIN_LIMITER: blocked })).status).toBe(400)
    } finally {
      restore()
    }
  })

  it('behaves as before when unset: the binding decides', async () => {
    const keys: string[] = []
    const limiter = {
      limit: async ({ key }: { key: string }) => {
        keys.push(key)
        return { success: keys.length <= 3 }
      },
    }
    const ip = '198.51.100.77'
    const codes: number[] = []
    for (let i = 0; i < 5; i++) codes.push((await hit(ip, { LOGIN_LIMITER: limiter })).status)
    expect(codes).toEqual([400, 400, 400, 429, 429])
    expect(keys[0]).toBe(`sso:${ip}`)
  })

  it('does not return 500 when reading the setting fails', async () => {
    const failing = new Proxy(env.DB, {
      get(t, prop) {
        if (prop === 'prepare') {
          return (q: string) => {
            if (q.includes('FROM instance_settings')) throw new Error('d1 down')
            return t.prepare(q)
          }
        }
        const v = Reflect.get(t, prop, t)
        return typeof v === 'function' ? v.bind(t) : v
      },
    })
    const limiter = { limit: async () => ({ success: true }) }
    const res = await hit('198.51.100.91', { DB: failing, LOGIN_LIMITER: limiter })
    expect(res.status).toBe(400)
  })

  it('leaves other scopes on the binding', async () => {
    const call = await person(true)
    await call(P, 'PUT', { ssoRateLimitPerMinute: 50 })
    const limiter = { limit: async () => ({ success: false }) }
    const res = await withEnv({ LOGIN_LIMITER: limiter }, '/identity/accounts/prelogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.78' },
      body: JSON.stringify({ email: 'a@example.com' }),
    })
    expect(res.status).toBe(429)
  })
})
