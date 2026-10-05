import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  ANALYTICS_URL,
  clearHealthCache,
  cpuLimitMs,
  HEALTH_QUERY,
  parseRange,
} from '../src/admin/health'
import { createSession, withEnv } from './helpers'

const P = '/api/cloudwarden/admin/health'
const ACCOUNT = '00000000000000000000000000000000'
const TOKEN = 'analytics-token-never-leaks-0123456789'
const CONFIGURED = { CF_ANALYTICS_TOKEN: TOKEN, CF_ACCOUNT_ID: ACCOUNT }

let n = 0
async function person(admin: boolean, extra: Record<string, unknown> = {}) {
  const email = `health${++n}@example.com`
  const s = await createSession(email)
  const over = {
    ADMIN_ENABLED: 'true',
    ADMIN_EMAILS: admin ? email : 'nobody@example.com',
    ...extra,
  }
  const call = (path: string) =>
    withEnv(over, path, { headers: { Authorization: `Bearer ${s.access_token}` } })
  return { call }
}

const analytics = {
  data: {
    viewer: {
      accounts: [
        {
          overall: [
            {
              sum: { requests: 1000, errors: 12, subrequests: 3000 },
              max: { cpuTime: 48_500, wallTime: 900_000 },
              quantiles: { cpuTimeP50: 2_300, cpuTimeP99: 9_876, cpuTimeP999: 31_000 },
            },
          ],
          byStatus: [
            { dimensions: { status: 'exceededCpu' }, sum: { requests: 7, errors: 7 } },
            { dimensions: { status: 'success' }, sum: { requests: 990, errors: 0 } },
            { dimensions: { status: 'scriptThrewException' }, sum: { requests: 3, errors: 3 } },
          ],
          series: [
            {
              dimensions: { datetimeHour: '2026-10-05T11:00:00Z', status: 'success' },
              sum: { requests: 400, errors: 0 },
            },
            {
              dimensions: { datetimeHour: '2026-10-05T10:00:00Z', status: 'success' },
              sum: { requests: 100, errors: 0 },
            },
            {
              dimensions: { datetimeHour: '2026-10-05T10:00:00Z', status: 'exceededCpu' },
              sum: { requests: 7, errors: 7 },
            },
          ],
        },
      ],
    },
  },
}

interface Seen {
  url: string
  auth: string | null
  body: any
}
let seen: Seen[] = []
let reply: () => Response | Promise<Response>
let realFetch: typeof fetch
beforeEach(() => {
  clearHealthCache()
  seen = []
  reply = () => Response.json(analytics)
  realFetch = globalThis.fetch
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input)
    if (url.startsWith('https://vault.example.com')) return realFetch(input, init)
    seen.push({
      url,
      auth: new Headers(init?.headers).get('Authorization'),
      body: JSON.parse(String(init?.body)),
    })
    return reply()
  }) as typeof fetch
})
afterEach(() => {
  globalThis.fetch = realFetch
})

describe('GET /api/cloudwarden/admin/health', () => {
  it('shapes the analytics: statuses, CPU in ms, hourly series, no token', async () => {
    const a = await person(true, CONFIGURED)
    const res = await a.call(P)
    expect(res.status).toBe(200)
    const text = await res.text()
    expect(text).not.toContain(TOKEN)
    const body = JSON.parse(text)
    expect(body).toMatchObject({
      configured: true,
      range: '24h',
      cpuLimitMs: 10,
      totals: { requests: 1000, errors: 12, subrequests: 3000 },
      limitFailures: { exceededCpu: 7, exceededMemory: 0, exceededResources: 0 },
      cpu: { p50: 2.3, p99: 9.88, p999: 31, max: 48.5, wallMax: 900 },
    })
    expect(body.statuses[0]).toEqual({ status: 'success', requests: 990, errors: 0 })
    expect(body.series).toEqual([
      { hour: '2026-10-05T10:00:00Z', requests: 107, errors: 7, exceededCpu: 7 },
      { hour: '2026-10-05T11:00:00Z', requests: 400, errors: 0, exceededCpu: 0 },
    ])
  })

  it('queries the fixed analytics URL for this script and account with the bearer token', async () => {
    const a = await person(true, {
      ...CONFIGURED,
      CF_WORKER_NAME: 'my-vault',
      WORKER_CPU_LIMIT_MS: '30',
    })
    const body = await (await a.call(`${P}?range=7d`)).json<any>()
    expect(body.range).toBe('7d')
    expect(body.cpuLimitMs).toBe(30)
    expect(seen).toHaveLength(1)
    expect(seen[0]?.url).toBe(ANALYTICS_URL)
    expect(seen[0]?.auth).toBe(`Bearer ${TOKEN}`)
    expect(seen[0]?.body.query).toBe(HEALTH_QUERY)
    expect(seen[0]?.body.variables).toMatchObject({ accountTag: ACCOUNT, scriptName: 'my-vault' })
    const { from, to } = seen[0]?.body.variables ?? {}
    expect(Date.parse(to) - Date.parse(from)).toBe(7 * 24 * 3_600_000)
  })

  it('says what is missing instead of failing when the token is not set', async () => {
    const a = await person(true)
    const res = await a.call(P)
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({
      configured: false,
      range: '24h',
      cpuLimitMs: 10,
      missing: ['CF_ANALYTICS_TOKEN', 'CF_ACCOUNT_ID'],
    })
    const b = await person(true, { CF_ANALYTICS_TOKEN: TOKEN })
    expect((await (await b.call(P)).json<any>()).missing).toEqual(['CF_ACCOUNT_ID'])
    expect(seen).toHaveLength(0)
  })

  it('answers 502 without the token when Cloudflare fails, and does not cache failures', async () => {
    const a = await person(true, CONFIGURED)
    reply = () => new Response('nope', { status: 500 })
    const bad = await a.call(P)
    expect(bad.status).toBe(502)
    expect(await bad.text()).not.toContain(TOKEN)
    reply = () => new Response('{}', { status: 403 })
    expect((await (await a.call(P)).json<any>()).message).toContain('rejected')
    reply = () => Response.json({ errors: [{ message: 'bad', extensions: { code: 'authz' } }] })
    expect((await (await a.call(P)).json<any>()).message).toContain('authz')
    reply = () => {
      throw new Error('timeout')
    }
    expect((await a.call(P)).status).toBe(502)
    reply = () => Response.json(analytics)
    expect((await a.call(P)).status).toBe(200)
  })

  it('rejects a malformed account id or range', async () => {
    const a = await person(true, { ...CONFIGURED, CF_ACCOUNT_ID: 'x" } ) { evil' })
    expect((await a.call(P)).status).toBe(502)
    expect(seen).toHaveLength(0)
    const b = await person(true, CONFIGURED)
    expect((await b.call(`${P}?range=90d`)).status).toBe(400)
  })

  it('caches the upstream result per range for a minute', async () => {
    const a = await person(true, CONFIGURED)
    await a.call(P)
    await a.call(P)
    expect(seen).toHaveLength(1)
    await a.call(`${P}?range=7d`)
    expect(seen).toHaveLength(2)
  })

  it('is admin only', async () => {
    const u = await person(false, CONFIGURED)
    expect((await u.call(P)).status).toBe(403)
    expect(seen).toHaveLength(0)
    const anon = await withEnv({ ADMIN_ENABLED: 'true', ...CONFIGURED }, P, {})
    expect(anon.status).toBe(401)
  })
})

describe('helpers', () => {
  it('parses the range and the CPU limit', () => {
    expect(parseRange(undefined)).toBe('24h')
    expect(parseRange('7d')).toBe('7d')
    expect(parseRange('1h')).toBeNull()
    expect(cpuLimitMs({ WORKER_CPU_LIMIT_MS: '50' } as any)).toBe(50)
    expect(cpuLimitMs({ WORKER_CPU_LIMIT_MS: 'abc' } as any)).toBe(10)
    expect(cpuLimitMs({ WORKER_CPU_LIMIT_MS: '-1' } as any)).toBe(10)
  })
})
