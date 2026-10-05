// Instance health: Cloudflare Worker limit failures from the GraphQL Analytics API (TASKS #361).
//
// The Worker cannot observe its own exceededCpu terminations (the isolate is killed) and cannot
// time its own CPU, so the numbers come from Cloudflare's analytics for this script. The query
// target is a fixed URL and the token is only ever sent there; it is never returned or logged.
import type { Bindings } from '../env'
import { log } from '../log'

export const ANALYTICS_URL = 'https://api.cloudflare.com/client/v4/graphql'
export const HEALTH_CACHE_MS = 60_000
export const HEALTH_FETCH_TIMEOUT_MS = 8_000
export const DEFAULT_CPU_LIMIT_MS = 10
export const DEFAULT_WORKER_NAME = 'cloudwarden'

export const HEALTH_RANGES = { '24h': 24 * 3_600_000, '7d': 7 * 24 * 3_600_000 } as const
export type HealthRange = keyof typeof HEALTH_RANGES

const ACCOUNT_ID = /^[0-9a-f]{32}$/i
const SCRIPT_NAME = /^[A-Za-z0-9_-]{1,63}$/

/**
 * Three aliases over `workersInvocationsAdaptive` for one script and window:
 * - `overall`: no dimensions, so one row with the CPU quantiles and maxima over every status.
 * - `byStatus`: one row per invocation status.
 * - `series`: one row per hour and status, for the chart (`datetimeHour`, ascending).
 * `cpuTime` and the quantiles are microseconds in the dataset; they are converted to ms below.
 */
export const HEALTH_QUERY = `query CloudwardenHealth($accountTag: string, $scriptName: string, $from: string, $to: string) {
  viewer {
    accounts(filter: { accountTag: $accountTag }) {
      overall: workersInvocationsAdaptive(limit: 1, filter: { scriptName: $scriptName, datetime_geq: $from, datetime_leq: $to }) {
        sum { requests errors subrequests }
        max { cpuTime wallTime }
        quantiles { cpuTimeP50 cpuTimeP99 cpuTimeP999 }
      }
      byStatus: workersInvocationsAdaptive(limit: 100, filter: { scriptName: $scriptName, datetime_geq: $from, datetime_leq: $to }) {
        dimensions { status }
        sum { requests errors }
      }
      series: workersInvocationsAdaptive(limit: 5000, orderBy: [datetimeHour_ASC], filter: { scriptName: $scriptName, datetime_geq: $from, datetime_leq: $to }) {
        dimensions { datetimeHour status }
        sum { requests errors }
      }
    }
  }
}`

export interface HealthStatusRow {
  status: string
  requests: number
  errors: number
}
export interface HealthPoint {
  hour: string
  requests: number
  errors: number
  exceededCpu: number
}
export interface HealthData {
  configured: true
  range: HealthRange
  from: string
  to: string
  generatedAt: string
  cpuLimitMs: number
  totals: { requests: number; errors: number; subrequests: number }
  statuses: HealthStatusRow[]
  /** Counts of invocations Cloudflare ended because of a platform limit. */
  limitFailures: { exceededCpu: number; exceededMemory: number; exceededResources: number }
  /** Milliseconds. Null when Cloudflare returned no invocations for the window. */
  cpu: {
    p50: number | null
    p99: number | null
    p999: number | null
    max: number | null
    wallMax: number | null
  } | null
  series: HealthPoint[]
}
export interface HealthNotConfigured {
  configured: false
  range: HealthRange
  cpuLimitMs: number
  missing: string[]
}
export type HealthResult = HealthData | HealthNotConfigured

export class HealthUpstreamError extends Error {}

export const parseRange = (v: string | undefined): HealthRange | null =>
  v === undefined || v === '' ? '24h' : v in HEALTH_RANGES ? (v as HealthRange) : null

export function cpuLimitMs(env: Bindings): number {
  const n = Number.parseFloat(env.WORKER_CPU_LIMIT_MS ?? '')
  return Number.isFinite(n) && n > 0 && n <= 300_000 ? n : DEFAULT_CPU_LIMIT_MS
}

const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0)
const ms = (v: unknown): number | null =>
  typeof v === 'number' && Number.isFinite(v) ? Math.round(v / 10) / 100 : null

interface CacheEntry {
  at: number
  value: Promise<HealthData>
}
const cache = new Map<string, CacheEntry>()
export const clearHealthCache = () => cache.clear()

// biome-ignore lint/suspicious/noExplicitAny: untyped upstream JSON, read defensively
type Json = any
type Rows = Json[]

export function shapeHealth(
  data: unknown,
  range: HealthRange,
  from: Date,
  to: Date,
  limit: number,
): HealthData {
  const acct = (data as Json)?.data?.viewer?.accounts?.[0]
  if (!acct) throw new HealthUpstreamError('no account in response')
  const overall: Rows = acct.overall ?? []
  const byStatus: Rows = acct.byStatus ?? []
  const series: Rows = acct.series ?? []
  const o = overall[0]
  const statuses = byStatus
    .map((r) => ({
      status: String(r.dimensions?.status ?? 'unknown'),
      requests: num(r.sum?.requests),
      errors: num(r.sum?.errors),
    }))
    .sort((a, b) => b.requests - a.requests)
  const count = (s: string) => statuses.find((r) => r.status === s)?.requests ?? 0
  const hours = new Map<string, HealthPoint>()
  for (const r of series) {
    const hour = String(r.dimensions?.datetimeHour ?? '')
    if (!hour) continue
    const p = hours.get(hour) ?? { hour, requests: 0, errors: 0, exceededCpu: 0 }
    p.requests += num(r.sum?.requests)
    p.errors += num(r.sum?.errors)
    if (r.dimensions?.status === 'exceededCpu') p.exceededCpu += num(r.sum?.requests)
    hours.set(hour, p)
  }
  return {
    configured: true,
    range,
    from: from.toISOString(),
    to: to.toISOString(),
    generatedAt: new Date().toISOString(),
    cpuLimitMs: limit,
    totals: {
      requests: num(o?.sum?.requests),
      errors: num(o?.sum?.errors),
      subrequests: num(o?.sum?.subrequests),
    },
    statuses,
    limitFailures: {
      exceededCpu: count('exceededCpu'),
      exceededMemory: count('exceededMemory'),
      exceededResources: count('exceededResources'),
    },
    cpu: o
      ? {
          p50: ms(o.quantiles?.cpuTimeP50),
          p99: ms(o.quantiles?.cpuTimeP99),
          p999: ms(o.quantiles?.cpuTimeP999),
          max: ms(o.max?.cpuTime),
          wallMax: ms(o.max?.wallTime),
        }
      : null,
    series: [...hours.values()].sort((a, b) => a.hour.localeCompare(b.hour)),
  }
}

async function query(
  token: string,
  accountTag: string,
  scriptName: string,
  range: HealthRange,
  limit: number,
): Promise<HealthData> {
  const to = new Date()
  const from = new Date(to.getTime() - HEALTH_RANGES[range])
  let res: Response
  try {
    res = await fetch(ANALYTICS_URL, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: HEALTH_QUERY,
        variables: {
          accountTag,
          scriptName,
          from: from.toISOString(),
          to: to.toISOString(),
        },
      }),
      signal: AbortSignal.timeout(HEALTH_FETCH_TIMEOUT_MS),
    })
  } catch {
    throw new HealthUpstreamError('Cloudflare analytics did not respond in time')
  }
  if (res.status === 401 || res.status === 403)
    throw new HealthUpstreamError('Cloudflare rejected the analytics token')
  if (!res.ok) throw new HealthUpstreamError(`Cloudflare analytics returned HTTP ${res.status}`)
  let body: Json
  try {
    body = await res.json()
  } catch {
    throw new HealthUpstreamError('Cloudflare analytics returned an unreadable response')
  }
  if (Array.isArray(body?.errors) && body.errors.length > 0) {
    // Only the error codes are kept: messages can echo the query and account.
    const code = String(body.errors[0]?.extensions?.code ?? 'error').slice(0, 40)
    throw new HealthUpstreamError(`Cloudflare analytics refused the query (${code})`)
  }
  return shapeHealth(body, range, from, to, limit)
}

/** Health for the admin panel. Cached for a minute per account, script and range. */
export async function instanceHealth(env: Bindings, range: HealthRange): Promise<HealthResult> {
  const token = env.CF_ANALYTICS_TOKEN?.trim()
  const account = env.CF_ACCOUNT_ID?.trim()
  const limit = cpuLimitMs(env)
  const missing = [...(token ? [] : ['CF_ANALYTICS_TOKEN']), ...(account ? [] : ['CF_ACCOUNT_ID'])]
  if (missing.length > 0 || !token || !account)
    return { configured: false, range, cpuLimitMs: limit, missing }
  const script = env.CF_WORKER_NAME?.trim() || DEFAULT_WORKER_NAME
  if (!ACCOUNT_ID.test(account) || !SCRIPT_NAME.test(script))
    throw new HealthUpstreamError('CF_ACCOUNT_ID or CF_WORKER_NAME is malformed')

  const key = `${account}:${script}:${range}:${limit}`
  const now = Date.now()
  const hit = cache.get(key)
  if (hit && now - hit.at < HEALTH_CACHE_MS) return hit.value
  const value = query(token, account, script, range, limit)
  cache.set(key, { at: now, value })
  try {
    return await value
  } catch (e) {
    // Never cache a failure.
    if (cache.get(key)?.value === value) cache.delete(key)
    log('warn', 'admin.health.upstream_failed', { reason: (e as Error).message.slice(0, 120) })
    throw e
  }
}
