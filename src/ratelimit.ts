import type { Context, MiddlewareHandler } from 'hono'
import { rateLimit as d1Window } from './admin/security'
import { loadSsoRateLimit } from './admin/sso-rate-limit'
import type { Env } from './env'
import { errorBody } from './errors'

/**
 * Limit key for a client address: IPv4 unchanged, IPv6 reduced to its normalised /64 prefix
 * (an attacker controls a whole /64, so per-address buckets are free to rotate). IPv4-mapped
 * IPv6 counts as IPv4. Unparseable input is returned unchanged.
 */
export function ipKey(ip: string): string {
  const raw = ip.trim().toLowerCase().split('%')[0] ?? ''
  if (!raw.includes(':')) return raw
  let text = raw
  const v4 = /(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text)
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number) as [number, number, number, number]
    if ([a, b, c, d].some((n) => n > 255)) return ip
    text = text.slice(0, v4.index) + `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`
  }
  const halves = text.split('::')
  if (halves.length > 2) return ip
  const [head, tail] = halves.map((h) => (h ? h.split(':') : [])) as [
    string[],
    string[] | undefined,
  ]
  const missing = 8 - head.length - (tail?.length ?? 0)
  if (tail ? missing < 1 : missing !== 0) return ip
  const parts = [...head, ...(tail ? Array<string>(missing).fill('0') : []), ...(tail ?? [])]
  if (!parts.every((h) => /^[0-9a-f]{1,4}$/.test(h))) return ip
  const n = parts.map((h) => Number.parseInt(h, 16)) as [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
  ]
  if (n.slice(0, 5).every((x) => x === 0) && n[5] === 0xffff) {
    return `${n[6] >> 8}.${n[6] & 255}.${n[7] >> 8}.${n[7] & 255}`
  }
  return `${n
    .slice(0, 4)
    .map((x) => x.toString(16))
    .join(':')}::/64`
}

/** The `CF-Connecting-IP` address as a limit key (see `ipKey`), or undefined when absent. */
export const clientKey = (c: Context<Env>): string | undefined => {
  const ip = c.req.header('CF-Connecting-IP')
  return ip === undefined ? undefined : ipKey(ip)
}

/**
 * Per-client-address rate limit using the `LOGIN_LIMITER` Workers Rate Limiting binding.
 * `scope` separates counters between routes. Skipped when the binding is not configured.
 */
export const rateLimit =
  (scope: string, d1Fallback?: number): MiddlewareHandler<Env> =>
  async (c, next) => {
    const limiter = c.env.LOGIN_LIMITER
    const header = clientKey(c)
    // An admin set SSO limit replaces the binding (its limit is fixed): enforce it in D1.
    const custom = scope === 'sso' ? await loadSsoRateLimit(c.env) : null
    if (custom && header) {
      if (!(await d1Window(c.env.DB, `${scope}:${header}`, custom, 60_000, Date.now()))) {
        return tooManyRequests(c)
      }
      return next()
    }
    if (!limiter && d1Fallback && header) {
      // No limiter bound: fall back to the D1 fixed window (per address, 60 s).
      if (!(await d1Window(c.env.DB, `${scope}:${header}`, d1Fallback, 60_000, Date.now()))) {
        return tooManyRequests(c)
      }
    }
    if (limiter) {
      const { success } = await limiter.limit({ key: `${scope}:${header ?? 'unknown'}` })
      if (!success) {
        return c.json(errorBody('Too many requests. Try again later.'), 429, {
          'Retry-After': '60',
        })
      }
    }
    await next()
  }

/**
 * Counts one attempt against the limiter for `scope` and `subject` (for example a user id).
 * Returns true when the caller is over the limit. Without the binding it uses a D1 window.
 */
export async function overLimit(c: Context<Env>, scope: string, subject: string): Promise<boolean> {
  const limiter = c.env.LOGIN_LIMITER
  if (!limiter) {
    // Fail safe for second factor paths: count in D1 (20 per subject per minute).
    return !(await d1Window(c.env.DB, `${scope}:${subject}`, 20, 60_000, Date.now()))
  }
  const { success } = await limiter.limit({ key: `${scope}:${subject}` })
  return !success
}

export const tooManyRequests = (c: Context<Env>) =>
  c.json(errorBody('Too many requests. Try again later.'), 429, { 'Retry-After': '60' })

export const FAILURE_BUDGET = 10
export const FAILURE_WINDOW_MS = 15 * 60_000

/**
 * Durable failure budget in D1, independent of the location-local limiter binding. Spends one
 * attempt atomically before the check and returns true while the attempt is within `limit`, so
 * parallel attempts cannot overshoot. Call `resetBudget` on success. The lockout lasts to the end
 * of the fixed window. Key by a normalised identifier whether or not the account exists.
 */
export const spendBudget = (
  db: D1Database,
  key: string,
  limit = FAILURE_BUDGET,
  windowMs = FAILURE_WINDOW_MS,
): Promise<boolean> => d1Window(db, key, limit, windowMs, Date.now())

/** Clears a failure budget after a success. */
export async function resetBudget(db: D1Database, key: string): Promise<void> {
  await db.prepare('DELETE FROM admin_rate_limits WHERE key = ?1').bind(key).run()
}
