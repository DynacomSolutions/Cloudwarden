import type { Context, MiddlewareHandler } from 'hono'
import { rateLimit as d1Window } from './admin/security'
import type { Env } from './env'
import { errorBody } from './errors'

/**
 * Per-client-address rate limit using the `LOGIN_LIMITER` Workers Rate Limiting binding.
 * `scope` separates counters between routes. Skipped when the binding is not configured.
 */
export const rateLimit =
  (scope: string, d1Fallback?: number): MiddlewareHandler<Env> =>
  async (c, next) => {
    const limiter = c.env.LOGIN_LIMITER
    const header = c.req.header('CF-Connecting-IP')
    if (!limiter && d1Fallback && header) {
      // No limiter bound: fall back to the D1 fixed window (per address, 60 s).
      if (!(await d1Window(c.env.DB, `${scope}:${header}`, d1Fallback, 60_000, Date.now()))) {
        return tooManyRequests(c)
      }
    }
    if (limiter) {
      const ip = c.req.header('CF-Connecting-IP') ?? 'unknown'
      const { success } = await limiter.limit({ key: `${scope}:${ip}` })
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
