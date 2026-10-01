import type { Context, MiddlewareHandler } from 'hono'
import type { Env } from './env'
import { errorBody } from './errors'

/**
 * Per-client-address rate limit using the `LOGIN_LIMITER` Workers Rate Limiting binding.
 * `scope` separates counters between routes. Skipped when the binding is not configured.
 */
export const rateLimit =
  (scope: string): MiddlewareHandler<Env> =>
  async (c, next) => {
    const limiter = c.env.LOGIN_LIMITER
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
 * Returns true when the caller is over the limit. Always false when no limiter is bound.
 */
export async function overLimit(c: Context<Env>, scope: string, subject: string): Promise<boolean> {
  const limiter = c.env.LOGIN_LIMITER
  if (!limiter) return false
  const { success } = await limiter.limit({ key: `${scope}:${subject}` })
  return !success
}

export const tooManyRequests = (c: Context<Env>) =>
  c.json(errorBody('Too many requests. Try again later.'), 429, { 'Retry-After': '60' })
