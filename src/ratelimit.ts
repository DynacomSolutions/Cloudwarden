import type { MiddlewareHandler } from 'hono'
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
