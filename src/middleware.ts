import type { MiddlewareHandler } from 'hono'
import type { Env } from './env'

export const securityHeaders: MiddlewareHandler<Env> = async (c, next) => {
  await next()
  const path = new URL(c.req.url).pathname
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('Referrer-Policy', 'same-origin')
  c.header('X-Frame-Options', 'SAMEORIGIN')
  if (path.startsWith('/api') || path.startsWith('/identity') || path === '/alive') {
    c.header('Cache-Control', 'no-store')
  }
}
