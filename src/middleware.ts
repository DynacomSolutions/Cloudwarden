import type { MiddlewareHandler } from 'hono'
import type { Env } from './env'

export const securityHeaders: MiddlewareHandler<Env> = async (c, next) => {
  await next()
  const path = new URL(c.req.url).pathname
  // No includeSubDomains or preload: operators run this on their own domains, and those flags reach sibling hosts.
  c.header('Strict-Transport-Security', 'max-age=31536000')
  c.header('X-Content-Type-Options', 'nosniff')
  c.header('Referrer-Policy', 'same-origin')
  c.header('X-Frame-Options', 'SAMEORIGIN')
  if (path.startsWith('/api') || path.startsWith('/identity') || path === '/alive') {
    c.header('Cache-Control', 'no-store')
  }
}
