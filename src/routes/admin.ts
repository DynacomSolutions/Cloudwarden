import { Hono } from 'hono'
import type { Env } from '../env'

export const admin = new Hono<Env>()

// The admin surface does not exist unless explicitly enabled.
admin.all('/admin', (c) => handle(c))
admin.all('/admin/*', (c) => handle(c))

function handle(c: import('hono').Context<Env>) {
  if (c.env.ADMIN_ENABLED !== 'true') {
    return c.json({ message: 'Not found', validationErrors: null, object: 'error' }, 404)
  }
  // TODO(TASKS #8): admin panel (token-hash authenticated)
  return c.json({ message: 'Not implemented' }, 501)
}
