import { Hono } from 'hono'
import type { Env } from './env'
import { securityHeaders } from './middleware'
import { admin } from './routes/admin'
import { alive } from './routes/alive'
import { config } from './routes/config'
import { prelogin } from './routes/prelogin'
import { stubs } from './routes/stubs'

const app = new Hono<Env>()

app.use('*', securityHeaders)

app.route('/', alive)
app.route('/', config)
app.route('/', prelogin)
app.route('/', stubs)
app.route('/', admin)

app.notFound((c) => c.json({ message: 'Not found', validationErrors: null, object: 'error' }, 404))

app.onError((err, c) => {
  console.error(err)
  return c.json({ message: 'Internal server error', validationErrors: null, object: 'error' }, 500)
})

export default app
export { NotificationHub } from './do/notification-hub'
