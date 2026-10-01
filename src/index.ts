import { Hono } from 'hono'
import type { Env } from './env'
import { ApiError, errorBody } from './errors'
import { securityHeaders } from './middleware'
import { accounts } from './routes/accounts'
import { admin } from './routes/admin'
import { alive } from './routes/alive'
import { appId } from './routes/app-id'
import { ciphers } from './routes/ciphers'
import { config } from './routes/config'
import { devices } from './routes/devices'
import { folders } from './routes/folders'
import { prelogin } from './routes/prelogin'
import { register } from './routes/register'
import { settings } from './routes/settings'
import { stubs } from './routes/stubs'
import { sync } from './routes/sync'
import { token } from './routes/token'

const app = new Hono<Env>()

app.use('*', securityHeaders)

app.route('/', alive)
app.route('/', appId)
app.route('/', config)
app.route('/', prelogin)
app.route('/', register)
app.route('/', token)
app.route('/', devices)
app.route('/', accounts)
app.route('/', sync)
app.route('/', ciphers)
app.route('/', folders)
app.route('/', settings)
app.route('/', stubs)
app.route('/', admin)

app.notFound((c) => c.json({ message: 'Not found', validationErrors: null, object: 'error' }, 404))

app.onError((err, c) => {
  if (err instanceof ApiError)
    return c.json(errorBody(err.message, err.validationErrors), err.status)
  // Log only the error, never request data.
  console.error(err)
  return c.json({ message: 'Internal server error', validationErrors: null, object: 'error' }, 500)
})

export default app
export { NotificationHub } from './do/notification-hub'
