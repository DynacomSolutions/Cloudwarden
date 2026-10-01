import { Hono } from 'hono'
import type { Env } from './env'
import { ApiError, errorBody } from './errors'
import { securityHeaders } from './middleware'
import { accounts } from './routes/accounts'
import { admin } from './routes/admin'
import { alive } from './routes/alive'
import { appId } from './routes/app-id'
import { downloadAttachment } from './routes/attachments'
import { authRequests } from './routes/auth-requests'
import { ciphers } from './routes/ciphers'
import { collectionsRouter } from './routes/collections'
import { config } from './routes/config'
import { devices } from './routes/devices'
import { emergencyAccess } from './routes/emergency-access'
import { events } from './routes/events'
import { folders } from './routes/folders'
import { notifications } from './routes/notifications'
import { groupsRouter } from './routes/groups'
import { orgCiphers } from './routes/org-ciphers'
import { orgUsers } from './routes/org-users'
import { organizations } from './routes/organizations'
import { policies, publicPolicies } from './routes/policies'
import { prelogin } from './routes/prelogin'
import { register } from './routes/register'
import { downloadSendFile, sends } from './routes/sends'
import { settings } from './routes/settings'
import { stubs } from './routes/stubs'
import { sync } from './routes/sync'
import { token } from './routes/token'
import { twofactor } from './routes/twofactor'
import { purgeExpired } from './vault/purge'

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
// Public and organisation routes come first: org-ciphers hands personal items on to `ciphers`.
app.route('/', publicPolicies)
app.route('/', organizations)
app.route('/', orgUsers)
app.route('/', collectionsRouter)
app.route('/', groupsRouter)
app.route('/', policies)
app.route('/', events)
app.route('/', emergencyAccess)
app.route('/', orgCiphers)
app.route('/', ciphers)
app.route('/', folders)
app.route('/', sends)
app.get('/attachments/:cipherId/:attachmentId', downloadAttachment)
app.get('/send-files/:sendId/:fileId', downloadSendFile)
app.route('/', settings)
app.route('/', twofactor)
app.route('/', authRequests)
app.route('/', notifications)
app.route('/', stubs)
app.route('/', admin)

app.notFound((c) => c.json({ message: 'Not found', validationErrors: null, object: 'error' }, 404))

app.onError((err, c) => {
  if (err instanceof ApiError)
    return c.json(errorBody(err.message, err.validationErrors), err.status)
  // Log only the error, never request data.
  // Log only the message: the URL (which can carry an access token) must never be recorded.
  console.error(err instanceof Error ? err.message : 'unknown error')
  return c.json({ message: 'Internal server error', validationErrors: null, object: 'error' }, 500)
})

export default {
  fetch: app.fetch,
  // Cron Trigger: purge expired Sends and orphaned blobs (TASKS #84).
  scheduled: (_controller: ScheduledController, env: Env['Bindings'], ctx: ExecutionContext) => {
    ctx.waitUntil(purgeExpired(env))
  },
}
export { NotificationHub } from './do/notification-hub'
