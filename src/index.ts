import { Hono } from 'hono'
import { adminApi } from './admin/api'
import { d1Sessions } from './db/sessions'
import type { Env } from './env'
import { ApiError, errorBody } from './errors'
import { errorKind, log, requestLogger } from './log'
import { securityHeaders } from './middleware'
import { orgChangeNotifier, secretsRevisionOnMemberChange } from './orgs/notify'
import { accountEmail } from './routes/account-email'
import { accounts } from './routes/accounts'
import { alive } from './routes/alive'
import { appId } from './routes/app-id'
import { archive } from './routes/archive'
import { downloadAttachment } from './routes/attachments'
import { authRequests } from './routes/auth-requests'
import { ciphers } from './routes/ciphers'
import { collectionsRouter } from './routes/collections'
import { config } from './routes/config'
import { devices } from './routes/devices'
import { emergencyAccess } from './routes/emergency-access'
import { events } from './routes/events'
import { folders } from './routes/folders'
import { groupsRouter } from './routes/groups'
import { icons } from './routes/icons'
import { notifications } from './routes/notifications'
import { orgCiphers } from './routes/org-ciphers'
import { orgUsers } from './routes/org-users'
import { organizations } from './routes/organizations'
import { policies, publicPolicies } from './routes/policies'
import { prelogin } from './routes/prelogin'
import { register } from './routes/register'
import { secretsManager } from './routes/secrets-manager'
import { downloadSendFile, sends } from './routes/sends'
import { settings } from './routes/settings'
import { sync } from './routes/sync'
import { token } from './routes/token'
import { twofactor } from './routes/twofactor'
import { webauthn } from './routes/webauthn'
import { scheduled } from './scheduled'

const app = new Hono<Env>()

app.use('*', requestLogger)
app.use('*', securityHeaders)
app.use('*', d1Sessions)

app.route('/', alive)
app.route('/', appId)
app.route('/', config)
app.route('/', icons)
app.route('/', prelogin)
app.route('/', register)
app.route('/', token)
app.route('/', devices)
app.route('/', accounts)
app.route('/', accountEmail)
app.route('/', sync)
// Secrets Manager accepts machine tokens, so it runs before the organisation routers whose
// `authOnce` middleware would refuse them (TASKS #220).
app.route('/', secretsManager)
// Public and organisation routes come first: org-ciphers hands personal items on to `ciphers`.
app.use('/api/organizations/:orgId/*', orgChangeNotifier)
for (const path of [
  '/api/organizations/:orgId/users',
  '/api/organizations/:orgId/users/*',
  '/api/organizations/:orgId/groups',
  '/api/organizations/:orgId/groups/*',
  '/api/organizations/:id/leave',
]) {
  app.use(path, secretsRevisionOnMemberChange)
}
app.route('/', publicPolicies)
app.route('/', organizations)
app.route('/', orgUsers)
app.route('/', collectionsRouter)
app.route('/', groupsRouter)
app.route('/', policies)
app.route('/', events)
app.route('/', emergencyAccess)
app.route('/', archive)
app.route('/', orgCiphers)
app.route('/', ciphers)
app.route('/', folders)
app.route('/', sends)
app.get('/attachments/:cipherId/:attachmentId', downloadAttachment)
app.get('/send-files/:sendId/:fileId', downloadSendFile)
app.route('/', settings)
app.route('/', twofactor)
app.route('/', webauthn)
app.route('/', authRequests)
app.route('/', notifications)
app.route('/', adminApi)

app.notFound((c) => c.json({ message: 'Not found', validationErrors: null, object: 'error' }, 404))

app.onError((err, c) => {
  if (err instanceof ApiError)
    return c.json(errorBody(err.message, err.validationErrors), err.status)
  log(
    'error',
    'unhandled',
    { errorKind: errorKind(err), method: c.req.method, route: c.req.routePath },
    c.env,
  )
  return c.json({ message: 'Internal server error', validationErrors: null, object: 'error' }, 500)
})

export { app }
export default { fetch: app.fetch, scheduled } satisfies ExportedHandler<Env['Bindings']>
export { NotificationHub } from './do/notification-hub'
