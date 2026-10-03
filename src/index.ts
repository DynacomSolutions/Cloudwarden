import { Hono } from 'hono'
import { adminApi } from './admin/api'
import { d1Sessions } from './db/sessions'
import type { Env } from './env'
import { ApiError, errorBody } from './errors'
import { federationForwarder } from './federation/forward'
import { federation } from './federation/routes'
import { errorKind, log, requestLogger } from './log'
import { securityHeaders } from './middleware'
import { orgChangeNotifier, secretsRevisionOnMemberChange } from './orgs/notify'
import { accountEmail } from './routes/account-email'
import { accountRecovery } from './routes/account-recovery'
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
import { discovery } from './routes/discovery'
import { emergencyAccess } from './routes/emergency-access'
import { events } from './routes/events'
import { folders } from './routes/folders'
import { groupsRouter } from './routes/groups'
import { icons } from './routes/icons'
import { notificationCenter } from './routes/notification-center'
import { notifications } from './routes/notifications'
import { orgApiKeys } from './routes/org-api-keys'
import { orgAuthRequests } from './routes/org-auth-requests'
import { orgCiphers } from './routes/org-ciphers'
import { orgConnections } from './routes/org-connections'
import { orgDeleteRecover } from './routes/org-delete-recover'
import { orgImport } from './routes/org-import'
import { orgIntegrations } from './routes/org-integrations'
import { orgIntegrationsApi } from './routes/org-integrations-api'
import { orgSettings } from './routes/org-settings'
import { orgUsers } from './routes/org-users'
import { organizations } from './routes/organizations'
import { policies, publicPolicies } from './routes/policies'
import { prelogin } from './routes/prelogin'
import { providers } from './routes/providers'
import { publicApi } from './routes/public-api'
import { register } from './routes/register'
import { reports } from './routes/reports'
import { secretsManager } from './routes/secrets-manager'
import { selfHostBilling } from './routes/self-host-billing'
import { downloadSendFile, sends } from './routes/sends'
import { settings } from './routes/settings'
import { sso } from './routes/sso'
import { publicSso, ssoAccounts, ssoAdmin } from './routes/sso-admin'
import { sync } from './routes/sync'
import { token } from './routes/token'
import { twofactor } from './routes/twofactor'
import { webauthn } from './routes/webauthn'
import { scheduled } from './scheduled'
import { scim } from './scim/routes'

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
app.route('/', discovery)
// SSO browser endpoints and service provider callbacks (TASKS #280 to #282).
app.route('/', sso)
app.route('/', devices)
app.route('/', ssoAccounts)
app.route('/', accounts)
app.route('/', accountEmail)
app.route('/', sync)
// Organisation-token APIs (TASKS #271, #273): their own authentication, before member routers.
app.route('/', publicApi)
app.route('/', scim)
// Federated organisations (TASKS #300): signed peer API, then forwarding of client requests that
// touch an organisation hosted on a peer. Inert unless FEDERATION_ENABLED is true.
app.route('/', federation)
for (const path of [
  '/api/ciphers',
  '/api/ciphers/*',
  '/api/organizations/:orgId',
  '/api/organizations/:orgId/*',
]) {
  app.use(path, federationForwarder)
}
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
// Before the other organisation routers: its public invite-link routes skip their `authOnce`.
app.route('/', orgDeleteRecover)
app.route('/', orgIntegrationsApi)
app.route('/', orgSettings)
// Anonymous SSO discovery by email must run before the authenticated organisation routers.
app.route('/', publicSso)
app.route('/', ssoAdmin)
app.route('/', orgApiKeys)
app.route('/', orgIntegrations)
// Billing, licence and sponsorship answers for a self-hosted server, and the absent Provider
// Portal (TASKS #231). Literal paths only, so the order relative to the organisation routers is free.
app.route('/', selfHostBilling)
app.route('/', providers)
// Organisation connections: literal `connections` paths, answered like a server without cloud links.
app.route('/', orgConnections)
app.route('/', organizations)
// Before orgUsers: `users/account-recovery-details` must not be read as a member id.
app.route('/', accountRecovery)
app.route('/', orgAuthRequests)
app.route('/', orgImport)
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
app.route('/', reports)
app.route('/', settings)
app.route('/', twofactor)
app.route('/', webauthn)
app.route('/', authRequests)
app.route('/', notificationCenter)
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
