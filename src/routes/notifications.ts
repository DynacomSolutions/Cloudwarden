import { and, eq, gt } from 'drizzle-orm'
import { Hono } from 'hono'
import { authenticateAccessToken } from '../auth/middleware'
import { createDb, schema } from '../db'
import { DEVICE_HEADER, EXPIRES_HEADER, stripInternalHeaders } from '../do/notification-hub'
import type { Env } from '../env'
import { anonymousHubName } from '../notifications/publish'
import { AUTH_REQUEST_TTL_MS } from './auth-requests'

/** Bitwarden notification hubs: `/notifications/hub` (per user) and `/notifications/anonymous-hub`. */
export const notifications = new Hono<Env>()

type Ctx = import('hono').Context<Env>

const unauthorized = (c: Ctx) =>
  c.json({ message: 'Unauthorized', validationErrors: null, object: 'error' }, 401, {
    'WWW-Authenticate': 'Bearer',
  })

/** SignalR clients pass the token as `access_token` (WebSocket) or a Bearer header (negotiate). */
async function authenticate(c: Ctx) {
  const header = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')?.[1]
  const token = c.req.query('access_token') ?? header
  return token ? authenticateAccessToken(c.env, token) : null
}

const wantsWebSocket = (c: Ctx) => c.req.header('Upgrade')?.toLowerCase() === 'websocket'

notifications.get('/notifications/hub', async (c) => {
  if (!wantsWebSocket(c)) return c.text('Expected WebSocket upgrade', 426)
  const authed = await authenticate(c)
  if (!authed) return unauthorized(c)

  const headers = stripInternalHeaders(c.req.raw.headers)
  headers.set(DEVICE_HEADER, authed.claims.device ?? '')
  const stub = c.env.NOTIFICATIONS.get(c.env.NOTIFICATIONS.idFromName(authed.user.uuid))
  return stub.fetch(new Request(c.req.url, { headers }))
})

/** Negotiate response for clients that do not skip negotiation (SignalR negotiate version 1). */
const negotiate = async (c: Ctx, authed: boolean) => {
  if (authed && !(await authenticate(c))) return unauthorized(c)
  const connectionToken = crypto.randomUUID().replaceAll('-', '')
  return c.json({
    connectionId: crypto.randomUUID().replaceAll('-', ''),
    connectionToken,
    negotiateVersion: 1,
    availableTransports: [{ transport: 'WebSockets', transferFormats: ['Text', 'Binary'] }],
  })
}
notifications.post('/notifications/hub/negotiate', (c) => negotiate(c, true))
notifications.post('/notifications/anonymous-hub/negotiate', (c) => negotiate(c, false))

// Unauthenticated: the token is the id of a pending login-with-device request.
notifications.get('/notifications/anonymous-hub', async (c) => {
  if (!wantsWebSocket(c)) return c.text('Expected WebSocket upgrade', 426)
  const id = c.req.query('Token') ?? c.req.query('token') ?? ''
  const [row] = id
    ? await createDb(c.env.DB)
        .select({ uuid: schema.authRequests.uuid, createdAt: schema.authRequests.createdAt })
        .from(schema.authRequests)
        .where(
          and(
            eq(schema.authRequests.uuid, id),
            gt(schema.authRequests.createdAt, Date.now() - AUTH_REQUEST_TTL_MS),
          ),
        )
        .limit(1)
    : []
  if (!row) return c.json({ message: 'Not found', validationErrors: null, object: 'error' }, 404)

  const stub = c.env.NOTIFICATIONS.get(c.env.NOTIFICATIONS.idFromName(anonymousHubName(row.uuid)))
  const headers = stripInternalHeaders(c.req.raw.headers)
  headers.set(EXPIRES_HEADER, String(row.createdAt + AUTH_REQUEST_TTL_MS))
  return stub.fetch(new Request(c.req.url, { headers }))
})
