// Access connector sign-in and request authentication (docs/privileged-access.md).
//
// A connector gets a client id and secret when an admin registers it. It then signs in at the
// identity token endpoint with `grant_type=client_credentials`, `scope=api.access-connector`,
// `client_id=access-connector.<apiKeyId>` and `client_secret`. This reuses the machine account
// design: only a SHA-256 of the secret is stored, and the response carries the opaque
// `encrypted_payload` (the organisation key under the connector's own key) that the registering
// client created. A disabled or deleted connector loses access at once, because the row is read on
// every request.
import { and, eq, isNull, lt, or } from 'drizzle-orm'
import type { Context, MiddlewareHandler } from 'hono'
import { safeEqualStrings, sha256B64u } from '../auth/crypto'
import { signingSecret, signJwt, verificationSecrets, verifyJwt } from '../auth/jwt'
import { issuerFor } from '../auth/middleware'
import { createDb, schema } from '../db'
import type { ConnectorTokenClaims, Env } from '../env'
import { oauthError } from '../errors'
import { organizationActive } from '../orgs/api-keys'
import { isUuid } from '../sm/auth'
import {
  CONNECTOR_CLIENT_PREFIX,
  CONNECTOR_SCOPE,
  CONNECTOR_TOKEN_TTL_SECONDS,
  ConnectorStatus,
  HEARTBEAT_MIN_INTERVAL_MS,
} from './constants'

/** SHA-256 (base64url) of nothing a client can send: the comparison target for unknown ids. */
const DUMMY_HASH = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

const unauthorized = (c: Context<Env>) =>
  c.json({ message: 'Unauthorized', validationErrors: null, object: 'error' }, 401, {
    'WWW-Authenticate': 'Bearer',
  })

/** `client_credentials` grant with `scope=api.access-connector`. */
export async function connectorLoginGrant(c: Context<Env>, form: Record<string, string>) {
  const bad = () => oauthError(c, 'invalid_client', 'invalid_client', 'Invalid client credentials.')
  const clientId = form.client_id ?? ''
  const apiKeyId = clientId.slice(CONNECTOR_CLIENT_PREFIX.length).toLowerCase()
  if (!clientId.startsWith(CONNECTOR_CLIENT_PREFIX) || !isUuid(apiKeyId) || !form.client_secret) {
    return bad()
  }
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const [row] = await db
    .select()
    .from(schema.pamAccessConnectors)
    .where(eq(schema.pamAccessConnectors.apiKeyId, apiKeyId))
    .limit(1)
  const hash = await sha256B64u(form.client_secret)
  const matches = safeEqualStrings(row?.clientSecretHash ?? DUMMY_HASH, hash)
  if (!row || !matches) return bad()
  if (
    row.status !== ConnectorStatus.Enabled ||
    !(await organizationActive(db, row.organizationUuid))
  ) {
    return bad()
  }
  const now = Math.floor(Date.now() / 1000)
  const claims: ConnectorTokenClaims = {
    nbf: now,
    exp: now + CONNECTOR_TOKEN_TTL_SECONDS,
    iss: issuerFor(c.env.DOMAIN),
    sub: row.uuid,
    organization: row.organizationUuid,
    client_id: clientId,
    scope: [CONNECTOR_SCOPE],
    type: 'AccessConnector',
  }
  await db
    .update(schema.pamAccessConnectors)
    .set({ lastHeartbeatAt: Date.now() })
    .where(eq(schema.pamAccessConnectors.uuid, row.uuid))
  return c.json({
    access_token: await signJwt(claims, signingSecret(c.env)),
    expires_in: CONNECTOR_TOKEN_TTL_SECONDS,
    token_type: 'Bearer',
    scope: CONNECTOR_SCOPE,
    encrypted_payload: row.encryptedPayload,
    key: row.key,
  })
}

/**
 * Authenticates a connector-facing request: a connector token whose connector still exists and is
 * enabled. Sets `c.var.connector` and records a heartbeat, at most once per
 * `HEARTBEAT_MIN_INTERVAL_MS`. User tokens are refused here and connector tokens everywhere else.
 */
export const requireConnectorAuth: MiddlewareHandler<Env> = async (c, next) => {
  const match = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')
  if (!match?.[1]) return unauthorized(c)
  const claims = await verifyJwt<ConnectorTokenClaims>(match[1], verificationSecrets(c.env))
  if (
    !claims ||
    claims.iss !== issuerFor(c.env.DOMAIN) ||
    !Array.isArray(claims.scope) ||
    !claims.scope.includes(CONNECTOR_SCOPE) ||
    claims.type !== 'AccessConnector' ||
    typeof claims.sub !== 'string' ||
    typeof claims.organization !== 'string'
  ) {
    return unauthorized(c)
  }
  // Disabling or deleting a connector takes effect at once: read the primary every time.
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const [row] = await db
    .select()
    .from(schema.pamAccessConnectors)
    .where(
      and(
        eq(schema.pamAccessConnectors.uuid, claims.sub),
        eq(schema.pamAccessConnectors.organizationUuid, claims.organization),
      ),
    )
    .limit(1)
  if (!row || row.status !== ConnectorStatus.Enabled) return unauthorized(c)
  const now = Date.now()
  await db
    .update(schema.pamAccessConnectors)
    .set({ lastHeartbeatAt: now })
    .where(
      and(
        eq(schema.pamAccessConnectors.uuid, row.uuid),
        or(
          isNull(schema.pamAccessConnectors.lastHeartbeatAt),
          lt(schema.pamAccessConnectors.lastHeartbeatAt, now - HEARTBEAT_MIN_INTERVAL_MS),
        ),
      ),
    )
  c.set('connector', { uuid: row.uuid, organizationUuid: row.organizationUuid })
  return next()
}
