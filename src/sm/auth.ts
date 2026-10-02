// Secrets Manager machine login and request authentication (TASKS #220).
//
// Wire contract (docs/secrets-manager.md): the SDK splits an access token
// `0.<accessTokenId>.<clientSecret>:<seed>` and sends `grant_type=client_credentials`,
// `scope=api.secrets`, `client_id=<accessTokenId>` and `client_secret=<clientSecret>` to the
// identity token endpoint. The response carries `encrypted_payload`, the organisation key the
// client encrypted under a key derived from the seed when it created the token. The server never
// sees the seed, so it cannot read that payload.
import { and, eq } from 'drizzle-orm'
import type { Context, MiddlewareHandler } from 'hono'
import { safeEqualStrings, sha256B64u } from '../auth/crypto'
import { signingSecret, signJwt, verificationSecrets, verifyJwt } from '../auth/jwt'
import { authenticateAccessToken, issuerFor } from '../auth/middleware'
import { createDb, schema } from '../db'
import type { Env, MachineTokenClaims } from '../env'
import { oauthError } from '../errors'

export const MACHINE_SCOPE = 'api.secrets'
export const MACHINE_TOKEN_TTL_SECONDS = 3600

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
export const isUuid = (s: string) => UUID.test(s)

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

/** A 30 character alphanumeric client secret (no `.` or `:`, which delimit the access token). */
export function newClientSecret(length = 30): string {
  const out: string[] = []
  // Rejection sampling keeps the distribution uniform over the 62 symbols.
  while (out.length < length) {
    for (const b of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (b < 248 && out.length < length) out.push(ALPHABET[b % 62] as string)
    }
  }
  return out.join('')
}

const unauthorized = (c: Context<Env>) =>
  c.json({ message: 'Unauthorized', validationErrors: null, object: 'error' }, 401, {
    'WWW-Authenticate': 'Bearer',
  })

/** `client_credentials` grant with `scope=api.secrets`: machine account login. */
export async function machineLoginGrant(c: Context<Env>, form: Record<string, string>) {
  const bad = () => oauthError(c, 'invalid_client', 'invalid_client', 'Invalid client credentials.')
  const clientId = form.client_id ?? ''
  if (!isUuid(clientId) || !form.client_secret) return bad()
  const db = createDb(c.env.DB)
  const [row] = await db
    .select({ t: schema.smAccessTokens, sa: schema.smServiceAccounts })
    .from(schema.smAccessTokens)
    .innerJoin(
      schema.smServiceAccounts,
      eq(schema.smServiceAccounts.uuid, schema.smAccessTokens.serviceAccountUuid),
    )
    .where(eq(schema.smAccessTokens.uuid, clientId.toLowerCase()))
    .limit(1)
  const hash = await sha256B64u(form.client_secret)
  const matches = safeEqualStrings(row?.t.clientSecretHash ?? '\0', hash)
  if (!row || !matches) return bad()
  if (row.t.expiresAt !== null && row.t.expiresAt <= Date.now()) return bad()

  const now = Math.floor(Date.now() / 1000)
  const expiry = row.t.expiresAt === null ? Number.POSITIVE_INFINITY : row.t.expiresAt / 1000
  const exp = Math.floor(Math.min(now + MACHINE_TOKEN_TTL_SECONDS, expiry))
  const claims: MachineTokenClaims = {
    nbf: now,
    exp,
    iss: issuerFor(c.env.DOMAIN),
    sub: row.sa.uuid,
    organization: row.sa.organizationUuid,
    client_id: row.t.uuid,
    scope: [MACHINE_SCOPE],
    type: 'ServiceAccount',
  }
  // No Kdf or Key members: the SDK would then read this as a user login (docs/secrets-manager.md).
  return c.json({
    access_token: await signJwt(claims, signingSecret(c.env)),
    expires_in: exp - now,
    token_type: 'Bearer',
    scope: MACHINE_SCOPE,
    encrypted_payload: row.t.encryptedPayload,
  })
}

/**
 * Authenticates a Secrets Manager request. Accepts a member access token (scope `api`, same checks
 * as `requireAuth`) or a machine token (scope `api.secrets`) whose access token still exists, has
 * not expired and still belongs to the named machine account. Machine tokens are accepted only on
 * routes that use this middleware; `requireAuth` rejects them everywhere else.
 */
export const requireSmAuth: MiddlewareHandler<Env> = async (c, next) => {
  if (c.var.sm) return next()
  const match = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')
  if (!match?.[1]) return unauthorized(c)
  const token = match[1]
  const claims = await verifyJwt<MachineTokenClaims>(token, verificationSecrets(c.env))
  if (!claims || claims.iss !== issuerFor(c.env.DOMAIN) || !Array.isArray(claims.scope)) {
    return unauthorized(c)
  }
  if (claims.scope.includes('api')) {
    const authed = await authenticateAccessToken(c.env, token)
    if (!authed) return unauthorized(c)
    c.set('user', authed.user)
    c.set('auth', { claims: authed.claims, deviceIdentifier: authed.claims.device })
    c.set('sm', { kind: 'user', user: authed.user })
    return next()
  }
  if (
    !claims.scope.includes(MACHINE_SCOPE) ||
    typeof claims.client_id !== 'string' ||
    typeof claims.sub !== 'string' ||
    typeof claims.organization !== 'string'
  ) {
    return unauthorized(c)
  }
  // Revocation is immediate: the token row is read on every request, never from a replica.
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const [row] = await db
    .select({ t: schema.smAccessTokens, sa: schema.smServiceAccounts })
    .from(schema.smAccessTokens)
    .innerJoin(
      schema.smServiceAccounts,
      eq(schema.smServiceAccounts.uuid, schema.smAccessTokens.serviceAccountUuid),
    )
    .where(
      and(
        eq(schema.smAccessTokens.uuid, claims.client_id),
        eq(schema.smAccessTokens.serviceAccountUuid, claims.sub),
      ),
    )
    .limit(1)
  if (
    !row ||
    row.sa.organizationUuid !== claims.organization ||
    (row.t.expiresAt !== null && row.t.expiresAt <= Date.now())
  ) {
    return unauthorized(c)
  }
  c.set('sm', {
    kind: 'machine',
    serviceAccountUuid: row.sa.uuid,
    organizationUuid: row.sa.organizationUuid,
    accessTokenUuid: row.t.uuid,
  })
  return next()
}
