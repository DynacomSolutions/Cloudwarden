import { eq } from 'drizzle-orm'
import type { MiddlewareHandler } from 'hono'
import { createDb, schema } from '../db'
import type { AccessTokenClaims, Env, User } from '../env'
import { FEDERATION_CLIENT_ID, isStandInUser } from '../federation/standin'
import { verifyAccessJwt } from './access-keys'
import { safeEqualStrings } from './crypto'

export const issuerFor = (domain: string): string => domain.replace(/\/+$/, '')

const unauthorized = (c: Parameters<MiddlewareHandler<Env>>[0]) =>
  c.json({ message: 'Unauthorized', validationErrors: null, object: 'error' }, 401, {
    'WWW-Authenticate': 'Bearer',
  })

/**
 * Verifies an access token (signature, issuer, `api` scope), loads the user and checks
 * the security stamp and that the account is enabled. Returns null on any failure.
 */
export async function authenticateAccessToken(
  env: Env['Bindings'],
  token: string,
): Promise<{ user: User; claims: AccessTokenClaims } | null> {
  const claims = await verifyAccessJwt<AccessTokenClaims>(env, token)
  if (
    !claims ||
    claims.iss !== issuerFor(env.DOMAIN) ||
    typeof claims.sub !== 'string' ||
    !Array.isArray(claims.scope) ||
    !claims.scope.includes('api')
  ) {
    return null
  }

  // The user row, security stamp and enabled flag decide revocation, so they are never read from
  // a replica (docs/d1-sessions.md).
  const [user] = await createDb(env.DB_PRIMARY ?? env.DB)
    .select()
    .from(schema.users)
    .where(eq(schema.users.uuid, claims.sub))
    .limit(1)
  if (!user?.enabled || !safeEqualStrings(claims.sstamp ?? '', user.securityStamp)) return null
  // Stand-in accounts of federated members only act through signed peer requests (TASKS #303).
  if (isStandInUser(user) && claims.client_id !== FEDERATION_CLIENT_ID) return null
  return { user, claims }
}

/**
 * Verifies the Bearer access token, loads the user, checks the security stamp and
 * that the account is enabled, then sets `c.var.user` and `c.var.auth`.
 * Responds 401 otherwise. Stable export: other route modules depend on it.
 */
export const requireAuth: MiddlewareHandler<Env> = async (c, next) => {
  const match = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')
  if (!match?.[1]) return unauthorized(c)
  const authed = await authenticateAccessToken(c.env, match[1])
  if (!authed) return unauthorized(c)

  c.set('user', authed.user)
  c.set('auth', { claims: authed.claims, deviceIdentifier: authed.claims.device })
  await next()
}
