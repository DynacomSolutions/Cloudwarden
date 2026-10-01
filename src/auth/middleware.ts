import { eq } from 'drizzle-orm'
import type { MiddlewareHandler } from 'hono'
import { createDb, schema } from '../db'
import type { AccessTokenClaims, Env } from '../env'
import { safeEqualStrings } from './crypto'
import { verificationSecrets, verifyJwt } from './jwt'

export const issuerFor = (domain: string): string => domain.replace(/\/+$/, '')

const unauthorized = (c: Parameters<MiddlewareHandler<Env>>[0]) =>
  c.json({ message: 'Unauthorized', validationErrors: null, object: 'error' }, 401, {
    'WWW-Authenticate': 'Bearer',
  })

/**
 * Verifies the Bearer access token, loads the user, checks the security stamp and
 * that the account is enabled, then sets `c.var.user` and `c.var.auth`.
 * Responds 401 otherwise. Stable export: other route modules depend on it.
 */
export const requireAuth: MiddlewareHandler<Env> = async (c, next) => {
  const match = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')
  if (!match?.[1]) return unauthorized(c)

  const claims = await verifyJwt<AccessTokenClaims>(match[1], verificationSecrets(c.env))
  if (
    !claims ||
    claims.iss !== issuerFor(c.env.DOMAIN) ||
    typeof claims.sub !== 'string' ||
    !Array.isArray(claims.scope) ||
    !claims.scope.includes('api')
  ) {
    return unauthorized(c)
  }

  const db = createDb(c.env.DB)
  const [user] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.uuid, claims.sub))
    .limit(1)
  if (!user?.enabled || !safeEqualStrings(claims.sstamp ?? '', user.securityStamp)) {
    return unauthorized(c)
  }

  c.set('user', user)
  c.set('auth', { claims, deviceIdentifier: claims.device })
  await next()
}
