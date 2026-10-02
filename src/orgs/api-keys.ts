// Organisation API keys (TASKS #270). Type 0 authenticates the Public API through the
// `client_credentials` grant with `client_id=organization.<id>` and `scope=api.organization`;
// type 2 authenticates SCIM requests. Keys are 30 alphanumeric characters, sealed at rest.
import { and, eq } from 'drizzle-orm'
import type { Context, MiddlewareHandler } from 'hono'
import { safeEqualStrings } from '../auth/crypto'
import { signingSecret, signJwt, verificationSecrets, verifyJwt } from '../auth/jwt'
import { issuerFor } from '../auth/middleware'
import { createDb, type Db, schema } from '../db'
import type { Bindings, Env } from '../env'
import { oauthError } from '../errors'
import { isUuid, newClientSecret } from '../sm/auth'
import { seal, unseal } from './sealed'

export const ApiKeyType = { Default: 0, BillingSync: 1, Scim: 2 } as const
export const ORG_API_SCOPE = 'api.organization'
export const ORG_TOKEN_TTL_SECONDS = 3600

const purpose = (orgUuid: string, type: number) => `org-api-key:${orgUuid}:${type}`

export type ApiKeyRow = typeof schema.organizationApiKeys.$inferSelect

export async function loadApiKey(db: Db, orgUuid: string, type: number) {
  const [row] = await db
    .select()
    .from(schema.organizationApiKeys)
    .where(
      and(
        eq(schema.organizationApiKeys.organizationUuid, orgUuid),
        eq(schema.organizationApiKeys.atype, type),
      ),
    )
    .limit(1)
  return row
}

export const openApiKey = (env: Bindings, row: ApiKeyRow) =>
  unseal(env, purpose(row.organizationUuid, row.atype), row.sealedKey)

/** Returns the key, creating it first when the organisation has none (or replacing it on rotate). */
export async function issueApiKey(
  env: Bindings,
  db: Db,
  orgUuid: string,
  type: number,
  rotate: boolean,
): Promise<{ apiKey: string; revisionDate: number }> {
  const existing = await loadApiKey(db, orgUuid, type)
  if (existing && !rotate) {
    return { apiKey: await openApiKey(env, existing), revisionDate: existing.revisionDate }
  }
  const apiKey = newClientSecret(30)
  const sealedKey = await seal(env, purpose(orgUuid, type), apiKey)
  // Strictly newer than the last revision so tokens bound to the old key stop working.
  const revisionDate = Math.max(Date.now(), (existing?.revisionDate ?? 0) + 1)
  await db
    .insert(schema.organizationApiKeys)
    .values({
      uuid: crypto.randomUUID(),
      organizationUuid: orgUuid,
      atype: type,
      sealedKey,
      revisionDate,
    })
    .onConflictDoUpdate({
      target: [schema.organizationApiKeys.organizationUuid, schema.organizationApiKeys.atype],
      set: { sealedKey, revisionDate },
    })
  return { apiKey, revisionDate }
}

/** Compares a presented key with the stored one in constant time. */
export async function apiKeyMatches(env: Bindings, row: ApiKeyRow | undefined, presented: string) {
  const stored = row ? await openApiKey(env, row).catch(() => null) : null
  const ok = safeEqualStrings(stored ?? '\0'.repeat(30), presented)
  return Boolean(stored) && ok
}

export interface OrgTokenClaims {
  nbf: number
  exp: number
  iss: string
  /** Organisation id. */
  sub: string
  client_id: string
  scope: string[]
  type: 'Organization'
  /** Revision of the key that issued the token; a rotation invalidates older tokens. */
  rev: number
}

/** `client_credentials` grant for `organization.<id>` clients (Public API, Directory Connector). */
export async function organizationLoginGrant(c: Context<Env>, form: Record<string, string>) {
  const bad = () => oauthError(c, 'invalid_client', 'invalid_client', 'Invalid client credentials.')
  const clientId = form.client_id ?? ''
  const orgUuid = clientId.slice('organization.'.length).toLowerCase()
  if (!clientId.startsWith('organization.') || !isUuid(orgUuid) || !form.client_secret) return bad()
  const scopes = (form.scope ?? ORG_API_SCOPE).split(' ').filter(Boolean)
  if (!scopes.every((s) => s === ORG_API_SCOPE)) {
    return oauthError(c, 'invalid_scope', 'invalid_scope', 'Invalid scope.')
  }
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const row = await loadApiKey(db, orgUuid, ApiKeyType.Default)
  if (!row || !(await apiKeyMatches(c.env, row, form.client_secret))) return bad()
  const now = Math.floor(Date.now() / 1000)
  const claims: OrgTokenClaims = {
    nbf: now,
    exp: now + ORG_TOKEN_TTL_SECONDS,
    iss: issuerFor(c.env.DOMAIN),
    sub: orgUuid,
    client_id: clientId,
    scope: [ORG_API_SCOPE],
    type: 'Organization',
    rev: row.revisionDate,
  }
  return c.json({
    access_token: await signJwt(claims, signingSecret(c.env)),
    expires_in: ORG_TOKEN_TTL_SECONDS,
    token_type: 'Bearer',
    scope: ORG_API_SCOPE,
  })
}

const publicUnauthorized = (c: Context<Env>) =>
  c.json({ object: 'error', message: 'Unauthorized.', errors: null }, 401, {
    'WWW-Authenticate': 'Bearer',
  })

/**
 * Authenticates a Public API request: an organisation token whose key has not been rotated since
 * it was issued. Sets `c.var.orgApi`.
 */
export const requireOrgApiAuth: MiddlewareHandler<Env> = async (c, next) => {
  const match = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')
  if (!match?.[1]) return publicUnauthorized(c)
  const claims = await verifyJwt<OrgTokenClaims>(match[1], verificationSecrets(c.env))
  if (
    !claims ||
    claims.iss !== issuerFor(c.env.DOMAIN) ||
    !Array.isArray(claims.scope) ||
    !claims.scope.includes(ORG_API_SCOPE) ||
    typeof claims.sub !== 'string' ||
    typeof claims.rev !== 'number'
  ) {
    return publicUnauthorized(c)
  }
  const row = await loadApiKey(
    createDb(c.env.DB_PRIMARY ?? c.env.DB),
    claims.sub,
    ApiKeyType.Default,
  )
  if (!row || row.revisionDate !== claims.rev) return publicUnauthorized(c)
  c.set('orgApi', { organizationUuid: claims.sub })
  return next()
}
