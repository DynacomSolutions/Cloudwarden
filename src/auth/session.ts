import { and, eq } from 'drizzle-orm'
import type { Db } from '../db'
import { createDb, schema } from '../db'
import type { AccessTokenClaims, Bindings, User } from '../env'
import { masterPasswordPolicyFor } from '../orgs/policies'
import { randomB64u, sha256B64u } from './crypto'
import { signingSecret, signJwt } from './jwt'
import { issuerFor } from './middleware'

export const ACCESS_TOKEN_TTL_SECONDS = 3600
/** Refresh tokens expire this long after the device last logged in or refreshed. */
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 3600 * 1000

export interface DeviceInput {
  identifier: string
  name: string
  type: number
}

/**
 * Creates or updates the device row for (user, identifier) and issues a fresh refresh
 * token secret. Returns the opaque refresh token the client stores.
 */
export async function registerDevice(db: Db, userUuid: string, d: DeviceInput): Promise<string> {
  const now = Date.now()
  const uuid = crypto.randomUUID()
  const secret = randomB64u(32)
  await db
    .insert(schema.devices)
    .values({
      uuid,
      identifier: d.identifier,
      userUuid,
      name: d.name,
      type: d.type,
      refreshToken: await sha256B64u(secret),
      createdAt: now,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: [schema.devices.userUuid, schema.devices.identifier],
      set: { name: d.name, type: d.type, refreshToken: await sha256B64u(secret), updatedAt: now },
    })
  const [row] = await db
    .select({ uuid: schema.devices.uuid })
    .from(schema.devices)
    .where(and(eq(schema.devices.userUuid, userUuid), eq(schema.devices.identifier, d.identifier)))
    .limit(1)
  return `${row?.uuid ?? uuid}.${secret}`
}

export async function signAccessToken(
  env: Bindings,
  user: User,
  deviceIdentifier: string,
  scope: string[],
  clientId?: string,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const claims: AccessTokenClaims = {
    nbf: now,
    exp: now + ACCESS_TOKEN_TTL_SECONDS,
    iss: issuerFor(env.DOMAIN),
    sub: user.uuid,
    email: user.email,
    name: user.name,
    premium: true,
    email_verified: user.verifiedAt !== null,
    sstamp: user.securityStamp,
    device: deviceIdentifier,
    scope,
    amr: ['Application'],
    ...(clientId ? { client_id: clientId } : {}),
  }
  return signJwt(claims, signingSecret(env))
}

/** Token endpoint success body, in the shape the official clients read. */
export async function tokenResponse(
  env: Bindings,
  user: User,
  opts: { deviceIdentifier: string; scope: string[]; refreshToken?: string; clientId?: string },
) {
  return {
    access_token: await signAccessToken(
      env,
      user,
      opts.deviceIdentifier,
      opts.scope,
      opts.clientId,
    ),
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    token_type: 'Bearer',
    ...(opts.refreshToken ? { refresh_token: opts.refreshToken } : {}),
    scope: opts.scope.join(' '),
    Key: user.akey,
    PrivateKey: user.privateKey,
    Kdf: user.kdfType,
    KdfIterations: user.kdfIterations,
    KdfMemory: user.kdfMemory,
    KdfParallelism: user.kdfParallelism,
    ResetMasterPassword: false,
    ForcePasswordReset: false,
    MasterPasswordPolicy: await masterPasswordPolicyJson(env, user.uuid),
    UserDecryptionOptions: { HasMasterPassword: true, Object: 'userDecryptionOptions' },
    UnofficialServer: true,
    Object: 'token',
  }
}

/**
 * Statements that rotate the security stamp and revoke every refresh token of a user.
 * Include them in the same `runBatch` as the credential change they accompany.
 */
export function stampRotationStatements(db: Db, userUuid: string) {
  return [
    db
      .update(schema.users)
      .set({ securityStamp: crypto.randomUUID(), updatedAt: Date.now() })
      .where(eq(schema.users.uuid, userUuid)),
    db
      .update(schema.devices)
      .set({ refreshToken: '' })
      .where(eq(schema.devices.userUuid, userUuid)),
  ]
}

/** Requirements merged across the user's organisations, in the identity service's casing. */
async function masterPasswordPolicyJson(env: Bindings, userUuid: string) {
  const p = await masterPasswordPolicyFor(createDb(env.DB), userUuid)
  if (!p) return { Object: 'masterPasswordPolicy' }
  return {
    MinComplexity: p.minComplexity,
    MinLength: p.minLength,
    RequireUpper: p.requireUpper,
    RequireLower: p.requireLower,
    RequireNumbers: p.requireNumbers,
    RequireSpecial: p.requireSpecial,
    EnforceOnLogin: p.enforceOnLogin,
    Object: 'masterPasswordPolicy',
  }
}
