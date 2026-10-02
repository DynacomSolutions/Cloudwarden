import { and, eq, isNotNull, isNull, ne, notInArray, or } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { authenticationData, checkNested, toKdfParams, unlockData } from '../auth/credentials'
import { randomB64u } from '../auth/crypto'
import { requireAuth } from '../auth/middleware'
import { hashMasterPassword, verifyMasterPassword } from '../auth/passwords'
import { accountKeysJson, stampRotationStatements } from '../auth/session'
import { findUserByEmail, normalizeEmail } from '../auth/users'
import { createDb, runBatch, schema } from '../db'
import {
  createEmailTransport,
  emailChangedNewEmail,
  emailChangedOldEmail,
  genericEmail,
} from '../email'
import { later, sendNotice } from '../email/send'
import type { Env, User } from '../env'
import { ApiError } from '../errors'
import { federatedProfileOrgs } from '../federation/replica'
import { pushLogOut } from '../notifications/publish'
import { relayDeleteDevice } from '../notifications/relay'
import { EventType } from '../orgs/constants'
import { assertNotClaimed } from '../orgs/domains'
import { eventStatement } from '../orgs/events'
import { assertNotSoleOwner } from '../orgs/members'
import { profileOrganizations } from '../orgs/views'
import { type KdfParams, kdfProblem, parseBody } from '../validation'
import { userAttachmentKeys } from '../vault/attachments'
import { deleteBlobs } from '../vault/blobs'
import { packPayload } from '../vault/ciphers'
import { userSendKeys } from '../vault/sends'

export const accounts = new Hono<Env>()

type Ctx = import('hono').Context<Env>

const EMAIL_TOKEN_TTL_MS = 10 * 60 * 1000

export async function profileJson(c: Ctx, user: User) {
  const [tf] = await createDb(c.env.DB)
    .select({ uuid: schema.twofactor.uuid })
    .from(schema.twofactor)
    .where(and(eq(schema.twofactor.userUuid, user.uuid), eq(schema.twofactor.enabled, true)))
    .limit(1)
  return {
    id: user.uuid,
    name: user.name,
    email: user.email,
    emailVerified: user.verifiedAt !== null,
    premium: true,
    premiumFromOrganization: false,
    masterPasswordHint: user.passwordHint,
    culture: 'en-US',
    twoFactorEnabled: tf !== undefined,
    key: user.akey || null,
    privateKey: user.privateKey,
    accountKeys: accountKeysJson(user),
    securityStamp: user.securityStamp,
    forcePasswordReset: user.forcePasswordReset,
    usesKeyConnector: user.usesKeyConnector,
    verifyDevices: user.verifyDevices,
    avatarColor: user.avatarColor,
    creationDate: new Date(user.createdAt).toISOString(),
    organizations: [
      ...(await profileOrganizations(createDb(c.env.DB), user.uuid)),
      ...(await federatedProfileOrgs(c.env, user.uuid)),
    ],
    providers: [],
    providerOrganizations: [],
    object: 'profile',
  }
}

async function reloadUser(c: Ctx, uuid: string): Promise<User> {
  const [u] = await createDb(c.env.DB)
    .select()
    .from(schema.users)
    .where(eq(schema.users.uuid, uuid))
    .limit(1)
  if (!u) throw new ApiError(404, 'User not found.')
  return u
}

async function requirePassword(user: User, masterPasswordHash: string) {
  if (!(await verifyMasterPassword(user, masterPasswordHash))) {
    throw new ApiError(400, 'Invalid password.', { masterPasswordHash: ['Invalid password.'] })
  }
}

const passwordOnly = z.object({ masterPasswordHash: z.string().min(1) })

accounts.get('/api/accounts/profile', requireAuth, async (c) =>
  c.json(await profileJson(c, c.var.user)),
)

const profileSchema = z.object({
  name: z.string().max(50).nullish(),
  masterPasswordHint: z.string().max(50).nullish(),
  culture: z.string().nullish(),
})
const updateProfile = async (c: Ctx) => {
  const body = await parseBody(c, profileSchema)
  const user = c.var.user
  await createDb(c.env.DB)
    .update(schema.users)
    .set({
      name: body.name ?? user.name,
      passwordHint:
        body.masterPasswordHint === undefined ? user.passwordHint : body.masterPasswordHint,
      updatedAt: Date.now(),
    })
    .where(eq(schema.users.uuid, user.uuid))
  return c.json(await profileJson(c, await reloadUser(c, user.uuid)))
}
accounts.put('/api/accounts/profile', requireAuth, updateProfile)
accounts.post('/api/accounts/profile', requireAuth, updateProfile)

// The avatar colour is a display preference only (a CSS hex colour, or null for the default).
const avatarSchema = z.object({
  avatarColor: z
    .string()
    .regex(/^#[0-9a-fA-F]{6}$/)
    .nullish(),
})
const updateAvatar = async (c: Ctx) => {
  const { avatarColor } = await parseBody(c, avatarSchema)
  await createDb(c.env.DB)
    .update(schema.users)
    .set({ avatarColor: avatarColor ?? null, updatedAt: Date.now() })
    .where(eq(schema.users.uuid, c.var.user.uuid))
  return c.json(await profileJson(c, await reloadUser(c, c.var.user.uuid)))
}
accounts.put('/api/accounts/avatar', requireAuth, updateAvatar)
accounts.post('/api/accounts/avatar', requireAuth, updateAvatar)

accounts.get('/api/accounts/keys', requireAuth, (c) => {
  const user = c.var.user
  return c.json({
    key: user.akey,
    publicKey: user.publicKey,
    privateKey: user.privateKey,
    accountKeys: accountKeysJson(user),
    object: 'keys',
  })
})

accounts.get('/api/accounts/organizations', requireAuth, async (c) =>
  c.json({
    data: await profileOrganizations(createDb(c.env.DB), c.var.user.uuid),
    object: 'list',
    continuationToken: null,
  }),
)

// Vault writes bump `users.updatedAt` (TASKS #43), so it is the account revision date.
accounts.get('/api/accounts/revision-date', requireAuth, (c) => c.json(c.var.user.updatedAt))

// The SDK (2026.x) reports the identifier of the user key after unlock (`SetUserKeyIdRequestModel`).
// It is returned as `userDecryption.userKeyId` in sync, which stops clients from backfilling it on
// every sync; key rotation clears it because the new user key has a new id.
const userKeyIdSchema = z.object({ userKeyId: z.string().min(1).max(200) })
accounts.post('/api/accounts/key-management/user-key-id', requireAuth, async (c) => {
  const { userKeyId } = await parseBody(c, userKeyIdSchema)
  const db = createDb(c.env.DB)
  await runBatch(db, [
    db.update(schema.users).set({ userKeyId }).where(eq(schema.users.uuid, c.var.user.uuid)),
  ])
  return c.body(null, 200)
})

accounts.post('/api/accounts/verify-password', requireAuth, async (c) => {
  const { masterPasswordHash } = await parseBody(c, passwordOnly)
  await requirePassword(c.var.user, masterPasswordHash)
  return c.body(null, 200)
})

// Password and KDF changes accept the legacy flat body (newMasterPasswordHash, key) and the
// nested body of clients 2026.9 (authenticationData, unlockData).
const credentialChange = z.object({
  masterPasswordHash: z.string().min(1),
  masterPasswordHint: z.string().max(50).nullish(),
  newMasterPasswordHash: z.string().min(1).nullish(),
  key: z.string().min(1).nullish(),
  kdf: z.number().int().nullish(),
  kdfIterations: z.number().int().nullish(),
  kdfMemory: z.number().int().nullish(),
  kdfParallelism: z.number().int().nullish(),
  authenticationData: authenticationData.nullish(),
  unlockData: unlockData.nullish(),
})

interface CredentialChange {
  newHash: string
  key: string
  /** Present when the request carries KDF settings. */
  kdf: KdfParams | null
}

function resolveChange(body: z.infer<typeof credentialChange>, email: string): CredentialChange {
  if (body.authenticationData && body.unlockData) {
    const kdf = checkNested(body.authenticationData, body.unlockData, email)
    return {
      newHash: body.authenticationData.masterPasswordAuthenticationHash,
      key: body.unlockData.masterKeyWrappedUserKey,
      kdf,
    }
  }
  if (!body.newMasterPasswordHash || !body.key) {
    throw new ApiError(400, 'The request is invalid.', {
      newMasterPasswordHash: ['newMasterPasswordHash and key are required'],
    })
  }
  const kdf =
    body.kdf != null && body.kdfIterations != null
      ? {
          kdf: body.kdf,
          kdfIterations: body.kdfIterations,
          kdfMemory: body.kdfMemory,
          kdfParallelism: body.kdfParallelism,
        }
      : null
  return { newHash: body.newMasterPasswordHash, key: body.key, kdf }
}

const kdfColumns = (k: KdfParams) => ({
  kdfType: k.kdf,
  kdfIterations: k.kdfIterations,
  kdfMemory: k.kdf === 1 ? (k.kdfMemory ?? null) : null,
  kdfParallelism: k.kdf === 1 ? (k.kdfParallelism ?? null) : null,
})

accounts.post('/api/accounts/password', requireAuth, async (c) => {
  const body = await parseBody(c, credentialChange)
  const user = c.var.user
  const change = resolveChange(body, user.email)
  // A password change must not alter the KDF (the client would derive the wrong hash).
  if (change.kdf) {
    const k = change.kdf
    const same =
      k.kdf === user.kdfType &&
      k.kdfIterations === user.kdfIterations &&
      (k.kdf !== 1 ||
        ((k.kdfMemory ?? null) === user.kdfMemory &&
          (k.kdfParallelism ?? null) === user.kdfParallelism))
    if (!same) throw new ApiError(400, 'KDF settings cannot change here; use the KDF change.')
  }
  await requirePassword(user, body.masterPasswordHash)
  const db = createDb(c.env.DB)
  await runBatch(db, [
    db
      .update(schema.users)
      .set({
        ...(await hashMasterPassword(change.newHash)),
        akey: change.key,
        passwordHint: body.masterPasswordHint ?? null,
        forcePasswordReset: false,
      })
      .where(eq(schema.users.uuid, user.uuid)),
    ...stampRotationStatements(db, user.uuid),
  ])
  c.executionCtx.waitUntil(pushLogOut(c.env, user.uuid, c.var.auth.deviceIdentifier))
  return c.body(null, 200)
})

// After an account recovery the user must replace the temporary password the administrator set
// (TASKS #240). No current password is asked: the client proved it can decrypt the vault with it.
const tempPasswordSchema = z.object({
  newMasterPasswordHash: z.string().min(1).nullish(),
  key: z.string().min(1).nullish(),
  masterPasswordHint: z.string().max(50).nullish(),
  authenticationData: authenticationData.nullish(),
  unlockData: unlockData.nullish(),
})
accounts.put('/api/accounts/update-temp-password', requireAuth, async (c) => {
  const body = await parseBody(c, tempPasswordSchema)
  const user = c.var.user
  if (!user.forcePasswordReset) {
    throw new ApiError(400, 'User does not have a temporary password to update.')
  }
  const change = resolveChange({ masterPasswordHash: '', ...body }, user.email)
  const db = createDb(c.env.DB)
  await runBatch(db, [
    db
      .update(schema.users)
      .set({
        ...(await hashMasterPassword(change.newHash)),
        akey: change.key,
        passwordHint: body.masterPasswordHint || null,
        forcePasswordReset: false,
        ...(change.kdf ? kdfColumns(change.kdf) : {}),
      })
      .where(eq(schema.users.uuid, user.uuid)),
    eventStatement(db, c, { type: EventType.UserUpdatedTempPassword, userUuid: user.uuid }),
    ...stampRotationStatements(db, user.uuid),
  ])
  c.executionCtx.waitUntil(pushLogOut(c.env, user.uuid, c.var.auth.deviceIdentifier))
  return c.body(null, 200)
})

accounts.post('/api/accounts/kdf', requireAuth, async (c) => {
  const body = await parseBody(c, credentialChange)
  const user = c.var.user
  const change = resolveChange(body, user.email)
  if (!change.kdf) throw new ApiError(400, 'KDF settings are required.')
  const problem = kdfProblem(change.kdf)
  if (problem) throw new ApiError(400, problem)
  await requirePassword(user, body.masterPasswordHash)
  const db = createDb(c.env.DB)
  await runBatch(db, [
    db
      .update(schema.users)
      .set({
        ...(await hashMasterPassword(change.newHash)),
        akey: change.key,
        ...kdfColumns(change.kdf),
      })
      .where(eq(schema.users.uuid, user.uuid)),
    ...stampRotationStatements(db, user.uuid),
  ])
  c.executionCtx.waitUntil(pushLogOut(c.env, user.uuid, c.var.auth.deviceIdentifier))
  return c.body(null, 200)
})

accounts.post('/api/accounts/security-stamp', requireAuth, async (c) => {
  const { masterPasswordHash } = await parseBody(c, passwordOnly)
  const user = c.var.user
  await requirePassword(user, masterPasswordHash)
  const db = createDb(c.env.DB)
  await runBatch(db, stampRotationStatements(db, user.uuid))
  c.executionCtx.waitUntil(pushLogOut(c.env, user.uuid, c.var.auth.deviceIdentifier))
  return c.body(null, 200)
})

const keysSchema = z.object({
  publicKey: z.string().min(1),
  encryptedPrivateKey: z.string().min(1),
})
accounts.post('/api/accounts/keys', requireAuth, async (c) => {
  const body = await parseBody(c, keysSchema)
  const user = c.var.user
  // Keys may be set once (accounts registered without them); replacing needs key rotation.
  if (user.privateKey || user.publicKey) throw new ApiError(400, 'Account keys are already set.')
  await createDb(c.env.DB)
    .update(schema.users)
    .set({ publicKey: body.publicKey, privateKey: body.encryptedPrivateKey, updatedAt: Date.now() })
    .where(eq(schema.users.uuid, user.uuid))
  return c.json({ publicKey: body.publicKey, privateKey: body.encryptedPrivateKey, object: 'keys' })
})

const apiKeyHandler = (rotate: boolean) => async (c: Ctx) => {
  const { masterPasswordHash } = await parseBody(c, passwordOnly)
  const user = c.var.user
  await requirePassword(user, masterPasswordHash)
  let apiKey = user.apiKey
  if (rotate || !apiKey) {
    apiKey = randomB64u(24).replace(/[-_]/g, 'x')
    await createDb(c.env.DB)
      .update(schema.users)
      .set({ apiKey, updatedAt: Date.now() })
      .where(eq(schema.users.uuid, user.uuid))
  }
  return c.json({ apiKey, revisionDate: new Date().toISOString(), object: 'apiKey' })
}
accounts.post('/api/accounts/api-key', requireAuth, apiKeyHandler(false))
accounts.post('/api/accounts/rotate-api-key', requireAuth, apiKeyHandler(true))

// Email change: the code is stored and emailed to the new address when a transport is bound.
const emailTokenSchema = z.object({
  newEmail: z.string().email(),
  masterPasswordHash: z.string().min(1),
})
accounts.post('/api/accounts/email-token', requireAuth, async (c) => {
  const body = await parseBody(c, emailTokenSchema)
  const user = c.var.user
  await requirePassword(user, body.masterPasswordHash)
  const db = createDb(c.env.DB)
  await assertNotClaimed(
    db,
    user,
    'Your account is claimed by an organization; its email address cannot be changed.',
  )
  const newEmail = normalizeEmail(body.newEmail)
  if (await findUserByEmail(db, newEmail)) throw new ApiError(400, 'Email is already in use.')
  const code = String((crypto.getRandomValues(new Uint32Array(1))[0] ?? 0) % 1_000_000).padStart(
    6,
    '0',
  )
  await db
    .update(schema.users)
    .set({
      emailNew: newEmail,
      emailNewToken: code,
      emailNewExpiresAt: Date.now() + EMAIL_TOKEN_TTL_MS,
    })
    .where(eq(schema.users.uuid, user.uuid))
  const transport = createEmailTransport(c.env)
  if (transport.configured) {
    await transport.send({
      to: newEmail,
      ...genericEmail('Your email change code', [
        `Your verification code is ${code}. It expires in 10 minutes.`,
        'If you did not request this change you can ignore this message.',
      ]),
    })
  }
  return c.body(null, 204)
})

const emailSchema = z.object({
  newEmail: z.string().email(),
  masterPasswordHash: z.string().min(1),
  newMasterPasswordHash: z.string().min(1),
  token: z.string().min(1),
  key: z.string().min(1),
})
accounts.post('/api/accounts/email', requireAuth, async (c) => {
  const body = await parseBody(c, emailSchema)
  const user = c.var.user
  await requirePassword(user, body.masterPasswordHash)
  const newEmail = normalizeEmail(body.newEmail)
  const valid =
    user.emailNew === newEmail &&
    user.emailNewToken !== null &&
    user.emailNewToken === body.token &&
    (user.emailNewExpiresAt ?? 0) > Date.now()
  if (!valid) throw new ApiError(400, 'Invalid token.')
  const db = createDb(c.env.DB)
  try {
    await runBatch(db, [
      db
        .update(schema.users)
        .set({
          email: newEmail,
          ...(await hashMasterPassword(body.newMasterPasswordHash)),
          akey: body.key,
          emailNew: null,
          emailNewToken: null,
          emailNewExpiresAt: null,
        })
        .where(eq(schema.users.uuid, user.uuid)),
      ...stampRotationStatements(db, user.uuid),
    ])
  } catch {
    throw new ApiError(400, 'Email is already in use.')
  }
  later(
    c,
    Promise.all([
      sendNotice(c.env, user.email, emailChangedOldEmail(newEmail)),
      sendNotice(c.env, newEmail, emailChangedNewEmail()),
    ]),
  )
  return c.body(null, 200)
})

// Key rotation: replaces the account key, private key and every re-encrypted vault item
// in one batch, so a failure leaves the vault untouched. Validation runs first.
const rotateSchema = z.object({
  masterPasswordHash: z.string().min(1),
  key: z.string().min(1),
  privateKey: z.string().min(1),
  folders: z.array(z.object({ id: z.string(), name: z.string() })).default([]),
  ciphers: z
    .array(
      z
        .object({
          id: z.string(),
          name: z.string(),
          notes: z.string().nullish(),
          key: z.string().nullish(),
          fields: z.unknown().optional(),
          passwordHistory: z.unknown().optional(),
        })
        .passthrough(),
    )
    .default([]),
  sends: z
    .array(z.object({ id: z.string(), key: z.string(), name: z.string().nullish() }))
    .default([]),
})

type RotationInput = Omit<z.infer<typeof rotateSchema>, 'masterPasswordHash'> & {
  publicKey?: string | null
  /** New master password credentials (key-management endpoint rotates them together). */
  credentials?: { hash: string; kdf: KdfParams; hint: string | null }
  /** Re-wrapped passkey keysets (key-management endpoint only). */
  passkeys?: z.infer<typeof passkeyUnlock>
  /** Re-wrapped trusted device keys (TASKS #284); trusted devices left out lose their trust. */
  devices?: z.infer<typeof deviceUnlock>
  /** Account recovery keys re-wrapped with the new user key (key-management endpoint only). */
  recovery?: { organizationId: string; resetPasswordKey: string }[]
}

/**
 * Account recovery enrolments wrap the user key, so a rotation must re-wrap each one (TASKS #240).
 * The key-management endpoint must name every enrolled organisation exactly once. The legacy
 * endpoint carries no recovery data, so enrolments are withdrawn rather than left wrapping a
 * stale key: an administrator reset with a stale key would lock the user out of their vault.
 */
async function recoveryRotation(
  db: ReturnType<typeof createDb>,
  userUuid: string,
  given: RotationInput['recovery'],
) {
  const uo = schema.usersOrganizations
  const enrolled = await db
    .select({ uuid: uo.uuid, orgUuid: uo.organizationUuid })
    .from(uo)
    .where(and(eq(uo.userUuid, userUuid), isNotNull(uo.resetPasswordKey)))
  const now = Date.now()
  if (given === undefined) {
    return enrolled.map((m) =>
      db.update(uo).set({ resetPasswordKey: null, updatedAt: now }).where(eq(uo.uuid, m.uuid)),
    )
  }
  const byOrg = new Map(given.map((g) => [g.organizationId, g.resetPasswordKey]))
  if (
    byOrg.size !== given.length ||
    byOrg.size !== enrolled.length ||
    enrolled.some((m) => !byOrg.has(m.orgUuid))
  ) {
    throw new ApiError(400, 'Rotation must include every account recovery enrolment exactly once.')
  }
  return enrolled.map((m) =>
    db
      .update(uo)
      .set({ resetPasswordKey: byOrg.get(m.orgUuid) as string, updatedAt: now })
      .where(and(eq(uo.uuid, m.uuid), isNotNull(uo.resetPasswordKey))),
  )
}

/**
 * Passkey keysets wrap the user key, so a rotation must re-wrap each one. The client sends the
 * new wrapped user and public keys per credential; a credential with a keyset that is missing
 * from the request cannot unlock the new key and loses its keyset (it stays usable as a login
 * credential and can enable encryption again).
 */
export async function passkeyRotation(
  db: ReturnType<typeof createDb>,
  userUuid: string,
  given: z.infer<typeof passkeyUnlock> | undefined,
) {
  // Callers that do not carry passkey data (the legacy rotation) cannot re-wrap anything, so
  // every keyset is dropped rather than left wrapping the old user key.
  const items = given ?? []
  const table = schema.webauthnCredentials
  const owned = await db.select().from(table).where(eq(table.userUuid, userUuid))
  const byId = new Map(owned.map((r) => [r.uuid, r]))
  const seen = new Set<string>()
  for (const g of items) {
    if (!byId.get(g.id)?.encryptedUserKey || seen.has(g.id)) {
      throw new ApiError(400, 'Rotation names a passkey that has no keyset.')
    }
    seen.add(g.id)
  }
  const now = Date.now()
  const none = {
    encryptedUserKey: null,
    encryptedPublicKey: null,
    encryptedPrivateKey: null,
    updatedAt: now,
  }
  const mine = eq(table.userUuid, userUuid)
  return [
    // Re-wrap, guarded by the row version read above: a concurrent keyset update changes
    // `updated_at`, so this misses it and the next statement removes the old-key wrap.
    ...items.map((g) =>
      db
        .update(table)
        .set({
          encryptedUserKey: g.encryptedUserKey,
          encryptedPublicKey: g.encryptedPublicKey,
          updatedAt: now,
        })
        .where(
          and(
            mine,
            eq(table.uuid, g.id),
            eq(table.updatedAt, (byId.get(g.id) as (typeof owned)[0]).updatedAt),
          ),
        ),
    ),
    ...items.map((g) =>
      db
        .update(table)
        .set(none)
        .where(
          and(
            mine,
            eq(table.uuid, g.id),
            or(isNull(table.encryptedUserKey), ne(table.encryptedUserKey, g.encryptedUserKey)),
          ),
        ),
    ),
    // Everything not re-wrapped, including keysets stored after the read above, is cleared.
    db
      .update(table)
      .set(none)
      .where(
        and(
          mine,
          isNotNull(table.encryptedUserKey),
          ...(items.length
            ? [
                notInArray(
                  table.uuid,
                  items.map((g) => g.id),
                ),
              ]
            : []),
        ),
      ),
  ]
}

async function applyRotation(c: Ctx, user: User, body: RotationInput) {
  const db = createDb(c.env.DB)

  const owned = async (
    table: typeof schema.folders | typeof schema.ciphers | typeof schema.sends,
  ) =>
    new Set(
      (await db.select({ id: table.uuid }).from(table).where(eq(table.userUuid, user.uuid))).map(
        (r) => r.id,
      ),
    )
  const [folderIds, cipherIds, sendIds] = await Promise.all([
    owned(schema.folders),
    owned(schema.ciphers),
    owned(schema.sends),
  ])
  const storedTypes = new Map(
    (
      await db
        .select({ id: schema.ciphers.uuid, type: schema.ciphers.atype })
        .from(schema.ciphers)
        .where(eq(schema.ciphers.userUuid, user.uuid))
    ).map((r) => [r.id, r.type]),
  )
  const same = (given: { id: string }[], have: Set<string>) =>
    given.length === have.size &&
    given.every((g) => have.has(g.id)) &&
    new Set(given.map((g) => g.id)).size === have.size
  if (
    !same(body.folders, folderIds) ||
    !same(body.ciphers, cipherIds) ||
    !same(body.sends, sendIds)
  ) {
    throw new ApiError(400, 'Rotation must include every folder, cipher and send exactly once.')
  }

  // The stored type decides which payload is kept; a mismatching type would drop data.
  if (body.ciphers.some((ci) => ci.type !== undefined && ci.type !== storedTypes.get(ci.id))) {
    throw new ApiError(400, 'Cipher type cannot change during key rotation.')
  }

  const passkeyStatements = await passkeyRotation(db, user.uuid, body.passkeys)
  const deviceStatements = await deviceTrustRotation(db, user.uuid, body.devices ?? [])
  const recoveryStatements = await recoveryRotation(db, user.uuid, body.recovery)

  const now = Date.now()
  await runBatch(db, [
    ...passkeyStatements,
    ...deviceStatements,
    ...recoveryStatements,
    db
      .update(schema.users)
      .set({
        akey: body.key,
        userKeyId: null,
        privateKey: body.privateKey,
        ...(body.publicKey ? { publicKey: body.publicKey } : {}),
        ...(body.credentials
          ? {
              ...(await hashMasterPassword(body.credentials.hash)),
              ...kdfColumns(body.credentials.kdf),
              passwordHint: body.credentials.hint,
            }
          : {}),
        updatedAt: now,
      })
      .where(eq(schema.users.uuid, user.uuid)),
    ...body.folders.map((f) =>
      db
        .update(schema.folders)
        .set({ name: f.name, updatedAt: now })
        .where(eq(schema.folders.uuid, f.id)),
    ),
    ...body.ciphers.map((ci) => {
      const data = packPayload(ci, storedTypes.get(ci.id))
      return db
        .update(schema.ciphers)
        .set({
          name: ci.name,
          notes: ci.notes ?? null,
          key: ci.key ?? null,
          fields: ci.fields == null ? null : JSON.stringify(ci.fields),
          passwordHistory: ci.passwordHistory == null ? null : JSON.stringify(ci.passwordHistory),
          data,
          updatedAt: now,
        })
        .where(eq(schema.ciphers.uuid, ci.id))
    }),
    ...body.sends.map((s) =>
      db
        .update(schema.sends)
        .set({ akey: s.key, ...(s.name ? { name: s.name } : {}), updatedAt: now })
        .where(eq(schema.sends.uuid, s.id)),
    ),
    ...stampRotationStatements(db, user.uuid),
  ])
  c.executionCtx.waitUntil(pushLogOut(c.env, user.uuid, c.var.auth.deviceIdentifier))
  return c.body(null, 200)
}

accounts.post('/api/accounts/key', requireAuth, async (c) => {
  const { masterPasswordHash, ...rest } = await parseBody(c, rotateSchema)
  await requirePassword(c.var.user, masterPasswordHash)
  await applyRotation(c, c.var.user, rest)
  return c.body(null, 200)
})

const deviceUnlock = z.array(
  z.object({
    deviceId: z.string().min(1),
    encryptedPublicKey: z.string().min(1),
    encryptedUserKey: z.string().min(1),
  }),
)

/**
 * Trusted devices hold the user key wrapped for them; after a rotation those wrappings are stale.
 * Devices the client re-wrapped get the new values, every other trusted device is untrusted.
 */
async function deviceTrustRotation(
  db: ReturnType<typeof createDb>,
  userUuid: string,
  given: z.infer<typeof deviceUnlock>,
) {
  const rows = await db
    .select({ uuid: schema.devices.uuid, key: schema.devices.encryptedUserKey })
    .from(schema.devices)
    .where(eq(schema.devices.userUuid, userUuid))
  const byId = new Map(given.map((g) => [g.deviceId, g]))
  return rows
    .filter((r) => r.key !== null)
    .map((r) => {
      const g = byId.get(r.uuid)
      return db
        .update(schema.devices)
        .set(
          g
            ? { encryptedPublicKey: g.encryptedPublicKey, encryptedUserKey: g.encryptedUserKey }
            : { encryptedPublicKey: null, encryptedUserKey: null, encryptedPrivateKey: null },
        )
        .where(eq(schema.devices.uuid, r.uuid))
    })
}

// Rotation as sent by clients 2026.9 (web vault).
const passkeyUnlock = z.array(
  z.object({
    id: z.string(),
    encryptedPublicKey: z.string().min(1),
    encryptedUserKey: z.string().min(1),
  }),
)
const rotateAccountKeys = z.object({
  oldMasterKeyAuthenticationHash: z.string().min(1),
  accountUnlockData: z.object({
    masterPasswordUnlockData: z.object({
      kdfType: z.number().int(),
      kdfIterations: z.number().int(),
      kdfMemory: z.number().int().nullish(),
      kdfParallelism: z.number().int().nullish(),
      email: z.string(),
      masterKeyAuthenticationHash: z.string().min(1),
      masterKeyEncryptedUserKey: z.string().min(1),
      masterPasswordHint: z.string().max(50).nullish(),
    }),
    passkeyUnlockData: passkeyUnlock.default([]),
    deviceKeyUnlockData: deviceUnlock.nullish(),
    organizationAccountRecoveryUnlockData: z
      .array(
        z.object({
          organizationId: z.string().min(1),
          resetPasswordKey: z.string().min(1).max(10_000),
        }),
      )
      .nullish()
      .transform((v) => v ?? []),
  }),
  accountKeys: z.object({
    userKeyEncryptedAccountPrivateKey: z.string().min(1),
    accountPublicKey: z.string().nullish(),
  }),
  accountData: z.object({
    ciphers: rotateSchema.shape.ciphers,
    folders: rotateSchema.shape.folders,
    sends: rotateSchema.shape.sends,
  }),
})
accounts.post('/api/accounts/key-management/rotate-user-account-keys', requireAuth, async (c) => {
  const body = await parseBody(c, rotateAccountKeys)
  const user = c.var.user
  const m = body.accountUnlockData.masterPasswordUnlockData
  if (m.email.trim().toLowerCase() !== user.email) {
    throw new ApiError(400, 'The salt must match the account email.')
  }
  const kdf = toKdfParams({
    kdfType: m.kdfType,
    iterations: m.kdfIterations,
    memory: m.kdfMemory,
    parallelism: m.kdfParallelism,
  })
  const problem = kdfProblem(kdf)
  if (problem) throw new ApiError(400, problem)
  const newPublic = body.accountKeys.accountPublicKey
  if (newPublic && user.publicKey && newPublic !== user.publicKey) {
    throw new ApiError(400, 'The account public key cannot change during key rotation.')
  }
  await requirePassword(user, body.oldMasterKeyAuthenticationHash)
  await applyRotation(c, user, {
    key: m.masterKeyEncryptedUserKey,
    privateKey: body.accountKeys.userKeyEncryptedAccountPrivateKey,
    publicKey: body.accountKeys.accountPublicKey,
    ...body.accountData,
    passkeys: body.accountUnlockData.passkeyUnlockData,
    devices: body.accountUnlockData.deviceKeyUnlockData ?? [],
    recovery: body.accountUnlockData.organizationAccountRecoveryUnlockData,
    credentials: {
      hash: m.masterKeyAuthenticationHash,
      kdf,
      hint: m.masterPasswordHint === undefined ? user.passwordHint : m.masterPasswordHint,
    },
  })
  return c.body(null, 200)
})

/** Deletes the account and everything it owns; blobs are removed after the response. */
export async function eraseAccount(c: Ctx, user: User) {
  const db = createDb(c.env.DB)
  await assertNotClaimed(
    db,
    user,
    'Your account is claimed by an organization and cannot be deleted. Contact your administrator.',
  )
  await assertNotSoleOwner(db, user.uuid)
  // Child rows (devices, folders, ciphers, sends, 2FA) cascade from the user row.
  const keys = [
    ...(await userAttachmentKeys(db, user.uuid)),
    ...(await userSendKeys(db, user.uuid)),
  ]
  const mobile = await db
    .select()
    .from(schema.devices)
    .where(and(eq(schema.devices.userUuid, user.uuid), isNotNull(schema.devices.pushToken)))
  await runBatch(db, [db.delete(schema.users).where(eq(schema.users.uuid, user.uuid))])
  // Best effort: stop the relay pushing to phones of a deleted account.
  later(c, Promise.all(mobile.map((d) => relayDeleteDevice(c.env, { ...d, userUuid: user.uuid }))))
  deleteBlobs(c, keys)
}

const deleteAccount = async (c: Ctx) => {
  const { masterPasswordHash } = await parseBody(c, passwordOnly)
  await requirePassword(c.var.user, masterPasswordHash)
  await eraseAccount(c, c.var.user)
  return c.body(null, 200)
}
accounts.delete('/api/accounts', requireAuth, deleteAccount)
accounts.post('/api/accounts/delete', requireAuth, deleteAccount)
