import { and, eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { randomB64u } from '../auth/crypto'
import { requireAuth } from '../auth/middleware'
import { hashMasterPassword, verifyMasterPassword } from '../auth/passwords'
import { stampRotationStatements } from '../auth/session'
import { findUserByEmail, normalizeEmail } from '../auth/users'
import { createDb, runBatch, schema } from '../db'
import { createEmailTransport, genericEmail } from '../email'
import type { Env, User } from '../env'
import { ApiError } from '../errors'
import { kdfProblem, parseBody } from '../validation'

export const accounts = new Hono<Env>()

type Ctx = import('hono').Context<Env>

const EMAIL_TOKEN_TTL_MS = 10 * 60 * 1000

async function profileJson(c: Ctx, user: User) {
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
    key: user.akey,
    privateKey: user.privateKey,
    securityStamp: user.securityStamp,
    forcePasswordReset: false,
    usesKeyConnector: false,
    avatarColor: null,
    organizations: [],
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

// TODO(TASKS #43): fold vault revision dates in once Phase 2 lands.
accounts.get('/api/accounts/revision-date', requireAuth, (c) => c.json(c.var.user.updatedAt))

accounts.post('/api/accounts/verify-password', requireAuth, async (c) => {
  const { masterPasswordHash } = await parseBody(c, passwordOnly)
  await requirePassword(c.var.user, masterPasswordHash)
  return c.body(null, 200)
})

const passwordSchema = z.object({
  masterPasswordHash: z.string().min(1),
  newMasterPasswordHash: z.string().min(1),
  masterPasswordHint: z.string().max(50).nullish(),
  key: z.string().min(1),
})
accounts.post('/api/accounts/password', requireAuth, async (c) => {
  const body = await parseBody(c, passwordSchema)
  const user = c.var.user
  await requirePassword(user, body.masterPasswordHash)
  const db = createDb(c.env.DB)
  await runBatch(db, [
    db
      .update(schema.users)
      .set({
        ...(await hashMasterPassword(body.newMasterPasswordHash)),
        akey: body.key,
        passwordHint: body.masterPasswordHint ?? null,
      })
      .where(eq(schema.users.uuid, user.uuid)),
    ...stampRotationStatements(db, user.uuid),
  ])
  return c.body(null, 200)
})

const kdfSchema = z.object({
  masterPasswordHash: z.string().min(1),
  newMasterPasswordHash: z.string().min(1),
  key: z.string().min(1),
  kdf: z.number().int(),
  kdfIterations: z.number().int(),
  kdfMemory: z.number().int().nullish(),
  kdfParallelism: z.number().int().nullish(),
})
accounts.post('/api/accounts/kdf', requireAuth, async (c) => {
  const body = await parseBody(c, kdfSchema)
  const user = c.var.user
  const problem = kdfProblem(body)
  if (problem) throw new ApiError(400, problem)
  await requirePassword(user, body.masterPasswordHash)
  const db = createDb(c.env.DB)
  const argon = body.kdf === 1
  await runBatch(db, [
    db
      .update(schema.users)
      .set({
        ...(await hashMasterPassword(body.newMasterPasswordHash)),
        akey: body.key,
        kdfType: body.kdf,
        kdfIterations: body.kdfIterations,
        kdfMemory: argon ? (body.kdfMemory ?? null) : null,
        kdfParallelism: argon ? (body.kdfParallelism ?? null) : null,
      })
      .where(eq(schema.users.uuid, user.uuid)),
    ...stampRotationStatements(db, user.uuid),
  ])
  return c.body(null, 200)
})

accounts.post('/api/accounts/security-stamp', requireAuth, async (c) => {
  const { masterPasswordHash } = await parseBody(c, passwordOnly)
  const user = c.var.user
  await requirePassword(user, masterPasswordHash)
  const db = createDb(c.env.DB)
  await runBatch(db, stampRotationStatements(db, user.uuid))
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
const CIPHER_TYPE_KEYS = ['login', 'card', 'identity', 'secureNote', 'sshKey'] as const

accounts.post('/api/accounts/key', requireAuth, async (c) => {
  const body = await parseBody(c, rotateSchema)
  const user = c.var.user
  await requirePassword(user, body.masterPasswordHash)
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

  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.users)
      .set({ akey: body.key, privateKey: body.privateKey, updatedAt: now })
      .where(eq(schema.users.uuid, user.uuid)),
    ...body.folders.map((f) =>
      db
        .update(schema.folders)
        .set({ name: f.name, updatedAt: now })
        .where(eq(schema.folders.uuid, f.id)),
    ),
    ...body.ciphers.map((ci) => {
      // TODO(TASKS #41): the stored `data` layout is owned by the ciphers module.
      const data = Object.fromEntries(
        CIPHER_TYPE_KEYS.filter((k) => ci[k] !== undefined).map((k) => [k, ci[k]]),
      )
      return db
        .update(schema.ciphers)
        .set({
          name: ci.name,
          notes: ci.notes ?? null,
          key: ci.key ?? null,
          fields: ci.fields == null ? null : JSON.stringify(ci.fields),
          passwordHistory: ci.passwordHistory == null ? null : JSON.stringify(ci.passwordHistory),
          data: JSON.stringify(data),
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
  return c.body(null, 200)
})

const deleteAccount = async (c: Ctx) => {
  const { masterPasswordHash } = await parseBody(c, passwordOnly)
  const user = c.var.user
  await requirePassword(user, masterPasswordHash)
  const db = createDb(c.env.DB)
  // Child rows (devices, folders, ciphers, sends, 2FA) cascade from the user row.
  // TODO(TASKS #80): also delete the user's attachment and Send blobs from R2.
  await runBatch(db, [db.delete(schema.users).where(eq(schema.users.uuid, user.uuid))])
  return c.body(null, 200)
}
accounts.delete('/api/accounts', requireAuth, deleteAccount)
accounts.post('/api/accounts/delete', requireAuth, deleteAccount)
