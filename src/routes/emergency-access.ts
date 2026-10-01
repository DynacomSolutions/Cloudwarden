import { and, eq, inArray } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { hashMasterPassword } from '../auth/passwords'
import { signPurposeToken, verifyPurposeToken } from '../auth/purpose-token'
import { stampRotationStatements } from '../auth/session'
import { normalizeEmail } from '../auth/users'
import { createDb, type Db, schema } from '../db'
import { createEmailTransport, emergencyInviteEmail, genericEmail } from '../email'
import type { Env, User } from '../env'
import { ApiError } from '../errors'
import { PolicyType } from '../orgs/constants'
import { listUserPolicies, policyJson } from '../orgs/policies'
import { authOnce, batch } from '../orgs/util'
import { parseBody } from '../validation'
import { bumpRevision, cipherJson, listCipherRows } from '../vault/ciphers'

export const emergencyAccess = new Hono<Env>()
emergencyAccess.use('/api/emergency-access/*', authOnce)
emergencyAccess.use('/api/users/*', authOnce)

type Ctx = Context<Env>
type Row = typeof schema.emergencyAccess.$inferSelect

export const EmergencyType = { View: 0, Takeover: 1 } as const
export const EmergencyStatus = {
  Invited: 0,
  Accepted: 1,
  Confirmed: 2,
  RecoveryInitiated: 3,
  RecoveryApproved: 4,
} as const

const DAY_MS = 24 * 3600 * 1000
const TOKEN_PURPOSE = 'emergencyaccess'
const TOKEN_TTL_SECONDS = 5 * 24 * 3600

/** Recovery completes by itself once the wait time has passed without a rejection. */
export function effectiveStatus(row: Row, now = Date.now()): number {
  if (
    row.status === EmergencyStatus.RecoveryInitiated &&
    row.recoveryInitiatedAt !== null &&
    now >= row.recoveryInitiatedAt + row.waitTimeDays * DAY_MS
  ) {
    return EmergencyStatus.RecoveryApproved
  }
  return row.status
}

const list = (data: unknown[]) => ({ object: 'list', data, continuationToken: null })
const idParam = (c: Ctx) => c.req.param('id') ?? ''
const iso = (ms: number) => new Date(ms).toISOString()

async function loadRow(db: Db, id: string): Promise<Row> {
  const [row] = await db
    .select()
    .from(schema.emergencyAccess)
    .where(eq(schema.emergencyAccess.uuid, id))
    .limit(1)
  if (!row) throw new ApiError(404, 'Emergency access not found.')
  return row
}

async function asGrantor(c: Ctx): Promise<{ db: Db; row: Row }> {
  const db = createDb(c.env.DB)
  const row = await loadRow(db, idParam(c))
  if (row.grantorUuid !== c.var.user.uuid) throw new ApiError(404, 'Emergency access not found.')
  return { db, row }
}

async function asGrantee(c: Ctx): Promise<{ db: Db; row: Row }> {
  const db = createDb(c.env.DB)
  const row = await loadRow(db, idParam(c))
  if (row.granteeUuid !== c.var.user.uuid) throw new ApiError(404, 'Emergency access not found.')
  return { db, row }
}

async function userByUuid(db: Db, uuid: string): Promise<User | undefined> {
  const [u] = await db.select().from(schema.users).where(eq(schema.users.uuid, uuid)).limit(1)
  return u
}

async function usersByUuid(db: Db, uuids: string[]): Promise<Map<string, User>> {
  const out = new Map<string, User>()
  if (uuids.length === 0) return out
  for (const u of await db.select().from(schema.users).where(inArray(schema.users.uuid, uuids))) {
    out.set(u.uuid, u)
  }
  return out
}

// ----- listings -----

emergencyAccess.get('/api/emergency-access/trusted', async (c) => {
  const db = createDb(c.env.DB)
  const rows = await db
    .select()
    .from(schema.emergencyAccess)
    .where(eq(schema.emergencyAccess.grantorUuid, c.var.user.uuid))
  const users = await usersByUuid(
    db,
    rows.flatMap((r) => (r.granteeUuid ? [r.granteeUuid] : [])),
  )
  const now = Date.now()
  return c.json(
    list(
      rows.map((r) => ({
        object: 'emergencyAccessGranteeDetails',
        id: r.uuid,
        granteeId: r.granteeUuid,
        name: (r.granteeUuid && users.get(r.granteeUuid)?.name) || null,
        email: r.email,
        type: r.atype,
        status: effectiveStatus(r, now),
        waitTimeDays: r.waitTimeDays,
        creationDate: iso(r.createdAt),
        avatarColor: null,
      })),
    ),
  )
})

emergencyAccess.get('/api/emergency-access/granted', async (c) => {
  const db = createDb(c.env.DB)
  const rows = await db
    .select()
    .from(schema.emergencyAccess)
    .where(eq(schema.emergencyAccess.granteeUuid, c.var.user.uuid))
  const users = await usersByUuid(
    db,
    rows.map((r) => r.grantorUuid),
  )
  const now = Date.now()
  return c.json(
    list(
      rows.map((r) => ({
        object: 'emergencyAccessGrantorDetails',
        id: r.uuid,
        grantorId: r.grantorUuid,
        name: users.get(r.grantorUuid)?.name ?? null,
        email: users.get(r.grantorUuid)?.email ?? null,
        type: r.atype,
        status: effectiveStatus(r, now),
        waitTimeDays: r.waitTimeDays,
        creationDate: iso(r.createdAt),
        avatarColor: null,
      })),
    ),
  )
})

// ----- invitation -----

const inviteSchema = z.object({
  email: z.string().min(3).max(256),
  type: z.number().int().min(0).max(1),
  waitTimeDays: z.number().int().min(1).max(90),
})

async function sendInvite(c: Ctx, row: Row) {
  const transport = createEmailTransport(c.env)
  if (!transport.configured) return
  const token = await signPurposeToken(
    c.env,
    TOKEN_PURPOSE,
    { sub: row.uuid, email: row.email },
    TOKEN_TTL_SECONDS,
  )
  const q = new URLSearchParams({
    id: row.uuid,
    name: c.var.user.name,
    email: row.email,
    token,
  })
  const url = `${c.env.DOMAIN.replace(/\/+$/, '')}/#/accept-emergency?${q.toString()}`
  try {
    await transport.send({
      to: row.email,
      ...emergencyInviteEmail(c.var.user.name || c.var.user.email, url),
    })
  } catch {
    // The invitation is stored and can be resent. Message content is never logged.
  }
}

emergencyAccess.post('/api/emergency-access/invite', async (c) => {
  const body = await parseBody(c, inviteSchema)
  const db = createDb(c.env.DB)
  const user = c.var.user
  const email = normalizeEmail(body.email)
  if (!email.includes('@')) throw new ApiError(400, 'Invalid email address.')
  if (email === user.email)
    throw new ApiError(400, 'You cannot grant emergency access to yourself.')
  const [dup] = await db
    .select({ id: schema.emergencyAccess.uuid })
    .from(schema.emergencyAccess)
    .where(
      and(
        eq(schema.emergencyAccess.grantorUuid, user.uuid),
        eq(schema.emergencyAccess.email, email),
      ),
    )
    .limit(1)
  if (dup) throw new ApiError(400, 'This person is already an emergency contact.')
  const [account] = await db
    .select({ uuid: schema.users.uuid })
    .from(schema.users)
    .where(eq(schema.users.email, email))
    .limit(1)
  const now = Date.now()
  const row: Row = {
    uuid: crypto.randomUUID(),
    grantorUuid: user.uuid,
    granteeUuid: null,
    email,
    keyEncrypted: null,
    atype: body.type,
    status: EmergencyStatus.Invited,
    waitTimeDays: body.waitTimeDays,
    recoveryInitiatedAt: null,
    createdAt: now,
    updatedAt: now,
  }
  await batch(db, [
    db.insert(schema.emergencyAccess).values(row),
    ...(account
      ? []
      : [
          db
            .insert(schema.invitations)
            .values({ uuid: crypto.randomUUID(), email, invitedBy: user.uuid, createdAt: now })
            .onConflictDoNothing(),
        ]),
  ])
  await sendInvite(c, row)
  return c.body(null, 200)
})

emergencyAccess.post('/api/emergency-access/:id/reinvite', async (c) => {
  const { row } = await asGrantor(c)
  if (row.status !== EmergencyStatus.Invited)
    throw new ApiError(400, 'Invitation was already accepted.')
  await sendInvite(c, row)
  return c.body(null, 200)
})

emergencyAccess.post('/api/emergency-access/:id/accept', async (c) => {
  const { token } = await parseBody(c, z.object({ token: z.string().min(1) }))
  const db = createDb(c.env.DB)
  const user = c.var.user
  const row = await loadRow(db, idParam(c))
  const claims = await verifyPurposeToken(c.env, TOKEN_PURPOSE, token)
  if (
    !claims ||
    claims.sub !== row.uuid ||
    claims.email !== user.email ||
    row.email !== user.email
  ) {
    throw new ApiError(400, 'Invalid token.')
  }
  if (row.status !== EmergencyStatus.Invited)
    throw new ApiError(400, 'Invitation was already accepted.')
  await batch(db, [
    db
      .update(schema.emergencyAccess)
      .set({ granteeUuid: user.uuid, status: EmergencyStatus.Accepted, updatedAt: Date.now() })
      .where(eq(schema.emergencyAccess.uuid, row.uuid)),
  ])
  return c.body(null, 200)
})

emergencyAccess.post('/api/emergency-access/:id/confirm', async (c) => {
  const { key } = await parseBody(c, z.object({ key: z.string().min(1) }))
  const { db, row } = await asGrantor(c)
  if (row.status !== EmergencyStatus.Accepted || !row.granteeUuid) {
    throw new ApiError(400, 'The contact has not accepted the invitation.')
  }
  await batch(db, [
    db
      .update(schema.emergencyAccess)
      .set({ status: EmergencyStatus.Confirmed, keyEncrypted: key, updatedAt: Date.now() })
      .where(eq(schema.emergencyAccess.uuid, row.uuid)),
  ])
  return c.body(null, 200)
})

// ----- single record -----

emergencyAccess.get('/api/emergency-access/:id/policies', async (c) => {
  const { db, row } = await asGrantee(c)
  if (effectiveStatus(row) !== EmergencyStatus.RecoveryApproved) {
    throw new ApiError(400, 'Emergency access is not approved.')
  }
  const rows = (await listUserPolicies(db, row.grantorUuid)).filter(
    (p) => p.atype === PolicyType.MasterPassword,
  )
  return c.json(list(rows.map(policyJson)))
})

emergencyAccess.get('/api/emergency-access/:id', async (c) => {
  const db = createDb(c.env.DB)
  const row = await loadRow(db, idParam(c))
  if (row.grantorUuid !== c.var.user.uuid && row.granteeUuid !== c.var.user.uuid) {
    throw new ApiError(404, 'Emergency access not found.')
  }
  return c.json({
    object: 'emergencyAccess',
    id: row.uuid,
    status: effectiveStatus(row),
    type: row.atype,
    waitTimeDays: row.waitTimeDays,
  })
})

const updateSchema = z.object({
  type: z.number().int().min(0).max(1),
  waitTimeDays: z.number().int().min(1).max(90),
  keyEncrypted: z.string().nullish(),
})
const updateAccess = async (c: Ctx) => {
  const body = await parseBody(c, updateSchema)
  const { db, row } = await asGrantor(c)
  await batch(db, [
    db
      .update(schema.emergencyAccess)
      .set({
        atype: body.type,
        waitTimeDays: body.waitTimeDays,
        keyEncrypted: body.keyEncrypted ?? row.keyEncrypted,
        updatedAt: Date.now(),
      })
      .where(eq(schema.emergencyAccess.uuid, row.uuid)),
  ])
  return c.body(null, 200)
}
emergencyAccess.put('/api/emergency-access/:id', updateAccess)
emergencyAccess.post('/api/emergency-access/:id', updateAccess)

const deleteAccess = async (c: Ctx) => {
  const db = createDb(c.env.DB)
  const row = await loadRow(db, idParam(c))
  const uuid = c.var.user.uuid
  if (row.grantorUuid !== uuid && row.granteeUuid !== uuid) {
    throw new ApiError(404, 'Emergency access not found.')
  }
  await batch(db, [
    db.delete(schema.emergencyAccess).where(eq(schema.emergencyAccess.uuid, row.uuid)),
  ])
  return c.body(null, 200)
}
emergencyAccess.delete('/api/emergency-access/:id', deleteAccess)
emergencyAccess.post('/api/emergency-access/:id/delete', deleteAccess)

// ----- recovery -----

emergencyAccess.post('/api/emergency-access/:id/initiate', async (c) => {
  const { db, row } = await asGrantee(c)
  if (row.status !== EmergencyStatus.Confirmed) {
    throw new ApiError(400, 'Emergency access is not confirmed.')
  }
  const now = Date.now()
  await batch(db, [
    db
      .update(schema.emergencyAccess)
      .set({ status: EmergencyStatus.RecoveryInitiated, recoveryInitiatedAt: now, updatedAt: now })
      .where(eq(schema.emergencyAccess.uuid, row.uuid)),
  ])
  const grantor = await userByUuid(db, row.grantorUuid)
  const transport = createEmailTransport(c.env)
  if (grantor && transport.configured) {
    try {
      await transport.send({
        to: grantor.email,
        ...genericEmail('Emergency access requested', [
          `An emergency contact has asked for access to your vault. Access is granted automatically in ${row.waitTimeDays} days unless you reject the request.`,
        ]),
      })
    } catch {
      // Notification is best effort.
    }
  }
  return c.body(null, 200)
})

emergencyAccess.post('/api/emergency-access/:id/approve', async (c) => {
  const { db, row } = await asGrantor(c)
  if (row.status !== EmergencyStatus.RecoveryInitiated) {
    throw new ApiError(400, 'No recovery request is pending.')
  }
  await batch(db, [
    db
      .update(schema.emergencyAccess)
      .set({ status: EmergencyStatus.RecoveryApproved, updatedAt: Date.now() })
      .where(eq(schema.emergencyAccess.uuid, row.uuid)),
  ])
  return c.body(null, 200)
})

emergencyAccess.post('/api/emergency-access/:id/reject', async (c) => {
  const { db, row } = await asGrantor(c)
  const status = effectiveStatus(row)
  if (status !== EmergencyStatus.RecoveryInitiated && status !== EmergencyStatus.RecoveryApproved) {
    throw new ApiError(400, 'No recovery request is pending.')
  }
  await batch(db, [
    db
      .update(schema.emergencyAccess)
      .set({ status: EmergencyStatus.Confirmed, recoveryInitiatedAt: null, updatedAt: Date.now() })
      .where(eq(schema.emergencyAccess.uuid, row.uuid)),
  ])
  return c.body(null, 200)
})

/** The grantee's row once recovery is approved (by the grantor or by the wait time elapsing). */
async function approvedFor(c: Ctx, type: number) {
  const { db, row } = await asGrantee(c)
  if (effectiveStatus(row) !== EmergencyStatus.RecoveryApproved || row.atype !== type) {
    throw new ApiError(400, 'Emergency access is not available.')
  }
  const grantor = await userByUuid(db, row.grantorUuid)
  if (!grantor) throw new ApiError(404, 'Emergency access not found.')
  return { db, row, grantor }
}

emergencyAccess.post('/api/emergency-access/:id/view', async (c) => {
  const { db, row, grantor } = await approvedFor(c, EmergencyType.View)
  const items = await listCipherRows(db, grantor.uuid)
  return c.json({
    object: 'emergencyAccessView',
    keyEncrypted: row.keyEncrypted,
    ciphers: items.map(cipherJson),
  })
})

emergencyAccess.post('/api/emergency-access/:id/takeover', async (c) => {
  const { row, grantor } = await approvedFor(c, EmergencyType.Takeover)
  return c.json({
    object: 'emergencyAccessTakeover',
    keyEncrypted: row.keyEncrypted,
    kdf: grantor.kdfType,
    kdfIterations: grantor.kdfIterations,
    kdfMemory: grantor.kdfMemory,
    kdfParallelism: grantor.kdfParallelism,
  })
})

emergencyAccess.post('/api/emergency-access/:id/password', async (c) => {
  const body = await parseBody(
    c,
    z.object({ newMasterPasswordHash: z.string().min(1), key: z.string().min(1) }),
  )
  const { db, grantor } = await approvedFor(c, EmergencyType.Takeover)
  await batch(db, [
    db
      .update(schema.users)
      .set({ ...(await hashMasterPassword(body.newMasterPasswordHash)), akey: body.key })
      .where(eq(schema.users.uuid, grantor.uuid)),
    // A takeover also clears the grantor's two-step login so they can sign in with the new password.
    db.delete(schema.twofactor).where(eq(schema.twofactor.userUuid, grantor.uuid)),
    ...stampRotationStatements(db, grantor.uuid),
    bumpRevision(db, grantor.uuid, Date.now()),
  ])
  return c.body(null, 200)
})

// ----- user keys, used to encrypt the confirmation key -----

emergencyAccess.get('/api/users/:id/public-key', async (c) => {
  const u = await userByUuid(createDb(c.env.DB), c.req.param('id'))
  if (!u?.publicKey) throw new ApiError(404, 'User not found.')
  return c.json({ userId: u.uuid, publicKey: u.publicKey, object: 'userKey' })
})

emergencyAccess.get('/api/users/:id/keys', async (c) => {
  const id = c.req.param('id')
  const u = await userByUuid(createDb(c.env.DB), id)
  if (!u?.publicKey) throw new ApiError(404, 'User not found.')
  return c.json({
    object: 'keys',
    publicKey: u.publicKey,
    privateKey: id === c.var.user.uuid ? u.privateKey : null,
  })
})
