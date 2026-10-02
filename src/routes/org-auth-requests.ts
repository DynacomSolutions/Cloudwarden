import { and, desc, eq, inArray, isNotNull, isNull } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { PushType, pushAuthRequestResponse, pushUserUpdate } from '../notifications/publish'
import type { Member } from '../orgs/access'
import { requireOrg } from '../orgs/access'
import { EventType, Status } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { defer } from '../orgs/notify'
import {
  assertCanRecover,
  assertOrgKeys,
  assertPolicyEnabled,
  requireRecoveryAdmin,
  unrecoverableMembers,
} from '../orgs/recovery'
import { authOnce, batch } from '../orgs/util'
import { parseBody } from '../validation'
import {
  ADMIN_AUTH_REQUEST_TTL_MS,
  AuthRequestType,
  deviceTypeName,
  isExpired,
} from './auth-requests'

/**
 * Device approvals (TASKS #241): administrators with `manageResetPassword` list and answer the
 * admin approval requests (type 2) of members enrolled in account recovery. Approving means the
 * administrator's client unwrapped the member's recovery key with the organisation private key
 * and re-encrypted the user key to the requesting device's public key; the server only relays
 * that ciphertext. Only requests the caller could also recover are listed or answerable.
 */
export const orgAuthRequests = new Hono<Env>()
orgAuthRequests.use('/api/organizations/*', authOnce)

type Ctx = Context<Env>
type Row = typeof schema.authRequests.$inferSelect
const org = (c: Ctx) => c.req.param('orgId') ?? ''
const MAX_BULK = 500

const encString = z
  .string()
  .max(10_000)
  .regex(/^\d+\.[A-Za-z0-9+/=|_-]+$/, 'Invalid encrypted key.')

/** Pending, unexpired admin requests of enrolled active members, joined to the membership. */
async function pendingRequests(db: Db, orgUuid: string, ids?: string[]) {
  const uo = schema.usersOrganizations
  const ar = schema.authRequests
  const rows = await db
    .select({ r: ar, m: uo, email: schema.users.email, u: schema.users })
    .from(ar)
    .innerJoin(uo, and(eq(uo.userUuid, ar.userUuid), eq(uo.organizationUuid, orgUuid)))
    .innerJoin(schema.users, eq(schema.users.uuid, ar.userUuid))
    .where(
      and(
        eq(ar.type, AuthRequestType.AdminApproval),
        isNull(ar.approved),
        isNotNull(uo.resetPasswordKey),
        eq(uo.status, Status.Confirmed),
        ...(ids ? [inArray(ar.uuid, ids)] : []),
      ),
    )
    .orderBy(desc(ar.createdAt))
  // Federated members and members of other organisations are never approvable from here.
  const blocked = await unrecoverableMembers(
    db,
    rows.map((x) => ({ m: x.m, u: x.u })),
  )
  return rows.filter((x) => !isExpired(x.r) && !blocked.has(x.m.uuid))
}

const outranked = (actor: Member, target: Member) => {
  try {
    assertCanRecover(actor, target)
    return true
  } catch {
    return false
  }
}

/** `pending-organization-auth-request`: never carries a key. */
const pendingJson = (r: Row, m: Member, email: string) => ({
  object: 'pending-org-auth-request',
  id: r.uuid,
  userId: r.userUuid,
  organizationUserId: m.uuid,
  email,
  publicKey: r.publicKey,
  requestDeviceIdentifier: r.requestDeviceIdentifier,
  requestDeviceType: deviceTypeName(r.requestDeviceType),
  requestDeviceTypeValue: r.requestDeviceType,
  requestIpAddress: r.requestIp,
  requestCountryName: null,
  creationDate: new Date(r.createdAt).toISOString(),
  expirationDate: new Date(r.createdAt + ADMIN_AUTH_REQUEST_TTL_MS).toISOString(),
})

async function requireApprover(c: Ctx, db: Db) {
  const actor = await requireRecoveryAdmin(db, c.var.user.uuid, org(c))
  await assertPolicyEnabled(db, org(c))
  assertOrgKeys(await requireOrg(db, org(c)))
  return actor
}

orgAuthRequests.get('/api/organizations/:orgId/auth-requests', async (c) => {
  const db = createDb(c.env.DB)
  const actor = await requireApprover(c, db)
  const rows = (await pendingRequests(db, org(c))).filter((x) => outranked(actor, x.m))
  return c.json({
    object: 'list',
    data: rows.map((x) => pendingJson(x.r, x.m, x.email)),
    continuationToken: null,
  })
})

interface Answer {
  id: string
  approved: boolean
  key: string | null
}

/** Answers each request; returns per-request errors and pushes to the requesting users. */
async function answer(c: Ctx, answers: Answer[]) {
  const db = createDb(c.env.DB)
  const actor = await requireApprover(c, db)
  const unique = [...new Map(answers.map((a) => [a.id, a])).values()]
  const found = new Map(
    (
      await pendingRequests(
        db,
        org(c),
        unique.map((a) => a.id),
      )
    ).map((x) => [x.r.uuid, x]),
  )
  const now = Date.now()
  const done: { id: string; userUuid: string }[] = []
  const events: unknown[] = []
  const errors = new Map<string, string>()
  for (const a of unique) {
    const x = found.get(a.id)
    if (!x?.r.userUuid || !outranked(actor, x.m)) {
      errors.set(a.id, 'Auth request not found.')
      continue
    }
    if (a.approved && !a.key) {
      errors.set(a.id, 'An encrypted user key is required to approve.')
      continue
    }
    const result = await db
      .update(schema.authRequests)
      .set({ approved: a.approved, key: a.approved ? a.key : null, responseDate: now })
      .where(and(eq(schema.authRequests.uuid, a.id), isNull(schema.authRequests.approved)))
    // Lost a race with another administrator: nothing changed, so nothing is logged or pushed.
    if (result.meta.changes === 0) {
      errors.set(a.id, 'Auth request not found.')
      continue
    }
    events.push(
      eventStatement(db, c, {
        type: a.approved
          ? EventType.OrganizationUserApprovedAuthRequest
          : EventType.OrganizationUserRejectedAuthRequest,
        organizationUuid: org(c),
        organizationUserUuid: x.m.uuid,
        userUuid: x.r.userUuid,
      }),
    )
    done.push({ id: a.id, userUuid: x.r.userUuid })
  }
  if (events.length) await batch(db, events)
  defer(
    c,
    Promise.all(
      done.flatMap((d) => [
        pushAuthRequestResponse(c.env, d.id, d.userUuid),
        pushUserUpdate(c.env, d.userUuid, PushType.AuthRequestResponse, {
          Id: d.id,
          UserId: d.userUuid,
        }),
      ]),
    ),
  )
  return errors
}

const singleSchema = z.object({
  requestApproved: z.boolean(),
  encryptedUserKey: encString.nullish(),
})

orgAuthRequests.post('/api/organizations/:orgId/auth-requests/deny', async (c) => {
  const { ids } = await parseBody(
    c,
    z.object({ ids: z.array(z.string()).max(MAX_BULK).default([]) }),
  )
  await answer(
    c,
    ids.map((id) => ({ id, approved: false, key: null })),
  )
  return c.body(null, 200)
})

orgAuthRequests.post('/api/organizations/:orgId/auth-requests/:requestId', async (c) => {
  const body = await parseBody(c, singleSchema)
  const id = c.req.param('requestId')
  const errors = await answer(c, [
    { id, approved: body.requestApproved, key: body.encryptedUserKey ?? null },
  ])
  const error = errors.get(id)
  if (error) throw new ApiError(error === 'Auth request not found.' ? 404 : 400, error)
  return c.body(null, 200)
})

const bulkSchema = z
  .array(
    z.object({
      id: z.string().min(1),
      approved: z.boolean(),
      key: encString.nullish(),
      encryptedUserKey: encString.nullish(),
    }),
  )
  .max(MAX_BULK)

orgAuthRequests.post('/api/organizations/:orgId/auth-requests', async (c) => {
  const items = await parseBody(c, bulkSchema)
  const errors = await answer(
    c,
    items.map((i) => ({
      id: i.id,
      approved: i.approved,
      key: i.encryptedUserKey ?? i.key ?? null,
    })),
  )
  return c.json({
    object: 'list',
    data: items.map((i) => ({ id: i.id, error: errors.get(i.id) ?? null })),
    continuationToken: null,
  })
})
