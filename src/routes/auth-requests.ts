import { and, desc, eq, gt, inArray, isNotNull, isNull, lt, ne, or } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { safeEqualStrings, sha256B64u } from '../auth/crypto'
import { requireAuth } from '../auth/middleware'
import { findUserByEmail, normalizeEmail } from '../auth/users'
import { createDb, schema } from '../db'
import { createEmailTransport, genericEmail } from '../email'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { PushType, pushAuthRequestResponse, pushUserUpdate } from '../notifications/publish'
import { can } from '../orgs/access'
import { EventType, PolicyType, Status } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { defer } from '../orgs/notify'
import { batch } from '../orgs/util'
import { rateLimit } from '../ratelimit'
import { parseBody } from '../validation'

/** Login-with-device: a new device asks an already signed-in device to approve it. */
export const authRequests = new Hono<Env>()

type AuthRequestRow = typeof schema.authRequests.$inferSelect

export const AUTH_REQUEST_TTL_MS = 15 * 60 * 1000
/** Admin approval requests wait for an administrator, so they live longer (TASKS #241). */
export const ADMIN_AUTH_REQUEST_TTL_MS = 7 * 24 * 3600 * 1000

/** Auth request types: 0 authenticate and unlock, 1 unlock, 2 admin approval. */
export const AuthRequestType = { AuthenticateAndUnlock: 0, Unlock: 1, AdminApproval: 2 } as const

const NOT_FOUND = () => new ApiError(404, 'Auth request not found.')
export const authRequestTtl = (type: number) =>
  type === AuthRequestType.AdminApproval ? ADMIN_AUTH_REQUEST_TTL_MS : AUTH_REQUEST_TTL_MS
export const isExpired = (r: AuthRequestRow) => Date.now() - r.createdAt >= authRequestTtl(r.type)

/** Deletes expired requests of every type. */
export const purgeExpired = (db: ReturnType<typeof createDb>, now: number) =>
  db
    .delete(schema.authRequests)
    .where(
      or(
        and(
          ne(schema.authRequests.type, AuthRequestType.AdminApproval),
          lt(schema.authRequests.createdAt, now - AUTH_REQUEST_TTL_MS),
        ),
        lt(schema.authRequests.createdAt, now - ADMIN_AUTH_REQUEST_TTL_MS),
      ),
    )

export const requestJson = (r: AuthRequestRow) => ({
  id: r.uuid,
  publicKey: r.publicKey,
  requestDeviceType: deviceTypeName(r.requestDeviceType),
  requestDeviceTypeValue: r.requestDeviceType,
  requestDeviceIdentifier: r.requestDeviceIdentifier,
  requestIpAddress: r.requestIp,
  requestCountryName: null,
  key: r.key,
  masterPasswordHash: r.masterPasswordHash,
  creationDate: new Date(r.createdAt).toISOString(),
  requestApproved: r.approved,
  responseDate: r.responseDate === null ? null : new Date(r.responseDate).toISOString(),
  isAnswered: r.approved !== null,
  isExpired: isExpired(r),
  object: 'auth-request',
})

export const deviceTypeName = (type: number) =>
  ({
    0: 'Android',
    1: 'iOS',
    2: 'Chrome Extension',
    3: 'Firefox Extension',
    4: 'Opera Extension',
    5: 'Edge Extension',
    6: 'Windows',
    7: 'macOS',
    8: 'Linux',
    9: 'Chrome',
    10: 'Firefox',
    11: 'Opera',
    12: 'Edge',
    13: 'Internet Explorer',
    14: 'Unknown Browser',
    15: 'Android',
    16: 'UWP',
    17: 'Safari',
    18: 'Vivaldi',
    19: 'Vivaldi Extension',
    20: 'Safari Extension',
    21: 'SDK',
    22: 'Server',
    23: 'Windows CLI',
    24: 'macOS CLI',
    25: 'Linux CLI',
  })[type] ?? 'Unknown'

const createSchema = z.object({
  email: z.string().min(1),
  deviceIdentifier: z.string().min(1).max(200),
  publicKey: z.string().min(1),
  type: z.number().int().optional(),
  accessCode: z.string().min(1),
})

const createRequest = async (c: import('hono').Context<Env>) => {
  const body = await parseBody(c, createSchema)
  const type = body.type ?? 0
  // Admin approval requests are created signed in, through `/auth-requests/admin-request`.
  if (type !== AuthRequestType.AuthenticateAndUnlock && type !== AuthRequestType.Unlock) {
    throw new ApiError(400, 'Use the admin request endpoint for admin approval requests.')
  }
  const db = createDb(c.env.DB)
  const deviceType = Number.parseInt(c.req.header('Device-Type') ?? '', 10)
  const now = Date.now()
  const row: AuthRequestRow = {
    uuid: crypto.randomUUID(),
    userUuid: null,
    type,
    requestDeviceIdentifier: body.deviceIdentifier,
    requestDeviceType: Number.isFinite(deviceType) ? deviceType : 14,
    requestIp: c.req.header('CF-Connecting-IP') ?? null,
    publicKey: body.publicKey,
    accessCodeHash: await sha256B64u(body.accessCode),
    approved: null,
    key: null,
    masterPasswordHash: null,
    responseDeviceUuid: null,
    responseDate: null,
    authenticatedAt: null,
    createdAt: now,
  }

  const user = await findUserByEmail(db, body.email)
  // Unknown or disabled accounts get a decoy row (no owner, no push) so the response, the
  // poll endpoint and the anonymous hub behave identically and emails cannot be probed.
  const real = user?.enabled ? user : null
  row.userUuid = real?.uuid ?? null
  await purgeExpired(db, now)
  await db.insert(schema.authRequests).values(row)
  if (!real) return c.json(requestJson(row))
  c.executionCtx.waitUntil(
    pushUserUpdate(
      c.env,
      real.uuid,
      PushType.AuthRequest,
      { Id: row.uuid, UserId: real.uuid },
      null,
    ),
  )
  return c.json(requestJson(row))
}
// Clients post to `/auth-requests/` with a trailing slash.
authRequests.post('/api/auth-requests', rateLimit('auth-request'), createRequest)
authRequests.post('/api/auth-requests/', rateLimit('auth-request'), createRequest)

const listPending = async (c: import('hono').Context<Env>) => {
  const rows = await createDb(c.env.DB)
    .select()
    .from(schema.authRequests)
    .where(
      and(
        eq(schema.authRequests.userUuid, c.var.user.uuid),
        gt(schema.authRequests.createdAt, Date.now() - AUTH_REQUEST_TTL_MS),
      ),
    )
    .orderBy(desc(schema.authRequests.createdAt))
  // Admin approval requests are answered by an organisation, never by the user's own devices.
  const pending = rows.filter(
    (r) => r.approved === null && r.type !== AuthRequestType.AdminApproval,
  )
  return c.json({ data: pending.map(requestJson), object: 'list', continuationToken: null })
}
authRequests.get('/api/auth-requests/pending', requireAuth, listPending)
authRequests.get('/api/auth-requests', requireAuth, listPending)
authRequests.get('/api/auth-requests/', requireAuth, listPending)

// Polled by the waiting device (no auth): the access code proves it created the request.
authRequests.get('/api/auth-requests/:id/response', rateLimit('auth-request'), async (c) => {
  const [row] = await createDb(c.env.DB)
    .select()
    .from(schema.authRequests)
    .where(eq(schema.authRequests.uuid, c.req.param('id')))
    .limit(1)
  const code = c.req.query('code') ?? ''
  if (!row || !safeEqualStrings(row.accessCodeHash, await sha256B64u(code))) throw NOT_FOUND()
  // Once redeemed the wrapped key is no longer served.
  return c.json(
    requestJson(
      row.authenticatedAt === null ? row : { ...row, key: null, masterPasswordHash: null },
    ),
  )
})

authRequests.get('/api/auth-requests/:id', requireAuth, async (c) => {
  const [row] = await createDb(c.env.DB)
    .select()
    .from(schema.authRequests)
    .where(
      and(
        eq(schema.authRequests.uuid, c.req.param('id')),
        eq(schema.authRequests.userUuid, c.var.user.uuid),
      ),
    )
    .limit(1)
  if (!row) throw NOT_FOUND()
  return c.json(requestJson(row))
})

const answerSchema = z.object({
  key: z.string().min(1).nullish(),
  masterPasswordHash: z.string().min(1).nullish(),
  deviceIdentifier: z.string().min(1).max(200),
  requestApproved: z.boolean(),
})

authRequests.put('/api/auth-requests/:id', requireAuth, async (c) => {
  const body = await parseBody(c, answerSchema)
  const user = c.var.user
  const db = createDb(c.env.DB)
  const [row] = await db
    .select()
    .from(schema.authRequests)
    .where(
      and(
        eq(schema.authRequests.uuid, c.req.param('id')),
        eq(schema.authRequests.userUuid, user.uuid),
      ),
    )
    .limit(1)
  if (!row || isExpired(row) || row.type === AuthRequestType.AdminApproval) throw NOT_FOUND()
  if (row.approved !== null) throw new ApiError(400, 'This request has already been answered.')
  if (body.requestApproved && !body.key) throw new ApiError(400, 'A key is required to approve.')

  const [device] = await db
    .select({ uuid: schema.devices.uuid })
    .from(schema.devices)
    .where(
      and(
        eq(schema.devices.userUuid, user.uuid),
        eq(schema.devices.identifier, c.var.auth.deviceIdentifier),
      ),
    )
    .limit(1)
  const now = Date.now()
  const updated: AuthRequestRow = {
    ...row,
    approved: body.requestApproved,
    key: body.requestApproved ? (body.key ?? null) : null,
    masterPasswordHash: body.requestApproved ? (body.masterPasswordHash ?? null) : null,
    responseDeviceUuid: device?.uuid ?? null,
    responseDate: now,
  }
  // The WHERE clause makes a concurrent second answer lose.
  const result = await db
    .update(schema.authRequests)
    .set({
      approved: updated.approved,
      key: updated.key,
      masterPasswordHash: updated.masterPasswordHash,
      responseDeviceUuid: updated.responseDeviceUuid,
      responseDate: now,
    })
    .where(and(eq(schema.authRequests.uuid, row.uuid), isNull(schema.authRequests.approved)))
  if (result.meta.changes === 0) throw new ApiError(400, 'This request has already been answered.')

  c.executionCtx.waitUntil(
    Promise.all([
      pushAuthRequestResponse(c.env, row.uuid, user.uuid),
      pushUserUpdate(
        c.env,
        user.uuid,
        PushType.AuthRequestResponse,
        { Id: row.uuid, UserId: user.uuid },
        body.deviceIdentifier,
      ),
    ]),
  )
  return c.json(requestJson(updated))
})

// ----- admin approval (type 2), TASKS #241 -----

/**
 * A signed-in device without the user key (trusted device encryption, or any account enrolled in
 * account recovery) asks the organisation to approve it. An administrator of an organisation
 * where the user is an enrolled, active member unwraps the recovery key and answers through
 * `/api/organizations/:orgId/auth-requests` (`src/routes/org-auth-requests.ts`). The requesting
 * device polls `GET /api/auth-requests/:id` and hears `AuthRequestResponse` on its user hub.
 */
authRequests.post('/api/auth-requests/admin-request', requireAuth, async (c) => {
  const body = await parseBody(c, createSchema)
  const user = c.var.user
  if (body.type !== AuthRequestType.AdminApproval) {
    throw new ApiError(400, 'Only admin approval requests are accepted here.')
  }
  if (normalizeEmail(body.email) !== user.email) throw new ApiError(400, 'Invalid email.')
  const db = createDb(c.env.DB)
  const orgs = await approvalOrganizations(db, user.uuid)
  if (orgs.length === 0) {
    throw new ApiError(
      400,
      'User does not belong to any organizations that support admin approval of devices.',
    )
  }
  const deviceType = Number.parseInt(c.req.header('Device-Type') ?? '', 10)
  const now = Date.now()
  const row: AuthRequestRow = {
    uuid: crypto.randomUUID(),
    userUuid: user.uuid,
    type: AuthRequestType.AdminApproval,
    requestDeviceIdentifier: body.deviceIdentifier,
    requestDeviceType: Number.isFinite(deviceType) ? deviceType : 14,
    requestIp: c.req.header('CF-Connecting-IP') ?? null,
    publicKey: body.publicKey,
    accessCodeHash: await sha256B64u(body.accessCode),
    approved: null,
    key: null,
    masterPasswordHash: null,
    responseDeviceUuid: null,
    responseDate: null,
    authenticatedAt: null,
    createdAt: now,
  }
  await purgeExpired(db, now)
  await batch(db, [
    db.insert(schema.authRequests).values(row),
    ...orgs.map((o) =>
      eventStatement(db, c, {
        type: EventType.UserRequestedDeviceApproval,
        userUuid: user.uuid,
        organizationUuid: o.org,
        organizationUserUuid: o.member,
      }),
    ),
  ])
  defer(c, notifyApprovers(c, orgs, user.email))
  return c.json(requestJson(row))
})

/** Organisations whose administrators may approve the user's devices. */
async function approvalOrganizations(db: ReturnType<typeof createDb>, userUuid: string) {
  const uo = schema.usersOrganizations
  const rows = await db
    .select({ org: uo.organizationUuid, member: uo.uuid, name: schema.organizations.name })
    .from(uo)
    .innerJoin(schema.organizations, eq(schema.organizations.uuid, uo.organizationUuid))
    .innerJoin(
      schema.policies,
      and(
        eq(schema.policies.organizationUuid, uo.organizationUuid),
        eq(schema.policies.atype, PolicyType.ResetPassword),
        eq(schema.policies.enabled, true),
      ),
    )
    .where(
      and(
        eq(uo.userUuid, userUuid),
        inArray(uo.status, [Status.Accepted, Status.Confirmed]),
        isNotNull(uo.resetPasswordKey),
      ),
    )
  return rows
}

/** Emails the members who can approve devices (owners, admins, custom with account recovery). */
async function notifyApprovers(
  c: import('hono').Context<Env>,
  orgs: { org: string; name: string }[],
  requester: string,
) {
  const transport = createEmailTransport(c.env)
  if (!transport.configured) return
  const db = createDb(c.env.DB)
  const link = `${c.env.DOMAIN.replace(/\/+$/, '')}/#/organizations`
  for (const o of orgs) {
    const members = await db
      .select({ m: schema.usersOrganizations, email: schema.users.email })
      .from(schema.usersOrganizations)
      .innerJoin(schema.users, eq(schema.users.uuid, schema.usersOrganizations.userUuid))
      .where(eq(schema.usersOrganizations.organizationUuid, o.org))
    for (const r of members.filter((x) => can(x.m, 'manageResetPassword'))) {
      const lines = [
        `${requester} asked to sign in on a new device and needs approval from an administrator of ${o.name}.`,
        'Review the request under Admin Console, Settings, Device approvals. It expires in seven days.',
      ]
      try {
        await transport.send({
          to: r.email,
          ...genericEmail('Device approval requested', [...lines, link]),
        })
      } catch {
        // Best effort; the request is listed for the administrators either way.
      }
    }
  }
}
