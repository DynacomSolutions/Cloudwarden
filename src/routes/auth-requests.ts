import { and, desc, eq, gt, isNull, lt } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { safeEqualStrings, sha256B64u } from '../auth/crypto'
import { requireAuth } from '../auth/middleware'
import { findUserByEmail } from '../auth/users'
import { createDb, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { PushType, pushAuthRequestResponse, pushUserUpdate } from '../notifications/publish'
import { rateLimit } from '../ratelimit'
import { parseBody } from '../validation'

/** Login-with-device: a new device asks an already signed-in device to approve it. */
export const authRequests = new Hono<Env>()

type AuthRequestRow = typeof schema.authRequests.$inferSelect

export const AUTH_REQUEST_TTL_MS = 15 * 60 * 1000

const NOT_FOUND = () => new ApiError(404, 'Auth request not found.')
const isExpired = (r: AuthRequestRow) => Date.now() - r.createdAt >= AUTH_REQUEST_TTL_MS

const requestJson = (r: AuthRequestRow) => ({
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

const deviceTypeName = (type: number) =>
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
  if (type !== 0 && type !== 1) throw new ApiError(400, 'Unsupported auth request type.')
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
  await db
    .delete(schema.authRequests)
    .where(lt(schema.authRequests.createdAt, now - AUTH_REQUEST_TTL_MS))
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
  const pending = rows.filter((r) => r.approved === null)
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
  if (!row || isExpired(row)) throw NOT_FOUND()
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
