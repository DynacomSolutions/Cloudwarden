import { and, count, eq, inArray, isNotNull } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { fromB64u, toB64u } from '../auth/crypto'
import { requireAuth } from '../auth/middleware'
import { verifyMasterPassword } from '../auth/passwords'
import { findUserByEmail } from '../auth/users'
import { createDb, runBatch, schema } from '../db'
import { later } from '../email/send'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { relayDeleteDevice, relayRegisterDevice } from '../notifications/relay'
import {
  MAX_WEB_PUSH_SUBSCRIPTIONS,
  validatePushEndpoint,
  validateSubscriptionKeys,
  validPublicKey,
} from '../notifications/webpush'
import { rateLimit } from '../ratelimit'
import { hasMasterPassword, isTrustedDevice } from '../sso/decryption'
import { parseBody } from '../validation'

export const devices = new Hono<Env>()

type Device = typeof schema.devices.$inferSelect

const deviceJson = (d: Device) => ({
  id: d.uuid,
  userId: d.userUuid,
  name: d.name,
  type: d.type,
  identifier: d.identifier,
  creationDate: new Date(d.createdAt).toISOString(),
  revisionDate: new Date(d.updatedAt).toISOString(),
  lastActivityDate: new Date(d.updatedAt).toISOString(),
  // Trusted device encryption (TASKS #284): trusted when all three keys are stored.
  isTrusted: isTrustedDevice(d),
  encryptedUserKey: d.encryptedUserKey,
  encryptedPublicKey: d.encryptedPublicKey,
  object: 'device',
})

/** The keys the client may read back for a trusted device (never the device private key). */
const protectedDeviceJson = (d: Device) => ({
  id: d.uuid,
  name: d.name,
  identifier: d.identifier,
  type: d.type,
  creationDate: new Date(d.createdAt).toISOString(),
  encryptedUserKey: d.encryptedUserKey,
  encryptedPublicKey: d.encryptedPublicKey,
  object: 'protectedDevice',
})

devices.get('/api/devices', requireAuth, async (c) => {
  const rows = await createDb(c.env.DB)
    .select()
    .from(schema.devices)
    .where(eq(schema.devices.userUuid, c.var.user.uuid))
  return c.json({ data: rows.map(deviceJson), object: 'list', continuationToken: null })
})

// Unauthenticated: the client asks before login whether this device is already known.
devices.get('/api/devices/knowndevice', rateLimit('knowndevice'), async (c) => {
  const encoded = c.req.header('X-Request-Email')
  const identifier = c.req.header('X-Device-Identifier')
  const bytes = encoded ? fromB64u(encoded) : null
  if (!bytes || !identifier)
    throw new ApiError(400, 'Both X-Request-Email and X-Device-Identifier are required.')
  const db = createDb(c.env.DB)
  const user = await findUserByEmail(db, new TextDecoder().decode(bytes))
  if (!user) return c.json(false)
  const [row] = await db
    .select({ uuid: schema.devices.uuid })
    .from(schema.devices)
    .where(and(eq(schema.devices.userUuid, user.uuid), eq(schema.devices.identifier, identifier)))
    .limit(1)
  return c.json(row !== undefined)
})

async function ownDevice(c: import('hono').Context<Env>, where: ReturnType<typeof eq>) {
  const [row] = await createDb(c.env.DB)
    .select()
    .from(schema.devices)
    .where(and(eq(schema.devices.userUuid, c.var.user.uuid), where))
    .limit(1)
  if (!row) throw new ApiError(404, 'Device not found.')
  return row
}

devices.get('/api/devices/identifier/:identifier', requireAuth, async (c) =>
  c.json(deviceJson(await ownDevice(c, eq(schema.devices.identifier, c.req.param('identifier'))))),
)

const tokenSchema = z.object({ pushToken: z.string().nullish() })

/** Stores (or, with null, clears) the mobile push token of one of the caller's devices. */
const storeToken = async (
  c: import('hono').Context<Env>,
  pushToken: string | null,
  status: 200 | 204 = 204,
) => {
  const row = await ownDevice(c, eq(schema.devices.identifier, c.req.param('identifier') ?? ''))
  await createDb(c.env.DB)
    .update(schema.devices)
    .set({ pushToken, updatedAt: Date.now() })
    .where(eq(schema.devices.uuid, row.uuid))
  // Mobile devices tell the relay where to push; clearing the token removes the registration.
  later(
    c,
    relayRegisterDevice(c.env, {
      uuid: row.uuid,
      identifier: row.identifier,
      type: row.type,
      pushToken,
      userUuid: row.userUuid,
    }),
  )
  return c.body(null, status)
}
const setToken = async (c: import('hono').Context<Env>) =>
  storeToken(c, (await parseBody(c, tokenSchema)).pushToken ?? null)
devices.put('/api/devices/identifier/:identifier/token', requireAuth, setToken)
devices.post('/api/devices/identifier/:identifier/token', requireAuth, setToken)

/** `PUT devices/identifier/{identifier}/clear-token`: forget the push token (sign-out, push off). */
const clearToken = (c: import('hono').Context<Env>) => storeToken(c, null, 200)
devices.put('/api/devices/identifier/:identifier/clear-token', requireAuth, clearToken)
devices.post('/api/devices/identifier/:identifier/clear-token', requireAuth, clearToken)

// Web Push subscription of a browser (TASKS #342): endpoint plus the P-256 key and auth secret.
const webPushSchema = z.object({
  endpoint: z.string().min(1).max(2048),
  p256dh: z.string().min(1).max(256),
  auth: z.string().min(1).max(256),
})
const setWebPushAuth = async (c: import('hono').Context<Env>) => {
  const body = await parseBody(c, webPushSchema)
  const row = await ownDevice(c, eq(schema.devices.identifier, c.req.param('identifier') ?? ''))
  const endpoint = validatePushEndpoint(body.endpoint)
  if (!endpoint) {
    throw new ApiError(400, 'The push endpoint is not supported.', {
      endpoint: ['The push endpoint is not supported.'],
    })
  }
  if (!validateSubscriptionKeys(body.p256dh, body.auth)) {
    throw new ApiError(400, 'The push subscription keys are not valid.', {
      p256dh: ['The push subscription keys are not valid.'],
    })
  }
  if (!(await validPublicKey(body.p256dh))) {
    throw new ApiError(400, 'The push subscription keys are not valid.', {
      p256dh: ['The push subscription keys are not valid.'],
    })
  }
  const db = createDb(c.env.DB)
  if (!row.webPushEndpoint) {
    const [{ n } = { n: 0 }] = await db
      .select({ n: count() })
      .from(schema.devices)
      .where(
        and(eq(schema.devices.userUuid, row.userUuid), isNotNull(schema.devices.webPushEndpoint)),
      )
    if (n >= MAX_WEB_PUSH_SUBSCRIPTIONS) {
      throw new ApiError(400, 'Too many push subscriptions for this account.')
    }
  }
  await db
    .update(schema.devices)
    .set({
      webPushEndpoint: endpoint,
      // Stored as unpadded base64url whichever alphabet the client used.
      webPushP256dh: toB64u(fromB64u(body.p256dh) as Uint8Array),
      webPushAuth: toB64u(fromB64u(body.auth) as Uint8Array),
      updatedAt: Date.now(),
    })
    .where(eq(schema.devices.uuid, row.uuid))
  return c.body(null, 200)
}
devices.put('/api/devices/identifier/:identifier/web-push-auth', requireAuth, setWebPushAuth)
devices.post('/api/devices/identifier/:identifier/web-push-auth', requireAuth, setWebPushAuth)

const deactivate = async (c: import('hono').Context<Env>) => {
  const row = await ownDevice(c, eq(schema.devices.uuid, c.req.param('id') ?? ''))
  await createDb(c.env.DB).delete(schema.devices).where(eq(schema.devices.uuid, row.uuid))
  later(
    c,
    relayDeleteDevice(c.env, {
      uuid: row.uuid,
      identifier: row.identifier,
      type: row.type,
      pushToken: row.pushToken,
      userUuid: row.userUuid,
    }),
  )
  return c.body(null, 200)
}
devices.delete('/api/devices/:id', requireAuth, deactivate)
devices.post('/api/devices/:id/deactivate', requireAuth, deactivate)

// ----- Trusted device encryption (TASKS #284) -----

const keysSchema = z.object({
  encryptedUserKey: z.string().min(1).max(10_000),
  encryptedPublicKey: z.string().min(1).max(10_000),
  encryptedPrivateKey: z.string().min(1).max(10_000),
})

/** `PUT devices/{identifier}/keys`: trust this device by storing its key set. */
devices.put('/api/devices/:identifier/keys', requireAuth, async (c) => {
  const body = await parseBody(c, keysSchema)
  const row = await ownDevice(c, eq(schema.devices.identifier, c.req.param('identifier')))
  await createDb(c.env.DB)
    .update(schema.devices)
    .set({ ...body, updatedAt: Date.now() })
    .where(eq(schema.devices.uuid, row.uuid))
  return c.json(deviceJson({ ...row, ...body }))
})

/** `POST devices/{identifier}/retrieve-keys`: the stored key set of a trusted device. */
devices.post('/api/devices/:identifier/retrieve-keys', requireAuth, async (c) => {
  const row = await ownDevice(c, eq(schema.devices.identifier, c.req.param('identifier')))
  if (!isTrustedDevice(row)) throw new ApiError(400, 'Device is not trusted.')
  return c.json(protectedDeviceJson(row))
})

const clearKeys = { encryptedUserKey: null, encryptedPublicKey: null, encryptedPrivateKey: null }

/** `POST devices/lost-trust`: the client lost its device key; forget the stored set. */
devices.post('/api/devices/lost-trust', requireAuth, async (c) => {
  const identifier = c.req.header('Device-Identifier') ?? c.var.auth.deviceIdentifier
  const row = await ownDevice(c, eq(schema.devices.identifier, identifier))
  await createDb(c.env.DB)
    .update(schema.devices)
    .set({ ...clearKeys, updatedAt: Date.now() })
    .where(eq(schema.devices.uuid, row.uuid))
  return c.body(null, 200)
})

/** `POST devices/untrust`: remove trust from the listed devices of the user. */
devices.post('/api/devices/untrust', requireAuth, async (c) => {
  const { devices: ids } = await parseBody(c, z.object({ devices: z.array(z.string()).max(500) }))
  if (ids.length > 0) {
    await createDb(c.env.DB)
      .update(schema.devices)
      .set({ ...clearKeys, updatedAt: Date.now() })
      .where(and(eq(schema.devices.userUuid, c.var.user.uuid), inArray(schema.devices.uuid, ids)))
  }
  return c.body(null, 200)
})

const rewrapSchema = z.object({
  encryptedPublicKey: z.string().min(1),
  encryptedUserKey: z.string().min(1),
})
const updateTrustSchema = z.object({
  masterPasswordHash: z.string().nullish(),
  otp: z.string().nullish(),
  authRequestAccessCode: z.string().nullish(),
  currentDevice: rewrapSchema.nullish(),
  otherDevices: z
    .array(rewrapSchema.extend({ deviceId: z.string().min(1) }))
    .max(500)
    .nullish(),
})

/**
 * `POST devices/update-trust`: after a user key rotation the client re-wraps the user key for
 * each trusted device. Needs the master password when the account has one. Devices must already
 * be trusted; the device private key is unchanged.
 */
devices.post('/api/devices/update-trust', requireAuth, async (c) => {
  const body = await parseBody(c, updateTrustSchema)
  const user = c.var.user
  if (
    hasMasterPassword(user) &&
    !(await verifyMasterPassword(user, body.masterPasswordHash ?? ''))
  ) {
    throw new ApiError(400, 'Invalid password.', { masterPasswordHash: ['Invalid password.'] })
  }
  const db = createDb(c.env.DB)
  const rows = await db.select().from(schema.devices).where(eq(schema.devices.userUuid, user.uuid))
  const identifier = c.req.header('Device-Identifier') ?? c.var.auth.deviceIdentifier
  const now = Date.now()
  const updates: { uuid: string; keys: z.infer<typeof rewrapSchema> }[] = []
  if (body.currentDevice) {
    const current = rows.find((d) => d.identifier === identifier)
    if (!current || !isTrustedDevice(current))
      throw new ApiError(400, 'The current device is not trusted.')
    updates.push({ uuid: current.uuid, keys: body.currentDevice })
  }
  for (const other of body.otherDevices ?? []) {
    const row = rows.find((d) => d.uuid === other.deviceId)
    if (!row || !isTrustedDevice(row))
      throw new ApiError(400, 'A device in the request is not trusted.')
    updates.push({
      uuid: row.uuid,
      keys: {
        encryptedPublicKey: other.encryptedPublicKey,
        encryptedUserKey: other.encryptedUserKey,
      },
    })
  }
  if (updates.length > 0) {
    await runBatch(
      db,
      updates.map((u) =>
        db
          .update(schema.devices)
          .set({ ...u.keys, updatedAt: now })
          .where(and(eq(schema.devices.uuid, u.uuid), eq(schema.devices.userUuid, user.uuid))),
      ) as never,
    )
  }
  return c.body(null, 200)
})

// SDK DeviceRequestModel. A device registered here holds no session until it logs in.
const deviceSchema = z.object({
  type: z.number().int().min(0),
  name: z.string().min(1).max(50),
  identifier: z.string().min(1).max(50),
  pushToken: z.string().nullish(),
})

devices.post('/api/devices', requireAuth, async (c) => {
  const body = await parseBody(c, deviceSchema)
  const db = createDb(c.env.DB)
  const now = Date.now()
  await db
    .insert(schema.devices)
    .values({
      uuid: crypto.randomUUID(),
      identifier: body.identifier,
      userUuid: c.var.user.uuid,
      name: body.name,
      type: body.type,
      pushToken: body.pushToken ?? null,
      refreshToken: '',
      createdAt: now,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: [schema.devices.userUuid, schema.devices.identifier],
      set: { name: body.name, type: body.type, pushToken: body.pushToken ?? null, updatedAt: now },
    })
  return c.json(deviceJson(await ownDevice(c, eq(schema.devices.identifier, body.identifier))))
})

// Only UUID ids match, so named routes under /api/devices added elsewhere are not shadowed.
const DEVICE_ID = '/api/devices/:id{[0-9a-fA-F-]{36}}'

devices.get(DEVICE_ID, requireAuth, async (c) =>
  c.json(deviceJson(await ownDevice(c, eq(schema.devices.uuid, c.req.param('id'))))),
)

const updateDevice = async (c: import('hono').Context<Env>) => {
  const body = await parseBody(c, deviceSchema)
  const row = await ownDevice(c, eq(schema.devices.uuid, c.req.param('id') ?? ''))
  // The identifier names the installation, so it is never changed by an update.
  await createDb(c.env.DB)
    .update(schema.devices)
    .set({
      name: body.name,
      type: body.type,
      pushToken: body.pushToken ?? null,
      updatedAt: Date.now(),
    })
    .where(eq(schema.devices.uuid, row.uuid))
  return c.json(deviceJson(await ownDevice(c, eq(schema.devices.uuid, row.uuid))))
}
devices.put(DEVICE_ID, requireAuth, updateDevice)
