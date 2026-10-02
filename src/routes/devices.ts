import { and, eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { fromB64u } from '../auth/crypto'
import { requireAuth } from '../auth/middleware'
import { findUserByEmail } from '../auth/users'
import { createDb, schema } from '../db'
import { later } from '../email/send'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { relayDeleteDevice, relayRegisterDevice } from '../notifications/relay'
import { rateLimit } from '../ratelimit'
import { parseBody } from '../validation'

export const devices = new Hono<Env>()

type Device = typeof schema.devices.$inferSelect

const deviceJson = (d: Device) => ({
  id: d.uuid,
  name: d.name,
  type: d.type,
  identifier: d.identifier,
  creationDate: new Date(d.createdAt).toISOString(),
  isTrusted: false,
  object: 'device',
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
const setToken = async (c: import('hono').Context<Env>) => {
  const { pushToken } = await parseBody(c, tokenSchema)
  const row = await ownDevice(c, eq(schema.devices.identifier, c.req.param('identifier') ?? ''))
  await createDb(c.env.DB)
    .update(schema.devices)
    .set({ pushToken: pushToken ?? null, updatedAt: Date.now() })
    .where(eq(schema.devices.uuid, row.uuid))
  // Mobile devices tell the relay where to push; clearing the token removes the registration.
  later(
    c,
    relayRegisterDevice(c.env, {
      uuid: row.uuid,
      identifier: row.identifier,
      type: row.type,
      pushToken: pushToken ?? null,
      userUuid: row.userUuid,
    }),
  )
  return c.body(null, 204)
}
devices.put('/api/devices/identifier/:identifier/token', requireAuth, setToken)
devices.post('/api/devices/identifier/:identifier/token', requireAuth, setToken)

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
