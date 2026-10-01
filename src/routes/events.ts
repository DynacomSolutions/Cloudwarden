import { and, eq, or } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { getMember, requirePermission } from '../orgs/access'
import { accessToCipher, loadCipherById } from '../orgs/ciphers'
import { eventStatement, listEvents } from '../orgs/events'
import { getTarget } from '../orgs/members'
import { authOnce, batch } from '../orgs/util'
import { parseBody } from '../validation'

export const events = new Hono<Env>()
events.use('/events/*', authOnce)
events.use('/api/events', authOnce)
events.use('/api/organizations/*', authOnce)
events.use('/api/ciphers/*', authOnce)

type Ctx = Context<Env>

const MAX_COLLECT = 100

const collectSchema = z
  .array(
    z.object({
      type: z.number().int().min(1000).max(9999),
      cipherId: z.string().nullish(),
      organizationId: z.string().nullish(),
      date: z.string().nullish(),
    }),
  )
  .max(MAX_COLLECT)

/**
 * Client-reported events (copy, autofill, view). Events about items the caller cannot see, or
 * about personal items, are dropped silently so one stale entry never fails the batch.
 */
events.post('/events/collect', async (c) => {
  const body = await parseBody(c, collectSchema)
  const db = createDb(c.env.DB)
  const user = c.var.user
  const now = Date.now()
  const rows = []
  for (const e of body) {
    let orgUuid: string | null = null
    if (e.cipherId) {
      const cipher = await loadCipherById(db, e.cipherId)
      if (cipher?.organizationUuid && (await accessToCipher(db, user.uuid, cipher))) {
        orgUuid = cipher.organizationUuid
      } else continue
    } else if (e.organizationId) {
      const m = await getMember(db, user.uuid, e.organizationId)
      if (m && m.status >= 1) orgUuid = e.organizationId
      else continue
    } else continue
    const when = e.date ? Date.parse(e.date) : now
    rows.push(
      eventStatement(db, c, {
        type: e.type,
        organizationUuid: orgUuid,
        cipherUuid: e.cipherId ?? null,
        userUuid: user.uuid,
        date: Number.isNaN(when) ? now : Math.min(when, now),
      }),
    )
  }
  await batch(db, rows)
  return c.body(null, 200)
})

events.get('/api/events', async (c) =>
  c.json(await listEvents(createDb(c.env.DB), c, eq(schema.events.userUuid, c.var.user.uuid))),
)

const orgId = (c: Ctx) => c.req.param('orgId') ?? ''

events.get('/api/organizations/:orgId/events', async (c) => {
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, orgId(c), 'accessEventLogs')
  return c.json(await listEvents(db, c, eq(schema.events.organizationUuid, orgId(c))))
})

events.get('/api/organizations/:orgId/users/:id/events', async (c) => {
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, orgId(c), 'accessEventLogs')
  const target = await getTarget(db, orgId(c), c.req.param('id'))
  const mine = target.userUuid
    ? or(
        eq(schema.events.organizationUserUuid, target.uuid),
        eq(schema.events.actingUserUuid, target.userUuid),
      )
    : eq(schema.events.organizationUserUuid, target.uuid)
  return c.json(await listEvents(db, c, and(eq(schema.events.organizationUuid, orgId(c)), mine)))
})

events.get('/api/ciphers/:id/events', async (c) => {
  const db = createDb(c.env.DB)
  const cipher = await loadCipherById(db, c.req.param('id'))
  if (!cipher?.organizationUuid) throw new ApiError(404, 'Cipher not found.')
  await requirePermission(db, c.var.user.uuid, cipher.organizationUuid, 'accessEventLogs')
  return c.json(
    await listEvents(
      db,
      c,
      and(
        eq(schema.events.organizationUuid, cipher.organizationUuid),
        eq(schema.events.cipherUuid, cipher.uuid),
      ),
    ),
  )
})
