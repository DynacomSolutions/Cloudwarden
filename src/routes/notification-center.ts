// Notification centre, security tasks and Secrets Manager access requests (TASKS #231).
// Shapes follow the web client (libs/common/src/vault/notifications, libs/common/src/vault/tasks,
// apps/web/src/app/secrets-manager/secrets-manager-landing) and the GPL SDK API crate.
import { and, eq, inArray } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb, type Db, schema } from '../db'
import { createEmailTransport, genericEmail } from '../email'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { listNotifications, setNotificationState } from '../notifications/center'
import { PushType, pushUserUpdate } from '../notifications/publish'
import { can, getMember, requireMember } from '../orgs/access'
import { listOrgCipherRows } from '../orgs/ciphers'
import { Role, Status } from '../orgs/constants'
import { activeMemberIds, defer } from '../orgs/notify'
import { authOnce, batch } from '../orgs/util'
import { parseBody } from '../validation'

export const notificationCenter = new Hono<Env>()
type Ctx = Context<Env>

for (const path of ['/api/notifications', '/api/notifications/*', '/api/tasks', '/api/tasks/*']) {
  notificationCenter.use(path, authOnce)
}
notificationCenter.use('/api/request-access/*', authOnce)

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const idParam = (c: Ctx, name: string, what: string) => {
  const v = c.req.param(name) ?? ''
  if (!UUID.test(v)) throw new ApiError(404, `${what} not found.`)
  return v.toLowerCase()
}
const iso = (ms: number) => new Date(ms).toISOString()
const list = <T>(data: T[]) => ({ object: 'list', data, continuationToken: null })

// ----- notifications -----

const MAX_PAGE_SIZE = 1000
const bool = (v: string | undefined) => (v === undefined || v === '' ? undefined : v === 'true')

notificationCenter.get('/api/notifications', async (c) => {
  const size = Number.parseInt(c.req.query('pageSize') ?? '', 10)
  const page = Number.parseInt(c.req.query('continuationToken') ?? '', 10)
  return c.json(
    await listNotifications(createDb(c.env.DB), c.var.user.uuid, {
      read: bool(c.req.query('readStatusFilter')),
      deleted: bool(c.req.query('deletedStatusFilter')),
      page: Number.isFinite(page) && page > 0 ? page : 1,
      pageSize: Number.isFinite(size) && size > 0 ? Math.min(size, MAX_PAGE_SIZE) : 10,
    }),
  )
})

const stateRoute = (change: 'read' | 'deleted') => async (c: Ctx) => {
  const id = idParam(c, 'id', 'Notification')
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  if (!(await setNotificationState(c, db, c.var.user.uuid, id, change))) {
    throw new ApiError(404, 'Notification not found.')
  }
  return c.body(null, 200)
}

notificationCenter.patch('/api/notifications/:id/read', stateRoute('read'))
// The web client sends DELETE, the SDK sends PATCH.
notificationCenter.delete('/api/notifications/:id/delete', stateRoute('deleted'))
notificationCenter.patch('/api/notifications/:id/delete', stateRoute('deleted'))

// ----- security tasks -----

type Task = typeof schema.securityTasks.$inferSelect

const taskJson = (t: Task) => ({
  object: 'securityTasks',
  id: t.uuid,
  organizationId: t.organizationUuid,
  cipherId: t.cipherUuid,
  type: t.type,
  status: t.status,
  creationDate: iso(t.createdAt),
  revisionDate: iso(t.updatedAt),
})

const statusFilter = (c: Ctx) => {
  const raw = c.req.query('status')
  if (raw === undefined || raw === '') return undefined
  const n = Number(raw)
  if (n !== 0 && n !== 1)
    throw new ApiError(400, 'Invalid status.', { status: ['Invalid status.'] })
  return n
}

/** Tasks the user should act on: those about items they can edit in their organisations. */
async function tasksForUser(db: Db, userUuid: string) {
  const editable = new Set(
    (await listOrgCipherRows(db, userUuid)).filter((r) => r.access.edit).map((r) => r.cipher.uuid),
  )
  const orgs = (
    await db
      .select({ id: schema.usersOrganizations.organizationUuid })
      .from(schema.usersOrganizations)
      .where(
        and(
          eq(schema.usersOrganizations.userUuid, userUuid),
          eq(schema.usersOrganizations.status, Status.Confirmed),
        ),
      )
  ).map((r) => r.id)
  if (orgs.length === 0) return []
  const rows = await db
    .select()
    .from(schema.securityTasks)
    .where(inArray(schema.securityTasks.organizationUuid, orgs))
  return rows.filter((t) => t.cipherUuid === null || editable.has(t.cipherUuid))
}

/** Tells every member of the organisation to refetch their tasks. */
async function refreshTasks(c: Ctx, db: Db, orgUuid: string) {
  const members = await activeMemberIds(db, orgUuid)
  defer(
    c,
    (async () => {
      for (const user of members) {
        await pushUserUpdate(c.env, user, PushType.RefreshSecurityTasks, {
          UserId: user,
          Date: new Date().toISOString(),
        })
      }
    })(),
  )
}

notificationCenter.get('/api/tasks', async (c) => {
  const status = statusFilter(c)
  const rows = await tasksForUser(createDb(c.env.DB), c.var.user.uuid)
  return c.json(list(rows.filter((t) => status === undefined || t.status === status).map(taskJson)))
})

notificationCenter.patch('/api/tasks/:taskId/complete', async (c) => {
  const id = idParam(c, 'taskId', 'Task')
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const task = (await tasksForUser(db, c.var.user.uuid)).find((t) => t.uuid === id)
  if (!task) throw new ApiError(404, 'Task not found.')
  if (task.status !== 1) {
    await db
      .update(schema.securityTasks)
      .set({ status: 1, updatedAt: Date.now() })
      .where(eq(schema.securityTasks.uuid, id))
    await refreshTasks(c, db, task.organizationUuid)
  }
  return c.body(null, 200)
})

/** Organisation task management: owners, admins and custom members who can read reports. */
async function requireTaskManager(db: Db, userUuid: string, orgUuid: string) {
  const m = await requireMember(db, userUuid, orgUuid)
  if (!can(m, 'accessReports')) {
    throw new ApiError(403, 'You do not have permission to do this.')
  }
  return m
}

const orgTasks = (db: Db, orgUuid: string) =>
  db.select().from(schema.securityTasks).where(eq(schema.securityTasks.organizationUuid, orgUuid))

notificationCenter.get('/api/tasks/organization', async (c) => {
  const orgUuid = (c.req.query('organizationId') ?? '').toLowerCase()
  if (!UUID.test(orgUuid)) throw new ApiError(404, 'Organization not found.')
  const db = createDb(c.env.DB)
  await requireTaskManager(db, c.var.user.uuid, orgUuid)
  const status = statusFilter(c)
  const rows = await orgTasks(db, orgUuid)
  return c.json(list(rows.filter((t) => status === undefined || t.status === status).map(taskJson)))
})

notificationCenter.get('/api/tasks/:orgId/metrics', async (c) => {
  const orgUuid = idParam(c, 'orgId', 'Organization')
  const db = createDb(c.env.DB)
  await requireTaskManager(db, c.var.user.uuid, orgUuid)
  const rows = await orgTasks(db, orgUuid)
  return c.json({
    object: 'securityTaskMetrics',
    completedTasks: rows.filter((t) => t.status === 1).length,
    totalTasks: rows.length,
  })
})

const bulkCreateSchema = z.object({
  tasks: z
    .array(z.object({ type: z.literal(0), cipherId: z.string().nullish() }))
    .min(1)
    .max(500),
})

notificationCenter.post('/api/tasks/:orgId/bulk-create', async (c) => {
  const orgUuid = idParam(c, 'orgId', 'Organization')
  const body = await parseBody(c, bulkCreateSchema)
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  await requireTaskManager(db, c.var.user.uuid, orgUuid)
  const cipherIds = [
    ...new Set(body.tasks.flatMap((t) => (t.cipherId ? [t.cipherId.toLowerCase()] : []))),
  ]
  if (!cipherIds.every((id) => UUID.test(id))) throw new ApiError(400, 'Invalid cipher id.')
  const found: string[] = []
  for (let i = 0; i < cipherIds.length; i += 80) {
    const rows = await db
      .select({ id: schema.ciphers.uuid })
      .from(schema.ciphers)
      .where(
        and(
          inArray(schema.ciphers.uuid, cipherIds.slice(i, i + 80)),
          eq(schema.ciphers.organizationUuid, orgUuid),
        ),
      )
    found.push(...rows.map((r) => r.id))
  }
  if (found.length !== cipherIds.length) {
    throw new ApiError(400, 'Every task must refer to an item of this organization.')
  }
  const now = Date.now()
  const created: Task[] = body.tasks.map((t) => ({
    uuid: crypto.randomUUID(),
    organizationUuid: orgUuid,
    cipherUuid: t.cipherId?.toLowerCase() ?? null,
    type: t.type,
    status: 0,
    createdAt: now,
    updatedAt: now,
  }))
  await batch(
    db,
    created.map((t) => db.insert(schema.securityTasks).values(t)),
  )
  await refreshTasks(c, db, orgUuid)
  return c.json(list(created.map(taskJson)))
})

// ----- Secrets Manager access requests -----

const smAccessSchema = z.object({
  organizationId: z.string(),
  emailContent: z.string().min(1).max(5000),
})

/** Emails the organisation's owners and admins that a member asks for Secrets Manager access. */
notificationCenter.post('/api/request-access/request-sm-access', async (c) => {
  const body = await parseBody(c, smAccessSchema)
  const orgUuid = body.organizationId.toLowerCase()
  if (!UUID.test(orgUuid)) throw new ApiError(404, 'Organization not found.')
  const db = createDb(c.env.DB)
  const me = await getMember(db, c.var.user.uuid, orgUuid)
  if (!me || me.status !== Status.Confirmed) throw new ApiError(404, 'Organization not found.')
  const [org] = await db
    .select({ name: schema.organizations.name })
    .from(schema.organizations)
    .where(eq(schema.organizations.uuid, orgUuid))
  const uo = schema.usersOrganizations
  const admins = await db
    .select({ email: schema.users.email })
    .from(uo)
    .innerJoin(schema.users, eq(schema.users.uuid, uo.userUuid))
    .where(
      and(
        eq(uo.organizationUuid, orgUuid),
        eq(uo.status, Status.Confirmed),
        inArray(uo.atype, [Role.Owner, Role.Admin]),
      ),
    )
  const transport = createEmailTransport(c.env)
  if (!transport.configured) {
    throw new ApiError(400, 'This server cannot send email, so the request could not be sent.')
  }
  const who = c.var.user.name ? `${c.var.user.name} (${c.var.user.email})` : c.var.user.email
  const orgName = (org?.name ?? '').replace(/[\r\n]+/g, ' ')
  const message = genericEmail(`Secrets Manager access request for ${orgName}`, [
    `${who} asks for access to Secrets Manager in the organization ${orgName}.`,
    body.emailContent,
    'To grant access, open the organization members page and enable Secrets Manager for this member.',
  ])
  for (const a of admins) {
    try {
      await transport.send({ to: a.email, ...message })
    } catch {
      // One failed address must not stop the others. Message content is never logged.
    }
  }
  return c.body(null, 200)
})
