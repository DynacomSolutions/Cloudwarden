import { and, eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { bumpOrgRevision, requirePermission } from '../orgs/access'
import { EventType } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { accessOf, assertIdsInOrg, dedupeSelections, type Selection } from '../orgs/members'
import { authOnce, batch } from '../orgs/util'
import { groupJson, selectionJson } from '../orgs/views'
import { parseBody } from '../validation'

export const groupsRouter = new Hono<Env>()
groupsRouter.use('/api/organizations/*', authOnce)

type Ctx = Context<Env>
const org = (c: Ctx) => c.req.param('orgId') ?? ''
const list = (data: unknown[]) => ({ object: 'list', data, continuationToken: null })

const selectionSchema = z.object({
  id: z.string().min(1),
  readOnly: z
    .boolean()
    .nullish()
    .transform((v) => v ?? false),
  hidePasswords: z
    .boolean()
    .nullish()
    .transform((v) => v ?? false),
  manage: z
    .boolean()
    .nullish()
    .transform((v) => v ?? false),
})
const groupSchema = z.object({
  name: z.string().min(1).max(100),
  accessAll: z.boolean().nullish(),
  externalId: z.string().nullish(),
  collections: z.array(selectionSchema).nullish(),
  users: z.array(z.string()).nullish(),
})

const guard = (c: Ctx) =>
  requirePermission(createDb(c.env.DB), c.var.user.uuid, org(c), 'manageGroups')

async function loadGroup(db: Db, orgUuid: string, id: string) {
  const [g] = await db
    .select()
    .from(schema.groups)
    .where(and(eq(schema.groups.uuid, id), eq(schema.groups.organizationUuid, orgUuid)))
    .limit(1)
  if (!g) throw new ApiError(404, 'Group not found.')
  return g
}

async function groupDetails(db: Db, g: typeof schema.groups.$inferSelect) {
  const cols = await db
    .select()
    .from(schema.collectionsGroups)
    .where(eq(schema.collectionsGroups.groupUuid, g.uuid))
  return {
    ...groupJson(g),
    object: 'groupDetails',
    collections: cols.map((r) =>
      selectionJson(r.collectionUuid, {
        readOnly: r.readOnly,
        hidePasswords: r.hidePasswords,
        manage: r.manage,
      }),
    ),
  }
}

groupsRouter.get('/api/organizations/:orgId/groups', async (c) => {
  await guard(c)
  const rows = await createDb(c.env.DB)
    .select()
    .from(schema.groups)
    .where(eq(schema.groups.organizationUuid, org(c)))
  return c.json(list(rows.map(groupJson)))
})

groupsRouter.get('/api/organizations/:orgId/groups/details', async (c) => {
  await guard(c)
  const db = createDb(c.env.DB)
  const rows = await db
    .select()
    .from(schema.groups)
    .where(eq(schema.groups.organizationUuid, org(c)))
  return c.json(list(await Promise.all(rows.map((g) => groupDetails(db, g)))))
})

groupsRouter.delete('/api/organizations/:orgId/groups', async (c) => {
  const { ids } = await parseBody(c, z.object({ ids: z.array(z.string()).max(500) }))
  await guard(c)
  const db = createDb(c.env.DB)
  await assertIdsInOrg(db, 'group', org(c), ids)
  await batch(db, [
    bumpOrgRevision(db, org(c), Date.now()),
    ...ids.map((id) => db.delete(schema.groups).where(eq(schema.groups.uuid, id))),
    ...ids.map((id) =>
      eventStatement(db, c, {
        type: EventType.GroupDeleted,
        organizationUuid: org(c),
        groupUuid: id,
      }),
    ),
  ])
  return c.body(null, 200)
})

async function groupMembers(db: Db, groupUuid: string) {
  const rows = await db
    .select({ m: schema.groupsUsers.organizationUserUuid })
    .from(schema.groupsUsers)
    .where(eq(schema.groupsUsers.groupUuid, groupUuid))
  return rows.map((r) => r.m)
}

groupsRouter.get('/api/organizations/:orgId/groups/:id/details', async (c) => {
  await guard(c)
  const db = createDb(c.env.DB)
  return c.json(await groupDetails(db, await loadGroup(db, org(c), c.req.param('id'))))
})

groupsRouter.get('/api/organizations/:orgId/groups/:id/users', async (c) => {
  await guard(c)
  const db = createDb(c.env.DB)
  const g = await loadGroup(db, org(c), c.req.param('id'))
  return c.json(await groupMembers(db, g.uuid))
})

/** Statements that replace the members and collection grants of a group. */
function groupStatements(
  db: Db,
  id: string,
  users: string[] | null,
  collections: Selection[] | null,
  fresh: boolean,
) {
  return [
    ...(users
      ? [
          ...(fresh
            ? []
            : [db.delete(schema.groupsUsers).where(eq(schema.groupsUsers.groupUuid, id))]),
          ...users.map((u) =>
            db.insert(schema.groupsUsers).values({ groupUuid: id, organizationUserUuid: u }),
          ),
        ]
      : []),
    ...(collections
      ? [
          ...(fresh
            ? []
            : [
                db
                  .delete(schema.collectionsGroups)
                  .where(eq(schema.collectionsGroups.groupUuid, id)),
              ]),
          ...collections.map((s) =>
            db
              .insert(schema.collectionsGroups)
              .values({ groupUuid: id, collectionUuid: s.id, ...accessOf(s) }),
          ),
        ]
      : []),
  ]
}

groupsRouter.put('/api/organizations/:orgId/groups/:id/users', async (c) => {
  const users = [...new Set(await parseBody(c, z.array(z.string())))]
  await guard(c)
  const db = createDb(c.env.DB)
  const g = await loadGroup(db, org(c), c.req.param('id'))
  if (users.length) await assertIdsInOrg(db, 'member', org(c), users)
  await batch(db, [
    ...groupStatements(db, g.uuid, users, null, false),
    eventStatement(db, c, {
      type: EventType.GroupUpdated,
      organizationUuid: org(c),
      groupUuid: g.uuid,
    }),
    bumpOrgRevision(db, org(c), Date.now()),
  ])
  return c.body(null, 200)
})

groupsRouter.get('/api/organizations/:orgId/groups/:id', async (c) => {
  await guard(c)
  const db = createDb(c.env.DB)
  return c.json(await groupDetails(db, await loadGroup(db, org(c), c.req.param('id'))))
})

async function checkRefs(
  db: Db,
  orgUuid: string,
  users: string[] | null,
  cols: Selection[] | null,
) {
  if (users?.length) await assertIdsInOrg(db, 'member', orgUuid, users)
  if (cols?.length)
    await assertIdsInOrg(
      db,
      'collection',
      orgUuid,
      cols.map((s) => s.id),
    )
}

groupsRouter.post('/api/organizations/:orgId/groups', async (c) => {
  const body = await parseBody(c, groupSchema)
  await guard(c)
  const db = createDb(c.env.DB)
  const users = body.users ? [...new Set(body.users)] : null
  const cols = body.collections ? dedupeSelections(body.collections) : null
  await checkRefs(db, org(c), users, cols)
  const id = crypto.randomUUID()
  const now = Date.now()
  await batch(db, [
    db.insert(schema.groups).values({
      uuid: id,
      organizationUuid: org(c),
      name: body.name,
      accessAll: body.accessAll === true,
      externalId: body.externalId ?? null,
      createdAt: now,
      updatedAt: now,
    }),
    ...groupStatements(db, id, users, body.accessAll ? null : cols, true),
    eventStatement(db, c, {
      type: EventType.GroupCreated,
      organizationUuid: org(c),
      groupUuid: id,
    }),
    bumpOrgRevision(db, org(c), now),
  ])
  return c.json(groupJson(await loadGroup(db, org(c), id)))
})

const updateGroup = async (c: Ctx) => {
  const body = await parseBody(c, groupSchema)
  await guard(c)
  const db = createDb(c.env.DB)
  const g = await loadGroup(db, org(c), c.req.param('id') ?? '')
  const users = body.users ? [...new Set(body.users)] : null
  const cols = body.collections ? dedupeSelections(body.collections) : []
  await checkRefs(db, org(c), users, cols)
  const now = Date.now()
  await batch(db, [
    db
      .update(schema.groups)
      .set({
        name: body.name,
        accessAll: body.accessAll === true,
        externalId: body.externalId ?? null,
        updatedAt: now,
      })
      .where(eq(schema.groups.uuid, g.uuid)),
    ...groupStatements(db, g.uuid, users, body.accessAll ? [] : cols, false),
    eventStatement(db, c, {
      type: EventType.GroupUpdated,
      organizationUuid: org(c),
      groupUuid: g.uuid,
    }),
    bumpOrgRevision(db, org(c), now),
  ])
  return c.json(groupJson(await loadGroup(db, org(c), g.uuid)))
}
groupsRouter.put('/api/organizations/:orgId/groups/:id', updateGroup)
groupsRouter.post('/api/organizations/:orgId/groups/:id', updateGroup)

const deleteGroup = async (c: Ctx) => {
  await guard(c)
  const db = createDb(c.env.DB)
  const g = await loadGroup(db, org(c), c.req.param('id') ?? '')
  await batch(db, [
    bumpOrgRevision(db, org(c), Date.now()),
    db.delete(schema.groups).where(eq(schema.groups.uuid, g.uuid)),
    eventStatement(db, c, {
      type: EventType.GroupDeleted,
      organizationUuid: org(c),
      groupUuid: g.uuid,
    }),
  ])
  return c.body(null, 200)
}
groupsRouter.delete('/api/organizations/:orgId/groups/:id', deleteGroup)
groupsRouter.post('/api/organizations/:orgId/groups/:id/delete', deleteGroup)
