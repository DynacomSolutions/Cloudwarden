import { and, eq, inArray } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import {
  type Access,
  bumpOrgRevision,
  can,
  collectionAccess,
  FULL_ACCESS,
  isAdminRole,
  listAccessibleCollections,
  loadUserAccess,
  type Member,
  requireMember,
  requirePermission,
} from '../orgs/access'
import { EventType } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { accessOf, assertIdsInOrg, dedupeSelections, type Selection } from '../orgs/members'
import { authOnce, batch } from '../orgs/util'
import { collectionDetailsJson, collectionJson, selectionJson } from '../orgs/views'
import { parseBody } from '../validation'
import { chunk } from '../vault/ciphers'

export const collectionsRouter = new Hono<Env>()
collectionsRouter.use('/api/organizations/*', authOnce)
collectionsRouter.use('/api/collections', authOnce)

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
const collectionSchema = z.object({
  name: z.string().min(1),
  externalId: z.string().nullish(),
  users: z.array(selectionSchema).nullish(),
  groups: z.array(selectionSchema).nullish(),
})

collectionsRouter.get('/api/collections', async (c) => {
  const rows = await listAccessibleCollections(createDb(c.env.DB), c.var.user.uuid)
  return c.json(list(rows.map((r) => collectionDetailsJson(r.collection, r.access))))
})

async function loadCollection(db: Db, orgUuid: string, id: string) {
  const [col] = await db
    .select()
    .from(schema.collections)
    .where(and(eq(schema.collections.uuid, id), eq(schema.collections.organizationUuid, orgUuid)))
    .limit(1)
  if (!col) throw new ApiError(404, 'Collection not found.')
  return col
}

/** Access the caller has to a collection: every collection for editAnyCollection holders. */
async function callerAccess(
  db: Db,
  actor: Member,
  id: string,
  orgUuid: string,
): Promise<Access | undefined> {
  if (can(actor, 'editAnyCollection')) return FULL_ACCESS
  return collectionAccess(await loadUserAccess(db, actor.userUuid as string), orgUuid, id)
}

async function requireManage(db: Db, actor: Member, orgUuid: string, id: string) {
  const a = await callerAccess(db, actor, id, orgUuid)
  if (!a) throw new ApiError(404, 'Collection not found.')
  if (!a.manage) throw new ApiError(403, 'You do not have permission to manage this collection.')
}

/** Statements that replace the user and group grants of a collection. */
function replaceAccess(
  db: Db,
  collectionUuid: string,
  users: Selection[] | null,
  groups: Selection[] | null,
  fresh = false,
) {
  return [
    ...(users
      ? [
          ...(fresh
            ? []
            : [
                db
                  .delete(schema.usersCollections)
                  .where(eq(schema.usersCollections.collectionUuid, collectionUuid)),
              ]),
          ...users.map((s) =>
            db.insert(schema.usersCollections).values({
              organizationUserUuid: s.id,
              collectionUuid,
              ...accessOf(s),
            }),
          ),
        ]
      : []),
    ...(groups
      ? [
          ...(fresh
            ? []
            : [
                db
                  .delete(schema.collectionsGroups)
                  .where(eq(schema.collectionsGroups.collectionUuid, collectionUuid)),
              ]),
          ...groups.map((s) =>
            db.insert(schema.collectionsGroups).values({
              groupUuid: s.id,
              collectionUuid,
              ...accessOf(s),
            }),
          ),
        ]
      : []),
  ]
}

async function checkGrants(
  db: Db,
  orgUuid: string,
  users: Selection[] | null,
  groups: Selection[] | null,
) {
  if (users?.length)
    await assertIdsInOrg(
      db,
      'member',
      orgUuid,
      users.map((s) => s.id),
    )
  if (groups?.length)
    await assertIdsInOrg(
      db,
      'group',
      orgUuid,
      groups.map((s) => s.id),
    )
}

/** Users and groups with access to each of the organisation's collections. */
async function loadGrants(db: Db, orgUuid: string) {
  const users = new Map<string, Selection[]>()
  const groups = new Map<string, Selection[]>()
  const urows = await db
    .select({ c: schema.usersCollections })
    .from(schema.usersCollections)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.uuid, schema.usersCollections.organizationUserUuid),
    )
    .where(eq(schema.usersOrganizations.organizationUuid, orgUuid))
  for (const { c } of urows) {
    users.set(c.collectionUuid, [
      ...(users.get(c.collectionUuid) ?? []),
      { id: c.organizationUserUuid, ...c },
    ])
  }
  const grows = await db
    .select({ c: schema.collectionsGroups })
    .from(schema.collectionsGroups)
    .innerJoin(schema.groups, eq(schema.groups.uuid, schema.collectionsGroups.groupUuid))
    .where(eq(schema.groups.organizationUuid, orgUuid))
  for (const { c } of grows) {
    groups.set(c.collectionUuid, [
      ...(groups.get(c.collectionUuid) ?? []),
      { id: c.groupUuid, ...c },
    ])
  }
  return { users, groups }
}

const sel = (list: Selection[] | undefined) =>
  (list ?? []).map((s) => selectionJson(s.id, accessOf(s)))

async function accessDetails(c: Ctx, onlyId?: string) {
  const orgUuid = org(c)
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, orgUuid)
  const ua = await loadUserAccess(db, c.var.user.uuid)
  const all = can(actor, 'editAnyCollection')
  const cols = await db
    .select()
    .from(schema.collections)
    .where(eq(schema.collections.organizationUuid, orgUuid))
  const grants = await loadGrants(db, orgUuid)
  const rows = cols
    .filter((col) => !onlyId || col.uuid === onlyId)
    .flatMap((col) => {
      const own = collectionAccess(ua, orgUuid, col.uuid)
      if (!all && !own?.manage) return []
      const a = own ?? FULL_ACCESS
      return [
        {
          ...collectionDetailsJson(col, a),
          object: 'collectionAccessDetails',
          assigned: own !== undefined,
          unmanaged: false,
          users: sel(grants.users.get(col.uuid)),
          groups: sel(grants.groups.get(col.uuid)),
        },
      ]
    })
  return rows
}

collectionsRouter.get('/api/organizations/:orgId/collections/details', async (c) =>
  c.json(list(await accessDetails(c))),
)

collectionsRouter.get('/api/organizations/:orgId/collections', async (c) => {
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, org(c))
  if (can(actor, 'editAnyCollection') || isAdminRole(actor)) {
    const cols = await db
      .select()
      .from(schema.collections)
      .where(eq(schema.collections.organizationUuid, org(c)))
    return c.json(list(cols.map(collectionJson)))
  }
  const rows = await listAccessibleCollections(db, c.var.user.uuid)
  return c.json(
    list(
      rows
        .filter((r) => r.collection.organizationUuid === org(c))
        .map((r) => collectionJson(r.collection)),
    ),
  )
})

const bulkAccessSchema = z.object({
  collectionIds: z.array(z.string()).min(1).max(500),
  users: z.array(selectionSchema).nullish(),
  groups: z.array(selectionSchema).nullish(),
})
collectionsRouter.post('/api/organizations/:orgId/collections/bulk-access', async (c) => {
  const body = await parseBody(c, bulkAccessSchema)
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, org(c))
  const users = body.users ? dedupeSelections(body.users) : null
  const groups = body.groups ? dedupeSelections(body.groups) : null
  await assertIdsInOrg(db, 'collection', org(c), body.collectionIds)
  await checkGrants(db, org(c), users, groups)
  for (const id of body.collectionIds) await requireManage(db, actor, org(c), id)
  await batch(db, [
    ...body.collectionIds.flatMap((id) => [
      ...replaceAccess(db, id, users, groups),
      eventStatement(db, c, {
        type: EventType.CollectionUpdated,
        organizationUuid: org(c),
        collectionUuid: id,
      }),
    ]),
    bumpOrgRevision(db, org(c), Date.now()),
  ])
  return c.body(null, 200)
})

collectionsRouter.delete('/api/organizations/:orgId/collections', async (c) => {
  const { ids } = await parseBody(c, z.object({ ids: z.array(z.string()).max(500) }))
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, org(c), 'deleteAnyCollection')
  await assertIdsInOrg(db, 'collection', org(c), ids)
  await batch(db, [
    bumpOrgRevision(db, org(c), Date.now()),
    ...chunk(ids).map((part) =>
      db.delete(schema.collections).where(inArray(schema.collections.uuid, part)),
    ),
    ...ids.map((id) =>
      eventStatement(db, c, {
        type: EventType.CollectionDeleted,
        organizationUuid: org(c),
        collectionUuid: id,
      }),
    ),
  ])
  return c.body(null, 200)
})

collectionsRouter.post('/api/organizations/:orgId/collections', async (c) => {
  const body = await parseBody(c, collectionSchema)
  const db = createDb(c.env.DB)
  const actor = await requirePermission(db, c.var.user.uuid, org(c), 'createNewCollections')
  let users = body.users ? dedupeSelections(body.users) : null
  const groups = body.groups ? dedupeSelections(body.groups) : null
  await checkGrants(db, org(c), users, groups)
  // A creator without blanket access keeps the collection they just made.
  if (!isAdminRole(actor) && !actor.accessAll && !users?.some((u) => u.id === actor.uuid)) {
    users = [
      ...(users ?? []),
      { id: actor.uuid, readOnly: false, hidePasswords: false, manage: true },
    ]
  }
  const id = crypto.randomUUID()
  const now = Date.now()
  await batch(db, [
    db.insert(schema.collections).values({
      uuid: id,
      organizationUuid: org(c),
      name: body.name,
      externalId: body.externalId ?? null,
      createdAt: now,
      updatedAt: now,
    }),
    ...replaceAccess(db, id, users, groups, true),
    eventStatement(db, c, {
      type: EventType.CollectionCreated,
      organizationUuid: org(c),
      collectionUuid: id,
    }),
    bumpOrgRevision(db, org(c), now),
  ])
  return c.json(collectionJson(await loadCollection(db, org(c), id)))
})

collectionsRouter.get('/api/organizations/:orgId/collections/:id/details', async (c) => {
  const [row] = await accessDetails(c, c.req.param('id'))
  if (!row) throw new ApiError(404, 'Collection not found.')
  return c.json(row)
})

collectionsRouter.get('/api/organizations/:orgId/collections/:id/users', async (c) => {
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, org(c))
  const id = c.req.param('id')
  await loadCollection(db, org(c), id)
  await requireManage(db, actor, org(c), id)
  const grants = await loadGrants(db, org(c))
  return c.json(sel(grants.users.get(id)))
})

collectionsRouter.put('/api/organizations/:orgId/collections/:id/users', async (c) => {
  const users = dedupeSelections(await parseBody(c, z.array(selectionSchema)))
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, org(c))
  const id = c.req.param('id')
  await loadCollection(db, org(c), id)
  await requireManage(db, actor, org(c), id)
  await checkGrants(db, org(c), users, null)
  await batch(db, [...replaceAccess(db, id, users, null), bumpOrgRevision(db, org(c), Date.now())])
  return c.body(null, 200)
})

collectionsRouter.get('/api/organizations/:orgId/collections/:id', async (c) => {
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, org(c))
  const id = c.req.param('id')
  const col = await loadCollection(db, org(c), id)
  if (!(await callerAccess(db, actor, id, org(c)))) throw new ApiError(404, 'Collection not found.')
  return c.json(collectionJson(col))
})

const updateCollection = async (c: Ctx) => {
  const body = await parseBody(c, collectionSchema)
  const db = createDb(c.env.DB)
  const actor = await requireMember(db, c.var.user.uuid, org(c))
  const id = c.req.param('id') ?? ''
  await loadCollection(db, org(c), id)
  await requireManage(db, actor, org(c), id)
  const users = body.users ? dedupeSelections(body.users) : null
  const groups = body.groups ? dedupeSelections(body.groups) : null
  await checkGrants(db, org(c), users, groups)
  const now = Date.now()
  await batch(db, [
    db
      .update(schema.collections)
      .set({ name: body.name, externalId: body.externalId ?? null, updatedAt: now })
      .where(eq(schema.collections.uuid, id)),
    ...replaceAccess(db, id, users, groups),
    eventStatement(db, c, {
      type: EventType.CollectionUpdated,
      organizationUuid: org(c),
      collectionUuid: id,
    }),
    bumpOrgRevision(db, org(c), now),
  ])
  return c.json(collectionJson(await loadCollection(db, org(c), id)))
}
collectionsRouter.put('/api/organizations/:orgId/collections/:id', updateCollection)
collectionsRouter.post('/api/organizations/:orgId/collections/:id', updateCollection)

const deleteCollection = async (c: Ctx) => {
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, org(c), 'deleteAnyCollection')
  const id = c.req.param('id') ?? ''
  await loadCollection(db, org(c), id)
  await batch(db, [
    bumpOrgRevision(db, org(c), Date.now()),
    db.delete(schema.collections).where(eq(schema.collections.uuid, id)),
    eventStatement(db, c, {
      type: EventType.CollectionDeleted,
      organizationUuid: org(c),
      collectionUuid: id,
    }),
  ])
  return c.body(null, 200)
}
collectionsRouter.delete('/api/organizations/:orgId/collections/:id', deleteCollection)
collectionsRouter.post('/api/organizations/:orgId/collections/:id/delete', deleteCollection)
