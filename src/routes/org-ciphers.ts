import { and, eq, inArray } from 'drizzle-orm'
import type { Context, Next } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { verifyMasterPassword } from '../auth/passwords'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import {
  bumpOrgRevision,
  canManageAllCiphers,
  loadUserAccess,
  type Member,
  requireMember,
  requireOwner,
  requirePermission,
} from '../orgs/access'
import {
  accessToCipher,
  adminItemAccess,
  assertWritableCollections,
  folderLinks,
  type ItemAccess,
  itemAccess,
  linkedCollections,
  listOrgCipherRows,
  loadCipherById,
  orgCipherJson,
  userFolderStatements,
} from '../orgs/ciphers'
import { EventType } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { assertPersonalOwnershipAllowed } from '../orgs/policies'
import { authOnce, batch } from '../orgs/util'
import { parseBody } from '../validation'
import {
  bumpRevision,
  type CipherBody,
  checkRevision,
  chunk,
  cipherJson,
  cipherSchema,
  cipherValues,
  requireFolder,
  setFolderStatements,
} from '../vault/ciphers'

/**
 * Organisation-aware cipher routes. Mounted before the personal vault router: each handler
 * deals with organisation items and calls `next()` for everything else, so personal behaviour
 * stays in `routes/ciphers.ts`.
 */
export const orgCiphers = new Hono<Env>()
orgCiphers.use('/api/ciphers', authOnce)
orgCiphers.use('/api/ciphers/*', authOnce)

type Ctx = Context<Env>
type CipherRecord = typeof schema.ciphers.$inferSelect

const MAX_BULK = 500
const list = (data: unknown[]) => ({ object: 'list', data, continuationToken: null })
const idParam = (c: Ctx) => c.req.param('id') ?? ''
const NOT_FOUND = () => new ApiError(404, 'Cipher not found.')

interface Resolved {
  cipher: CipherRecord
  access: ItemAccess
  member?: Member
}

/** Resolves an organisation item for the caller; null when the id is not an organisation item. */
async function resolve(c: Ctx, id: string, admin: boolean): Promise<Resolved | null> {
  const db = createDb(c.env.DB)
  const cipher = await loadCipherById(db, id)
  if (!cipher?.organizationUuid) return null
  if (admin) {
    const member = await requireMember(db, c.var.user.uuid, cipher.organizationUuid)
    if (!canManageAllCiphers(member))
      throw new ApiError(403, 'You do not have permission to do this.')
    return { cipher, access: await adminItemAccess(db, cipher), member }
  }
  const access = await accessToCipher(db, c.var.user.uuid, cipher)
  if (!access) throw NOT_FOUND()
  return { cipher, access }
}

async function userFolderOf(db: Db, userUuid: string, cipherUuid: string) {
  return (await folderLinks(db, userUuid)).get(cipherUuid) ?? null
}

/** The item as the caller sees it, read fresh from the database. */
async function respond(c: Ctx, id: string, admin: boolean) {
  const db = createDb(c.env.DB)
  const r = await resolve(c, id, admin)
  if (!r) throw NOT_FOUND()
  const folderId = await userFolderOf(db, c.var.user.uuid, id)
  return c.json(orgCipherJson({ cipher: r.cipher, folderId, access: r.access }))
}

const canDelete = (a: ItemAccess) => a.edit || a.manage

// ----- create -----

async function createOrgCipher(c: Ctx, body: CipherBody, collectionIds: string[], admin: boolean) {
  const db = createDb(c.env.DB)
  const user = c.var.user
  const orgUuid = body.organizationId as string
  const member = await requireMember(db, user.uuid, orgUuid)
  const manager = canManageAllCiphers(member)
  if (admin && !manager) throw new ApiError(403, 'You do not have permission to do this.')
  if (!admin && collectionIds.length === 0 && !manager && !member.accessAll) {
    throw new ApiError(400, 'You must select at least one collection.')
  }
  await assertWritableCollections(db, user.uuid, member, orgUuid, collectionIds)
  if (body.folderId) await requireFolder(db, user.uuid, body.folderId)
  const id = crypto.randomUUID()
  const now = Date.now()
  const unique = [...new Set(collectionIds)]
  await batch(db, [
    db.insert(schema.ciphers).values({
      uuid: id,
      userUuid: null,
      organizationUuid: orgUuid,
      ...cipherValues(body),
      favorite: false,
      createdAt: now,
      updatedAt: now,
    }),
    ...unique.map((collectionUuid) =>
      db.insert(schema.ciphersCollections).values({ cipherUuid: id, collectionUuid }),
    ),
    ...(body.folderId && !admin
      ? [db.insert(schema.foldersCiphers).values({ cipherUuid: id, folderUuid: body.folderId })]
      : []),
    eventStatement(db, c, {
      type: EventType.CipherCreated,
      organizationUuid: orgUuid,
      cipherUuid: id,
    }),
    bumpOrgRevision(db, orgUuid, now),
  ])
  return respond(c, id, admin)
}

const createSchema = z.object({
  cipher: cipherSchema,
  collectionIds: z.array(z.string()).nullish(),
})

orgCiphers.post('/api/ciphers', async (c, next) => {
  const body = await parseBody(c, cipherSchema)
  if (body.organizationId) return createOrgCipher(c, body, [], false)
  await assertPersonalOwnershipAllowed(createDb(c.env.DB), c.var.user.uuid)
  return next()
})

orgCiphers.post('/api/ciphers/create', async (c, next) => {
  const body = await parseBody(c, createSchema)
  if (body.cipher.organizationId) {
    return createOrgCipher(c, body.cipher, body.collectionIds ?? [], false)
  }
  if (body.collectionIds?.length) {
    throw new ApiError(400, 'Collections can only be set on organization items.')
  }
  await assertPersonalOwnershipAllowed(createDb(c.env.DB), c.var.user.uuid)
  return next()
})

orgCiphers.post('/api/ciphers/admin', async (c) => {
  const body = await parseBody(c, createSchema)
  if (!body.cipher.organizationId) throw new ApiError(400, 'An organization is required.')
  return createOrgCipher(c, body.cipher, body.collectionIds ?? [], true)
})

orgCiphers.post('/api/ciphers/import', async (c, next) => {
  const body = await parseBody(c, z.object({ ciphers: z.array(z.unknown()).default([]) }))
  if (body.ciphers.length > 0) {
    await assertPersonalOwnershipAllowed(createDb(c.env.DB), c.var.user.uuid)
  }
  return next()
})

const importOrgSchema = z.object({
  ciphers: z.array(cipherSchema).default([]),
  collections: z
    .array(z.object({ name: z.string().min(1), externalId: z.string().nullish() }))
    .default([]),
  collectionRelationships: z
    .array(z.object({ key: z.number().int(), value: z.number().int() }))
    .default([]),
})
orgCiphers.post('/api/ciphers/import-organization', async (c) => {
  const orgUuid = c.req.query('organizationId') ?? ''
  const body = await parseBody(c, importOrgSchema)
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, orgUuid, 'accessImportExport')
  if (body.ciphers.length > 7000)
    throw new ApiError(400, 'You cannot import this much data at once.')
  for (const r of body.collectionRelationships) {
    if (
      r.key < 0 ||
      r.key >= body.ciphers.length ||
      r.value < 0 ||
      r.value >= body.collections.length
    ) {
      throw new ApiError(400, 'Invalid collection relationship.')
    }
  }
  const now = Date.now()
  const collectionIds = body.collections.map(() => crypto.randomUUID())
  const cipherIds = body.ciphers.map(() => crypto.randomUUID())
  await batch(db, [
    ...body.collections.map((col, i) =>
      db.insert(schema.collections).values({
        uuid: collectionIds[i] as string,
        organizationUuid: orgUuid,
        name: col.name,
        externalId: col.externalId ?? null,
        createdAt: now,
        updatedAt: now,
      }),
    ),
    ...body.ciphers.map((ci, i) =>
      db.insert(schema.ciphers).values({
        uuid: cipherIds[i] as string,
        userUuid: null,
        organizationUuid: orgUuid,
        ...cipherValues(ci),
        favorite: false,
        createdAt: now,
        updatedAt: now,
      }),
    ),
    ...body.collectionRelationships.map((r) =>
      db.insert(schema.ciphersCollections).values({
        cipherUuid: cipherIds[r.key] as string,
        collectionUuid: collectionIds[r.value] as string,
      }),
    ),
    bumpOrgRevision(db, orgUuid, now),
  ])
  return c.body(null, 200)
})

// ----- organisation listings -----

orgCiphers.get('/api/ciphers/organization-details', async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = c.req.query('organizationId') ?? ''
  const member = await requireMember(db, c.var.user.uuid, orgUuid)
  if (!canManageAllCiphers(member))
    throw new ApiError(403, 'You do not have permission to do this.')
  const [rows, links, folders] = await Promise.all([
    db.select().from(schema.ciphers).where(eq(schema.ciphers.organizationUuid, orgUuid)),
    db
      .select({
        cipher: schema.ciphersCollections.cipherUuid,
        id: schema.ciphersCollections.collectionUuid,
      })
      .from(schema.ciphersCollections)
      .innerJoin(
        schema.collections,
        eq(schema.collections.uuid, schema.ciphersCollections.collectionUuid),
      )
      .where(eq(schema.collections.organizationUuid, orgUuid)),
    folderLinks(db, c.var.user.uuid),
  ])
  const byCipher = new Map<string, string[]>()
  for (const l of links) byCipher.set(l.cipher, [...(byCipher.get(l.cipher) ?? []), l.id])
  return c.json(
    list(
      rows.map((cipher) =>
        orgCipherJson({
          cipher,
          folderId: folders.get(cipher.uuid) ?? null,
          access: {
            edit: true,
            viewPassword: true,
            manage: true,
            collectionIds: byCipher.get(cipher.uuid) ?? [],
          },
        }),
      ),
    ),
  )
})

orgCiphers.get('/api/ciphers/organization-details/assigned', async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = c.req.query('organizationId') ?? ''
  await requireMember(db, c.var.user.uuid, orgUuid)
  const rows = await listOrgCipherRows(db, c.var.user.uuid)
  return c.json(list(rows.filter((r) => r.cipher.organizationUuid === orgUuid).map(orgCipherJson)))
})

// ----- sharing -----

const shareSchema = z.object({
  cipher: cipherSchema,
  collectionIds: z.array(z.string()).default([]),
})

/** Validates one personal item moving into an organisation and returns its statements. */
async function shareStatements(
  c: Ctx,
  db: Db,
  member: Member,
  id: string,
  body: CipherBody,
  collectionIds: string[],
  now: number,
) {
  const user = c.var.user
  const orgUuid = body.organizationId as string
  const cipher = await loadCipherById(db, id)
  if (!cipher || cipher.userUuid !== user.uuid) throw NOT_FOUND()
  if (cipher.organizationUuid)
    throw new ApiError(400, 'This item already belongs to an organization.')
  checkRevision(cipher, body.lastKnownRevisionDate)
  await assertWritableCollections(db, user.uuid, member, orgUuid, collectionIds)
  return [
    db
      .update(schema.ciphers)
      .set({ ...cipherValues(body), userUuid: null, organizationUuid: orgUuid, updatedAt: now })
      .where(and(eq(schema.ciphers.uuid, id), eq(schema.ciphers.userUuid, user.uuid))),
    ...[...new Set(collectionIds)].map((collectionUuid) =>
      db.insert(schema.ciphersCollections).values({ cipherUuid: id, collectionUuid }),
    ),
    eventStatement(db, c, {
      type: EventType.CipherShared,
      organizationUuid: orgUuid,
      cipherUuid: id,
    }),
  ]
}

async function shareTarget(c: Ctx, db: Db, body: CipherBody, collectionIds: string[]) {
  if (!body.organizationId) throw new ApiError(400, 'An organization is required.')
  if (collectionIds.length === 0)
    throw new ApiError(400, 'You must select at least one collection.')
  return requireMember(db, c.var.user.uuid, body.organizationId)
}

orgCiphers.put('/api/ciphers/share', async (c) => {
  const body = await parseBody(
    c,
    z.object({
      ciphers: z.array(cipherSchema.extend({ id: z.string().min(1) })).max(MAX_BULK),
      collectionIds: z.array(z.string()).default([]),
    }),
  )
  const db = createDb(c.env.DB)
  const first = body.ciphers[0]
  if (!first) return c.json(list([]))
  const orgs = new Set(body.ciphers.map((x) => x.organizationId))
  if (orgs.size !== 1)
    throw new ApiError(400, 'All items must be shared with the same organization.')
  const member = await shareTarget(c, db, first, body.collectionIds)
  const now = Date.now()
  const statements: unknown[] = []
  for (const ci of body.ciphers) {
    statements.push(...(await shareStatements(c, db, member, ci.id, ci, body.collectionIds, now)))
  }
  await batch(db, [
    ...statements,
    bumpRevision(db, c.var.user.uuid, now),
    bumpOrgRevision(db, member.organizationUuid, now),
  ])
  const folders = await folderLinks(db, c.var.user.uuid)
  const ua = await loadUserAccess(db, c.var.user.uuid)
  const out = []
  for (const ci of body.ciphers) {
    const cipher = await loadCipherById(db, ci.id)
    const access =
      cipher && itemAccess(ua, member.organizationUuid, await linkedCollections(db, ci.id))
    if (cipher && access)
      out.push(orgCipherJson({ cipher, folderId: folders.get(ci.id) ?? null, access }))
  }
  return c.json(list(out))
})

const shareOne = async (c: Ctx) => {
  const id = idParam(c)
  const body = await parseBody(c, shareSchema)
  const db = createDb(c.env.DB)
  const member = await shareTarget(c, db, body.cipher, body.collectionIds)
  const now = Date.now()
  await batch(db, [
    ...(await shareStatements(c, db, member, id, body.cipher, body.collectionIds, now)),
    bumpRevision(db, c.var.user.uuid, now),
    bumpOrgRevision(db, member.organizationUuid, now),
  ])
  return respond(c, id, false)
}

// ----- bulk delete, restore and move (static paths before `/:id`) -----

const bulkSchema = z.object({
  ids: z.array(z.string()).max(MAX_BULK).default([]),
  organizationId: z.string().nullish(),
})
type BulkOp = 'soft' | 'restore' | 'hard'
const OP_EVENT = {
  soft: EventType.CipherSoftDeleted,
  restore: EventType.CipherRestored,
  hard: EventType.CipherDeleted,
}

async function loadMany(db: Db, ids: string[]): Promise<CipherRecord[]> {
  const found: CipherRecord[] = []
  for (const part of chunk([...new Set(ids)])) {
    found.push(
      ...(await db.select().from(schema.ciphers).where(inArray(schema.ciphers.uuid, part))),
    )
  }
  if (found.length !== new Set(ids).size) throw NOT_FOUND()
  return found
}

function bulk(op: BulkOp, admin: boolean, respondList: boolean) {
  return async (c: Ctx, next: Next) => {
    const body = await parseBody(c, bulkSchema)
    const db = createDb(c.env.DB)
    const user = c.var.user
    if (!admin && body.ids.length === 0) return next()
    const rows = body.ids.length ? await loadMany(db, body.ids) : []
    if (!admin && !rows.some((r) => r.organizationUuid)) return next()

    let adminMember: Member | undefined
    if (admin) {
      if (!body.organizationId) throw new ApiError(400, 'An organization is required.')
      adminMember = await requireMember(db, user.uuid, body.organizationId)
      if (!canManageAllCiphers(adminMember))
        throw new ApiError(403, 'You do not have permission to do this.')
    }
    const ua = admin ? null : await loadUserAccess(db, user.uuid)
    const orgs = new Set<string>()
    for (const row of rows) {
      if (admin) {
        if (row.organizationUuid !== body.organizationId) throw NOT_FOUND()
      } else if (!row.organizationUuid) {
        if (row.userUuid !== user.uuid) throw NOT_FOUND()
        continue
      } else {
        const a = ua && itemAccess(ua, row.organizationUuid, await linkedCollections(db, row.uuid))
        if (!a) throw NOT_FOUND()
        if (!canDelete(a)) throw new ApiError(403, 'You do not have permission to do this.')
      }
      orgs.add(row.organizationUuid as string)
    }
    const now = Date.now()
    const ids = rows.map((r) => r.uuid)
    await batch(db, [
      ...chunk(ids).map((part) =>
        op === 'hard'
          ? db.delete(schema.ciphers).where(inArray(schema.ciphers.uuid, part))
          : db
              .update(schema.ciphers)
              .set({ deletedAt: op === 'soft' ? now : null, updatedAt: now })
              .where(inArray(schema.ciphers.uuid, part)),
      ),
      ...rows
        .filter((r) => r.organizationUuid)
        .map((r) =>
          eventStatement(db, c, {
            type: OP_EVENT[op],
            organizationUuid: r.organizationUuid,
            cipherUuid: r.uuid,
          }),
        ),
      bumpRevision(db, user.uuid, now),
      ...[...orgs].map((o) => bumpOrgRevision(db, o, now)),
    ])
    if (!respondList) return c.body(null, 200)
    const fresh = await loadMany(db, ids)
    const folders = await folderLinks(db, user.uuid)
    const accessUa = await loadUserAccess(db, user.uuid)
    const out = []
    for (const cipher of fresh) {
      const folderId = folders.get(cipher.uuid) ?? null
      if (!cipher.organizationUuid) {
        out.push(cipherJson({ cipher, folderId }))
        continue
      }
      const access = admin
        ? await adminItemAccess(db, cipher)
        : itemAccess(accessUa, cipher.organizationUuid, await linkedCollections(db, cipher.uuid))
      if (access) out.push(orgCipherJson({ cipher, folderId, access }))
    }
    return c.json(list(out))
  }
}

orgCiphers.put('/api/ciphers/delete', bulk('soft', false, false))
orgCiphers.post('/api/ciphers/delete', bulk('hard', false, false))
orgCiphers.delete('/api/ciphers', bulk('hard', false, false))
orgCiphers.put('/api/ciphers/restore', bulk('restore', false, true))
orgCiphers.put('/api/ciphers/delete-admin', bulk('soft', true, false))
orgCiphers.delete('/api/ciphers/admin', bulk('hard', true, false))
orgCiphers.put('/api/ciphers/restore-admin', bulk('restore', true, true))

orgCiphers.put('/api/ciphers/move', async (c, next) => {
  const body = await parseBody(
    c,
    z.object({
      ids: z.array(z.string()).max(MAX_BULK).default([]),
      folderId: z.string().nullish(),
    }),
  )
  const db = createDb(c.env.DB)
  const user = c.var.user
  if (body.ids.length === 0) return next()
  const rows = await loadMany(db, body.ids)
  if (!rows.some((r) => r.organizationUuid)) return next()
  if (body.folderId) await requireFolder(db, user.uuid, body.folderId)
  const ua = await loadUserAccess(db, user.uuid)
  const now = Date.now()
  const statements: unknown[] = []
  for (const row of rows) {
    if (!row.organizationUuid) {
      if (row.userUuid !== user.uuid) throw NOT_FOUND()
      statements.push(
        ...setFolderStatements(db, row.uuid, body.folderId ?? null),
        db.update(schema.ciphers).set({ updatedAt: now }).where(eq(schema.ciphers.uuid, row.uuid)),
      )
    } else {
      if (!itemAccess(ua, row.organizationUuid, await linkedCollections(db, row.uuid)))
        throw NOT_FOUND()
      // A folder is private to its owner, so moving an organisation item changes nothing for others.
      statements.push(...userFolderStatements(db, user.uuid, row.uuid, body.folderId ?? null))
    }
  }
  await batch(db, [...statements, bumpRevision(db, user.uuid, now)])
  return c.body(null, 204)
})

orgCiphers.post('/api/ciphers/purge', async (c, next) => {
  const orgUuid = c.req.query('organizationId')
  if (!orgUuid) return next()
  const { masterPasswordHash } = await parseBody(
    c,
    z.object({ masterPasswordHash: z.string().min(1) }),
  )
  const db = createDb(c.env.DB)
  await requireOwner(db, c.var.user.uuid, orgUuid)
  if (!(await verifyMasterPassword(c.var.user, masterPasswordHash))) {
    throw new ApiError(400, 'Invalid password.', { masterPasswordHash: ['Invalid password.'] })
  }
  await batch(db, [
    bumpOrgRevision(db, orgUuid, Date.now()),
    db.delete(schema.ciphers).where(eq(schema.ciphers.organizationUuid, orgUuid)),
  ])
  return c.body(null, 200)
})

orgCiphers.post('/api/ciphers/bulk-collections', async (c) => {
  const body = await parseBody(
    c,
    z.object({
      organizationId: z.string().min(1),
      cipherIds: z.array(z.string()).min(1).max(MAX_BULK),
      collectionIds: z.array(z.string()).min(1),
      removeCollections: z.boolean().nullish(),
    }),
  )
  const db = createDb(c.env.DB)
  const user = c.var.user
  const member = await requireMember(db, user.uuid, body.organizationId)
  await assertWritableCollections(db, user.uuid, member, body.organizationId, body.collectionIds)
  const rows = await loadMany(db, body.cipherIds)
  const ua = await loadUserAccess(db, user.uuid)
  for (const row of rows) {
    if (row.organizationUuid !== body.organizationId) throw NOT_FOUND()
    const a = itemAccess(ua, body.organizationId, await linkedCollections(db, row.uuid))
    if (!a && !canManageAllCiphers(member)) throw NOT_FOUND()
    if (a && !a.manage && !canManageAllCiphers(member))
      throw new ApiError(403, 'You do not have permission to do this.')
  }
  const now = Date.now()
  const collections = [...new Set(body.collectionIds)]
  await batch(db, [
    ...rows.flatMap((row): unknown[] =>
      body.removeCollections
        ? [
            db
              .delete(schema.ciphersCollections)
              .where(
                and(
                  eq(schema.ciphersCollections.cipherUuid, row.uuid),
                  inArray(schema.ciphersCollections.collectionUuid, collections),
                ),
              ),
          ]
        : collections.map((collectionUuid) =>
            db
              .insert(schema.ciphersCollections)
              .values({ cipherUuid: row.uuid, collectionUuid })
              .onConflictDoNothing(),
          ),
    ),
    ...rows.map((row) =>
      eventStatement(db, c, {
        type: EventType.CipherUpdatedCollections,
        organizationUuid: body.organizationId,
        cipherUuid: row.uuid,
      }),
    ),
    db
      .update(schema.ciphers)
      .set({ updatedAt: now })
      .where(
        inArray(
          schema.ciphers.uuid,
          rows.map((r) => r.uuid),
        ),
      ),
    bumpOrgRevision(db, body.organizationId, now),
  ])
  return c.body(null, 200)
})

// ----- single items -----

orgCiphers.put('/api/ciphers/:id/share', shareOne)
orgCiphers.post('/api/ciphers/:id/share', shareOne)

const getOne = (admin: boolean) => async (c: Ctx, next: Next) =>
  (await resolve(c, idParam(c), admin)) ? respond(c, idParam(c), admin) : next()
orgCiphers.get('/api/ciphers/:id', getOne(false))
orgCiphers.get('/api/ciphers/:id/details', getOne(false))
orgCiphers.get('/api/ciphers/:id/admin', getOne(true))

const update = (admin: boolean) => async (c: Ctx, next: Next) => {
  const id = idParam(c)
  const r = await resolve(c, id, admin)
  if (!r) return next()
  if (!r.access.edit) throw new ApiError(403, 'You do not have permission to edit this item.')
  const body = await parseBody(c, cipherSchema)
  const db = createDb(c.env.DB)
  const user = c.var.user
  checkRevision(r.cipher, body.lastKnownRevisionDate)
  if (body.folderId) await requireFolder(db, user.uuid, body.folderId)
  const orgUuid = r.cipher.organizationUuid as string
  const now = Date.now()
  await batch(db, [
    db
      .update(schema.ciphers)
      // Favorites are stored on the item, so an update never changes them for other members.
      .set({ ...cipherValues(body), favorite: r.cipher.favorite, updatedAt: now })
      .where(eq(schema.ciphers.uuid, id)),
    ...(admin ? [] : userFolderStatements(db, user.uuid, id, body.folderId ?? null)),
    eventStatement(db, c, {
      type: EventType.CipherUpdated,
      organizationUuid: orgUuid,
      cipherUuid: id,
    }),
    bumpOrgRevision(db, orgUuid, now),
  ])
  return respond(c, id, admin)
}
orgCiphers.put('/api/ciphers/:id', update(false))
orgCiphers.post('/api/ciphers/:id', update(false))
orgCiphers.put('/api/ciphers/:id/admin', update(true))
orgCiphers.post('/api/ciphers/:id/admin', update(true))

const partial = async (c: Ctx, next: Next) => {
  const id = idParam(c)
  const r = await resolve(c, id, false)
  if (!r) return next()
  const body = await parseBody(
    c,
    z.object({ folderId: z.string().nullish(), favorite: z.boolean() }),
  )
  const db = createDb(c.env.DB)
  if (body.folderId) await requireFolder(db, c.var.user.uuid, body.folderId)
  await batch(db, [
    ...userFolderStatements(db, c.var.user.uuid, id, body.folderId ?? null),
    bumpRevision(db, c.var.user.uuid, Date.now()),
  ])
  return respond(c, id, false)
}
orgCiphers.put('/api/ciphers/:id/partial', partial)
orgCiphers.post('/api/ciphers/:id/partial', partial)

/** Single-item delete, soft delete and restore, in personal-path and admin forms. */
function single(op: BulkOp, admin: boolean, respondItem: boolean) {
  return async (c: Ctx, next: Next) => {
    const id = idParam(c)
    const r = await resolve(c, id, admin)
    if (!r) return next()
    if (!canDelete(r.access)) throw new ApiError(403, 'You do not have permission to do this.')
    const db = createDb(c.env.DB)
    const orgUuid = r.cipher.organizationUuid as string
    const now = Date.now()
    await batch(db, [
      op === 'hard'
        ? db.delete(schema.ciphers).where(eq(schema.ciphers.uuid, id))
        : db
            .update(schema.ciphers)
            .set({ deletedAt: op === 'soft' ? now : null, updatedAt: now })
            .where(eq(schema.ciphers.uuid, id)),
      eventStatement(db, c, { type: OP_EVENT[op], organizationUuid: orgUuid, cipherUuid: id }),
      bumpOrgRevision(db, orgUuid, now),
    ])
    return respondItem ? respond(c, id, admin) : c.body(null, 200)
  }
}
orgCiphers.delete('/api/ciphers/:id', single('hard', false, false))
orgCiphers.post('/api/ciphers/:id/delete', single('hard', false, false))
orgCiphers.delete('/api/ciphers/:id/admin', single('hard', true, false))
orgCiphers.put('/api/ciphers/:id/delete', single('soft', false, false))
orgCiphers.put('/api/ciphers/:id/delete-admin', single('soft', true, false))
orgCiphers.put('/api/ciphers/:id/restore', single('restore', false, true))
orgCiphers.put('/api/ciphers/:id/restore-admin', single('restore', true, true))

// ----- collections of an item -----

const collectionsSchema = z.object({ collectionIds: z.array(z.string()) })

/** Replaces the collections of an item that the caller is allowed to change; others are kept. */
const setCollections = (admin: boolean, v2: boolean) => async (c: Ctx, next: Next) => {
  const id = idParam(c)
  const r = await resolve(c, id, admin)
  if (!r) return next()
  const body = await parseBody(c, collectionsSchema)
  const db = createDb(c.env.DB)
  const user = c.var.user
  const orgUuid = r.cipher.organizationUuid as string
  const member = r.member ?? (await requireMember(db, user.uuid, orgUuid))
  const manager = canManageAllCiphers(member)
  if (!r.access.manage && !manager) {
    throw new ApiError(403, 'You need manage access to change the collections of an item.')
  }
  if (body.collectionIds.length === 0 && !manager) {
    throw new ApiError(400, 'You must select at least one collection.')
  }
  const wanted = [...new Set(body.collectionIds)]
  await assertWritableCollections(db, user.uuid, member, orgUuid, wanted)

  // Collections the caller cannot write to stay linked; the rest follow the request.
  const current = await linkedCollections(db, id)
  const ua = manager ? null : await loadUserAccess(db, user.uuid)
  const writable = (col: string) => manager || (ua !== null && !isReadOnly(ua, orgUuid, col))
  const kept = current.filter((col) => !writable(col))
  const now = Date.now()
  await batch(db, [
    db.delete(schema.ciphersCollections).where(eq(schema.ciphersCollections.cipherUuid, id)),
    ...[...new Set([...kept, ...wanted])].map((collectionUuid) =>
      db.insert(schema.ciphersCollections).values({ cipherUuid: id, collectionUuid }),
    ),
    db.update(schema.ciphers).set({ updatedAt: now }).where(eq(schema.ciphers.uuid, id)),
    eventStatement(db, c, {
      type: EventType.CipherUpdatedCollections,
      organizationUuid: orgUuid,
      cipherUuid: id,
    }),
    bumpOrgRevision(db, orgUuid, now),
  ])
  if (admin) return c.body(null, 200)
  if (!v2) return respond(c, id, admin)
  // The caller may have just removed their own access to the item.
  const still = await accessToCipher(db, user.uuid, r.cipher)
  if (!still) return c.json({ unavailable: true, cipher: null })
  return c.json({ unavailable: false, cipher: await (await respond(c, id, admin)).json() })
}

function isReadOnly(ua: Awaited<ReturnType<typeof loadUserAccess>>, orgUuid: string, col: string) {
  if (ua.accessAllOrgs.has(orgUuid)) return false
  return ua.grants.get(col)?.readOnly ?? true
}

orgCiphers.put('/api/ciphers/:id/collections', setCollections(false, false))
orgCiphers.post('/api/ciphers/:id/collections', setCollections(false, false))
orgCiphers.put('/api/ciphers/:id/collections_v2', setCollections(false, true))
orgCiphers.post('/api/ciphers/:id/collections_v2', setCollections(false, true))
orgCiphers.put('/api/ciphers/:id/collections-admin', setCollections(true, false))
orgCiphers.post('/api/ciphers/:id/collections-admin', setCollections(true, false))
