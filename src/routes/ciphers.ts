import { and, eq, inArray, sql } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { requireAuth } from '../auth/middleware'
import { verifyMasterPassword } from '../auth/passwords'
import { changes, createDb, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { rateLimit } from '../ratelimit'
import { parseBody } from '../validation'
import {
  bumpRevision,
  type CipherBody,
  checkRevision,
  chunk,
  cipherJson,
  cipherSchema,
  cipherValues,
  listCipherRows,
  rejectUnsupported,
  requireCipher,
  requireFolder,
  STALE_MESSAGE,
  setFolderStatements,
  setFolderStatementsIfAt,
  stillAt,
} from '../vault/ciphers'

export const ciphers = new Hono<Env>()
ciphers.use('/api/ciphers', requireAuth)
ciphers.use('/api/ciphers/*', requireAuth)

type Ctx = Context<Env>

const list = (rows: ReturnType<typeof cipherJson>[]) => ({
  data: rows,
  object: 'list',
  continuationToken: null,
})

async function respond(c: Ctx, id: string) {
  const row = await requireCipher(createDb(c.env.DB), c.var.user.uuid, id)
  return c.json(cipherJson(row))
}

async function createCipher(c: Ctx, body: CipherBody) {
  rejectUnsupported(body)
  const db = createDb(c.env.DB)
  const user = c.var.user
  if (body.folderId) await requireFolder(db, user.uuid, body.folderId)
  const id = crypto.randomUUID()
  const now = Date.now()
  await runBatch(db, [
    db.insert(schema.ciphers).values({
      uuid: id,
      userUuid: user.uuid,
      ...cipherValues(body),
      createdAt: now,
      updatedAt: now,
    }),
    ...setFolderStatements(db, id, body.folderId ?? null).slice(1),
    bumpRevision(db, user.uuid, now),
  ])
  return respond(c, id)
}

ciphers.post('/api/ciphers', async (c) => createCipher(c, await parseBody(c, cipherSchema)))

// Create with collection ids: the cipher is nested under `cipher`.
const createWithCollections = z.object({
  cipher: cipherSchema,
  collectionIds: z.array(z.string()).nullish(),
})
ciphers.post('/api/ciphers/create', async (c) => {
  const body = await parseBody(c, createWithCollections)
  // TODO(TASKS #62): collections arrive with Phase 3; personal ciphers have none.
  if (body.collectionIds?.length) throw new ApiError(400, 'Collections are not supported yet.')
  return createCipher(c, body.cipher)
})

// Import: folders, ciphers and a list of (cipher index, folder index) pairs, in one batch.
const importSchema = z.object({
  folders: z.array(z.object({ name: z.string().min(1) })).default([]),
  ciphers: z.array(cipherSchema).default([]),
  folderRelationships: z
    .array(z.object({ key: z.number().int(), value: z.number().int() }))
    .default([]),
})
// D1 allows 1000 queries per Worker invocation (paid plan; 50 on free). One batch statement
// counts as one query, so an import is capped well below that: folders + ciphers + links.
const MAX_IMPORT_STATEMENTS = 900
const MAX_IMPORT_FOLDERS = 200
ciphers.post('/api/ciphers/import', async (c) => {
  const body = await parseBody(c, importSchema)
  const linked = new Set(body.folderRelationships.map((r) => r.key)).size
  if (
    body.folders.length > MAX_IMPORT_FOLDERS ||
    body.folders.length + body.ciphers.length + linked + 1 > MAX_IMPORT_STATEMENTS
  ) {
    throw new ApiError(400, 'You cannot import this much data at once.')
  }
  for (const r of body.folderRelationships) {
    if (
      r.key < 0 ||
      r.key >= body.ciphers.length ||
      r.value < 0 ||
      r.value >= body.folders.length
    ) {
      throw new ApiError(400, 'Invalid folder relationship.')
    }
  }
  for (const ci of body.ciphers) rejectUnsupported(ci)
  const db = createDb(c.env.DB)
  const user = c.var.user
  const now = Date.now()
  const folderIds = body.folders.map(() => crypto.randomUUID())
  const cipherIds = body.ciphers.map(() => crypto.randomUUID())
  const folderOf = new Map(
    body.folderRelationships.map((r) => [r.key, folderIds[r.value] as string]),
  )
  await runBatch(db, [
    ...body.folders.map((f, i) =>
      db.insert(schema.folders).values({
        uuid: folderIds[i] as string,
        userUuid: user.uuid,
        name: f.name,
        createdAt: now,
        updatedAt: now,
      }),
    ),
    ...body.ciphers.map((ci, i) =>
      db.insert(schema.ciphers).values({
        uuid: cipherIds[i] as string,
        userUuid: user.uuid,
        ...cipherValues(ci),
        createdAt: now,
        updatedAt: now,
      }),
    ),
    ...[...folderOf].map(([i, folderUuid]) =>
      db.insert(schema.foldersCiphers).values({ cipherUuid: cipherIds[i] as string, folderUuid }),
    ),
    bumpRevision(db, user.uuid, now),
  ])
  return c.body(null, 200)
})

// Bulk operations. Static paths are registered before `/:id`.
const idsSchema = z.object({ ids: z.array(z.string()).default([]) })
const MAX_BULK = 500

async function ownedIds(c: Ctx, ids: string[]): Promise<string[]> {
  if (ids.length > MAX_BULK) throw new ApiError(400, 'Too many ciphers in one request.')
  const db = createDb(c.env.DB)
  const found: string[] = []
  for (const part of chunk(ids)) {
    const rows = await db
      .select({ id: schema.ciphers.uuid })
      .from(schema.ciphers)
      .where(and(eq(schema.ciphers.userUuid, c.var.user.uuid), inArray(schema.ciphers.uuid, part)))
    found.push(...rows.map((r) => r.id))
  }
  if (new Set(found).size !== new Set(ids).size) throw new ApiError(404, 'Cipher not found.')
  return found
}

ciphers.put('/api/ciphers/move', async (c) => {
  const body = await parseBody(c, idsSchema.extend({ folderId: z.string().nullish() }))
  const db = createDb(c.env.DB)
  if (body.folderId) await requireFolder(db, c.var.user.uuid, body.folderId)
  const ids = await ownedIds(c, body.ids)
  const now = Date.now()
  await runBatch(db, [
    ...chunk(ids).map((part) =>
      db.delete(schema.foldersCiphers).where(inArray(schema.foldersCiphers.cipherUuid, part)),
    ),
    ...(body.folderId
      ? ids.map((id) =>
          db
            .insert(schema.foldersCiphers)
            .values({ cipherUuid: id, folderUuid: body.folderId as string }),
        )
      : []),
    ...chunk(ids).map((part) =>
      db
        .update(schema.ciphers)
        .set({ updatedAt: now })
        .where(
          and(eq(schema.ciphers.userUuid, c.var.user.uuid), inArray(schema.ciphers.uuid, part)),
        ),
    ),
    bumpRevision(db, c.var.user.uuid, now),
  ])
  return c.body(null, 204)
})

const hardDelete = async (c: Ctx) => {
  const { ids } = await parseBody(c, idsSchema)
  const owned = await ownedIds(c, ids)
  const db = createDb(c.env.DB)
  await runBatch(db, [
    ...chunk(owned).map((part) =>
      db
        .delete(schema.ciphers)
        .where(
          and(eq(schema.ciphers.userUuid, c.var.user.uuid), inArray(schema.ciphers.uuid, part)),
        ),
    ),
    bumpRevision(db, c.var.user.uuid, Date.now()),
  ])
  return c.body(null, 200)
}
ciphers.post('/api/ciphers/delete', hardDelete)
ciphers.delete('/api/ciphers', hardDelete)

async function setDeleted(c: Ctx, ids: string[], deletedAt: number | null) {
  const owned = await ownedIds(c, ids)
  const db = createDb(c.env.DB)
  const now = Date.now()
  await runBatch(db, [
    ...chunk(owned).map((part) =>
      db
        .update(schema.ciphers)
        .set({
          // Keep the original deletion time when deleting an already deleted cipher.
          deletedAt:
            deletedAt === null ? null : sql`coalesce(${schema.ciphers.deletedAt}, ${deletedAt})`,
          updatedAt: now,
        })
        .where(
          and(eq(schema.ciphers.userUuid, c.var.user.uuid), inArray(schema.ciphers.uuid, part)),
        ),
    ),
    bumpRevision(db, c.var.user.uuid, now),
  ])
  return owned
}

ciphers.put('/api/ciphers/delete', async (c) => {
  const { ids } = await parseBody(c, idsSchema)
  await setDeleted(c, ids, Date.now())
  return c.body(null, 200)
})

ciphers.put('/api/ciphers/restore', async (c) => {
  const { ids } = await parseBody(c, idsSchema)
  const restored = new Set(await setDeleted(c, ids, null))
  const rows = (await listCipherRows(createDb(c.env.DB), c.var.user.uuid)).filter((r) =>
    restored.has(r.cipher.uuid),
  )
  return c.json(list(rows.map(cipherJson)))
})

// Purge removes every personal cipher and folder after re-verifying the master password.
ciphers.post('/api/ciphers/purge', rateLimit('purge'), async (c) => {
  const { masterPasswordHash } = await parseBody(
    c,
    z.object({ masterPasswordHash: z.string().min(1) }),
  )
  const user = c.var.user
  if (!(await verifyMasterPassword(user, masterPasswordHash))) {
    throw new ApiError(400, 'Invalid password.', { masterPasswordHash: ['Invalid password.'] })
  }
  const db = createDb(c.env.DB)
  await runBatch(db, [
    db.delete(schema.ciphers).where(eq(schema.ciphers.userUuid, user.uuid)),
    db.delete(schema.folders).where(eq(schema.folders.userUuid, user.uuid)),
    // TODO(TASKS #80): also remove attachment and Send blobs from R2.
    db.delete(schema.sends).where(eq(schema.sends.userUuid, user.uuid)),
    bumpRevision(db, user.uuid, Date.now()),
  ])
  return c.body(null, 200)
})

ciphers.get('/api/ciphers', async (c) =>
  c.json(list((await listCipherRows(createDb(c.env.DB), c.var.user.uuid)).map(cipherJson))),
)

ciphers.get('/api/ciphers/:id', (c) => respond(c, c.req.param('id')))
ciphers.get('/api/ciphers/:id/details', (c) => respond(c, c.req.param('id')))

const updateCipher = async (c: Ctx) => {
  const id = c.req.param('id') ?? ''
  const body = await parseBody(c, cipherSchema)
  rejectUnsupported(body)
  const db = createDb(c.env.DB)
  const user = c.var.user
  const existing = await requireCipher(db, user.uuid, id)
  checkRevision(existing.cipher, body.lastKnownRevisionDate)
  if (body.folderId) await requireFolder(db, user.uuid, body.folderId)
  // The write only applies if nobody changed the cipher since it was read; otherwise the
  // client copy is stale. A client that omits lastKnownRevisionDate skips the comparison
  // above but still cannot overwrite a concurrent write.
  const ts = Math.max(Date.now(), existing.cipher.updatedAt + 1)
  const results = await runBatch(db, [
    db
      .update(schema.ciphers)
      .set({ ...cipherValues(body), updatedAt: ts })
      .where(
        and(
          eq(schema.ciphers.uuid, id),
          eq(schema.ciphers.userUuid, user.uuid),
          eq(schema.ciphers.updatedAt, existing.cipher.updatedAt),
        ),
      ),
    ...setFolderStatementsIfAt(db, id, body.folderId ?? null, ts),
    bumpRevision(db, user.uuid, ts, stillAt(id, ts)),
  ])
  if (changes(results[0]) === 0) throw new ApiError(400, STALE_MESSAGE)
  return respond(c, id)
}
ciphers.put('/api/ciphers/:id', updateCipher)
ciphers.post('/api/ciphers/:id', updateCipher)

const partialSchema = z.object({ folderId: z.string().nullish(), favorite: z.boolean() })
const partial = async (c: Ctx) => {
  const id = c.req.param('id') ?? ''
  const body = await parseBody(c, partialSchema)
  const db = createDb(c.env.DB)
  const user = c.var.user
  await requireCipher(db, user.uuid, id)
  if (body.folderId) await requireFolder(db, user.uuid, body.folderId)
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.ciphers)
      .set({ favorite: body.favorite, updatedAt: now })
      .where(and(eq(schema.ciphers.uuid, id), eq(schema.ciphers.userUuid, user.uuid))),
    ...setFolderStatements(db, id, body.folderId ?? null),
    bumpRevision(db, user.uuid, now),
  ])
  return respond(c, id)
}
ciphers.put('/api/ciphers/:id/partial', partial)
ciphers.post('/api/ciphers/:id/partial', partial)

const removeOne = async (c: Ctx) => {
  const id = c.req.param('id') ?? ''
  const db = createDb(c.env.DB)
  await requireCipher(db, c.var.user.uuid, id)
  await runBatch(db, [
    db
      .delete(schema.ciphers)
      .where(and(eq(schema.ciphers.uuid, id), eq(schema.ciphers.userUuid, c.var.user.uuid))),
    bumpRevision(db, c.var.user.uuid, Date.now()),
  ])
  return c.body(null, 200)
}
ciphers.delete('/api/ciphers/:id', removeOne)
ciphers.post('/api/ciphers/:id/delete', removeOne)

ciphers.put('/api/ciphers/:id/delete', async (c) => {
  await setDeleted(c, [c.req.param('id') ?? ''], Date.now())
  return c.body(null, 200)
})

ciphers.put('/api/ciphers/:id/restore', async (c) => {
  const id = c.req.param('id') ?? ''
  await setDeleted(c, [id], null)
  return respond(c, id)
})
