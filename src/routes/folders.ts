import { and, eq, sql } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { requireAuth } from '../auth/middleware'
import { createDb, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { parseBody } from '../validation'
import { bumpRevision } from '../vault/ciphers'
import { folderJson } from '../vault/folders'

export const folders = new Hono<Env>()
folders.use('/api/folders', requireAuth)
folders.use('/api/folders/*', requireAuth)

type Ctx = Context<Env>

const bodySchema = z.object({ name: z.string().min(1) })

async function requireFolderRow(c: Ctx, id: string) {
  const [f] = await createDb(c.env.DB)
    .select()
    .from(schema.folders)
    .where(and(eq(schema.folders.uuid, id), eq(schema.folders.userUuid, c.var.user.uuid)))
    .limit(1)
  if (!f) throw new ApiError(404, 'Folder not found.')
  return f
}

folders.get('/api/folders', async (c) => {
  const rows = await createDb(c.env.DB)
    .select()
    .from(schema.folders)
    .where(eq(schema.folders.userUuid, c.var.user.uuid))
  return c.json({ data: rows.map(folderJson), object: 'list', continuationToken: null })
})

folders.get('/api/folders/:id', async (c) =>
  c.json(folderJson(await requireFolderRow(c, c.req.param('id')))),
)

folders.post('/api/folders', async (c) => {
  const { name } = await parseBody(c, bodySchema)
  const db = createDb(c.env.DB)
  const now = Date.now()
  const uuid = crypto.randomUUID()
  await runBatch(db, [
    db
      .insert(schema.folders)
      .values({ uuid, userUuid: c.var.user.uuid, name, createdAt: now, updatedAt: now }),
    bumpRevision(db, c.var.user.uuid, now),
  ])
  return c.json(folderJson(await requireFolderRow(c, uuid)))
})

const rename = async (c: Ctx) => {
  const id = c.req.param('id') ?? ''
  const { name } = await parseBody(c, bodySchema)
  await requireFolderRow(c, id)
  const db = createDb(c.env.DB)
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.folders)
      .set({ name, updatedAt: now })
      .where(and(eq(schema.folders.uuid, id), eq(schema.folders.userUuid, c.var.user.uuid))),
    bumpRevision(db, c.var.user.uuid, now),
  ])
  return c.json(folderJson(await requireFolderRow(c, id)))
}
folders.put('/api/folders/:id', rename)
folders.post('/api/folders/:id', rename)

// Ciphers in the folder are kept and become unfiled: only the link rows go.
const remove = async (c: Ctx) => {
  const id = c.req.param('id') ?? ''
  await requireFolderRow(c, id)
  const db = createDb(c.env.DB)
  await runBatch(db, [
    db
      .delete(schema.foldersCiphers)
      .where(
        and(
          eq(schema.foldersCiphers.folderUuid, id),
          sql`exists (select 1 from folders where uuid = ${id} and user_uuid = ${c.var.user.uuid})`,
        ),
      ),
    db
      .delete(schema.folders)
      .where(and(eq(schema.folders.uuid, id), eq(schema.folders.userUuid, c.var.user.uuid))),
    bumpRevision(db, c.var.user.uuid, Date.now()),
  ])
  return c.body(null, 200)
}
folders.delete('/api/folders/:id', remove)
folders.post('/api/folders/:id/delete', remove)
