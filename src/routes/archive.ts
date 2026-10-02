import { and, eq, inArray, sql } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { PushType } from '../notifications/publish'
import { notifyCiphers } from '../notifications/vault-events'
import { loadUserAccess } from '../orgs/access'
import {
  accessToCipher,
  folderLinks,
  type ItemAccess,
  orgCipherJson,
  setUserStateStatement,
  userCipherStates,
} from '../orgs/ciphers'
import { authOnce, batch } from '../orgs/util'
import { parseBody } from '../validation'
import { attachmentsByCipher } from '../vault/attachments'
import { bumpRevision, chunk, cipherJson } from '../vault/ciphers'

/**
 * Archive and unarchive (the vault "Archive" feature). Archiving is a personal choice: for a
 * personal item it is stored on the item, for an organisation item per member, so one member
 * archiving never hides the item from the others. Mounted before the cipher routers because the
 * id lists may mix both kinds.
 */
export const archive = new Hono<Env>()
archive.use('/api/ciphers/archive', authOnce)
archive.use('/api/ciphers/unarchive', authOnce)
archive.use('/api/ciphers/:id/archive', authOnce)
archive.use('/api/ciphers/:id/unarchive', authOnce)

type Ctx = Context<Env>
type CipherRecord = typeof schema.ciphers.$inferSelect

const MAX_BULK = 500
const idsSchema = z.object({ ids: z.array(z.string()).max(MAX_BULK).default([]) })

interface Reachable {
  cipher: CipherRecord
  access: ItemAccess | null
}

/** The items the caller may archive: their own and the organisation items they can see. */
async function reachable(c: Ctx, db: Db, ids: string[]): Promise<Reachable[]> {
  const unique = [...new Set(ids)]
  const rows: CipherRecord[] = []
  for (const part of chunk(unique)) {
    rows.push(...(await db.select().from(schema.ciphers).where(inArray(schema.ciphers.uuid, part))))
  }
  if (rows.length !== unique.length) throw new ApiError(404, 'Cipher not found.')
  const ua = rows.some((r) => r.organizationUuid)
    ? await loadUserAccess(db, c.var.user.uuid)
    : undefined
  const out: Reachable[] = []
  for (const cipher of rows) {
    if (!cipher.organizationUuid) {
      if (cipher.userUuid !== c.var.user.uuid) throw new ApiError(404, 'Cipher not found.')
      out.push({ cipher, access: null })
      continue
    }
    const access = await accessToCipher(db, c.var.user.uuid, cipher, ua)
    if (!access) throw new ApiError(404, 'Cipher not found.')
    out.push({ cipher, access })
  }
  return out
}

async function setArchived(c: Ctx, ids: string[], archived: boolean): Promise<unknown[]> {
  const db = createDb(c.env.DB)
  const user = c.var.user
  const items = await reachable(c, db, ids)
  const now = Date.now()
  const personal = items.filter((i) => !i.access).map((i) => i.cipher.uuid)
  await batch(db, [
    ...chunk(personal).map((part) =>
      db
        .update(schema.ciphers)
        .set({
          // An item that is already archived keeps its original date.
          archivedAt: archived ? sql`coalesce(${schema.ciphers.archivedAt}, ${now})` : null,
          updatedAt: now,
        })
        .where(and(eq(schema.ciphers.userUuid, user.uuid), inArray(schema.ciphers.uuid, part))),
    ),
    ...items
      .filter((i) => i.access)
      .map((i) =>
        archived
          ? db
              .insert(schema.cipherUserState)
              .values({ userUuid: user.uuid, cipherUuid: i.cipher.uuid, archivedAt: now })
              .onConflictDoUpdate({
                target: [schema.cipherUserState.userUuid, schema.cipherUserState.cipherUuid],
                set: { archivedAt: sql`coalesce(${schema.cipherUserState.archivedAt}, ${now})` },
              })
          : setUserStateStatement(db, user.uuid, i.cipher.uuid, { archivedAt: null }),
      ),
    bumpRevision(db, user.uuid, now),
  ])
  notifyCiphers(c, PushType.SyncCipherUpdate, [...new Set(ids)], now)
  return respondItems(c, db, [...new Set(ids)])
}

async function respondItems(c: Ctx, db: Db, ids: string[]): Promise<unknown[]> {
  const items = await reachable(c, db, ids)
  const [folders, states, attachments] = await Promise.all([
    folderLinks(db, c.var.user.uuid),
    userCipherStates(db, c.var.user.uuid),
    attachmentsByCipher(
      c.env,
      db,
      items.map((i) => i.cipher.uuid),
    ),
  ])
  return items.map(({ cipher, access }) => {
    const files = attachments.get(cipher.uuid) ?? null
    if (access) {
      return orgCipherJson(
        {
          cipher,
          folderId: folders.get(cipher.uuid) ?? null,
          access,
          state: states.get(cipher.uuid),
        },
        files,
      )
    }
    return cipherJson({ cipher, folderId: folders.get(cipher.uuid) ?? null }, files)
  })
}

const bulk = (archived: boolean) => async (c: Ctx) => {
  const { ids } = await parseBody(c, idsSchema)
  const data = ids.length ? await setArchived(c, ids, archived) : []
  return c.json({ data, object: 'list', continuationToken: null })
}
archive.put('/api/ciphers/archive', bulk(true))
archive.put('/api/ciphers/unarchive', bulk(false))

const single = (archived: boolean) => async (c: Ctx) => {
  const [item] = await setArchived(c, [c.req.param('id') ?? ''], archived)
  return c.json(item)
}
archive.put('/api/ciphers/:id/archive', single(true))
archive.put('/api/ciphers/:id/unarchive', single(false))
