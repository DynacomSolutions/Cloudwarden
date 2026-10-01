import { and, eq, inArray, isNotNull } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import type { Bindings } from '../env'
import { ApiError } from '../errors'
import { baseUrl, signBlobToken, sizeName } from './blobs'
import { type CipherRow, chunk, cipherJson } from './ciphers'

type AttachmentRow = typeof schema.attachments.$inferSelect

export const ATTACHMENT_AUD = 'attachment'

/** Signed, short-lived download URL served by `GET /attachments/:cipherId/:attachmentId`. */
export async function attachmentUrl(env: Bindings, a: AttachmentRow): Promise<string> {
  const token = await signBlobToken(env, ATTACHMENT_AUD, `${a.cipherUuid}/${a.id}`)
  return `${baseUrl(env)}/attachments/${a.cipherUuid}/${a.id}?token=${token}`
}

export async function attachmentJson(env: Bindings, a: AttachmentRow) {
  return {
    object: 'attachment',
    id: a.id,
    url: await attachmentUrl(env, a),
    fileName: a.fileName,
    key: a.key,
    size: String(a.fileSize),
    sizeName: sizeName(a.fileSize),
  }
}

/** Completed attachments for the given ciphers, shaped for cipher responses. */
export async function attachmentsByCipher(
  env: Bindings,
  db: Db,
  cipherIds: string[],
): Promise<Map<string, Awaited<ReturnType<typeof attachmentJson>>[]>> {
  const out = new Map<string, Awaited<ReturnType<typeof attachmentJson>>[]>()
  for (const part of chunk(cipherIds)) {
    const rows = await db
      .select()
      .from(schema.attachments)
      .where(
        and(inArray(schema.attachments.cipherUuid, part), isNotNull(schema.attachments.uploadedAt)),
      )
    for (const row of rows) {
      const list = out.get(row.cipherUuid) ?? []
      list.push(await attachmentJson(env, row))
      out.set(row.cipherUuid, list)
    }
  }
  return out
}

export async function requireAttachment(
  db: Db,
  cipherId: string,
  attachmentId: string,
): Promise<AttachmentRow> {
  const [row] = await db
    .select()
    .from(schema.attachments)
    .where(
      and(eq(schema.attachments.cipherUuid, cipherId), eq(schema.attachments.id, attachmentId)),
    )
    .limit(1)
  if (!row) throw new ApiError(404, 'Attachment not found.')
  return row
}

/** R2 keys of every attachment blob belonging to the given ciphers. */
export async function attachmentKeys(db: Db, cipherIds: string[]): Promise<string[]> {
  const keys: string[] = []
  for (const part of chunk(cipherIds)) {
    const rows = await db
      .select({ key: schema.attachments.r2Key })
      .from(schema.attachments)
      .where(inArray(schema.attachments.cipherUuid, part))
    keys.push(...rows.map((r) => r.key))
  }
  return keys
}

/** R2 keys of every attachment blob owned by a user. */
export async function userAttachmentKeys(db: Db, userUuid: string): Promise<string[]> {
  const rows = await db
    .select({ key: schema.attachments.r2Key })
    .from(schema.attachments)
    .innerJoin(schema.ciphers, eq(schema.ciphers.uuid, schema.attachments.cipherUuid))
    .where(eq(schema.ciphers.userUuid, userUuid))
  return rows.map((r) => r.key)
}

/** Cipher responses with their completed attachments. */
export async function cipherResponses(env: Bindings, db: Db, rows: CipherRow[]) {
  const byCipher = await attachmentsByCipher(
    env,
    db,
    rows.map((r) => r.cipher.uuid),
  )
  return rows.map((r) => cipherJson(r, byCipher.get(r.cipher.uuid) ?? null))
}
