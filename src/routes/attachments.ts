import { and, count, eq, gt, isNull, lt, or } from 'drizzle-orm'
import type { Context, Hono } from 'hono'
import { z } from 'zod'
import { changes, createDb, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { parseBody } from '../validation'
import {
  ATTACHMENT_AUD,
  attachmentJson,
  cipherResponses,
  requireAttachment,
} from '../vault/attachments'
import {
  attachmentKey,
  baseUrl,
  deleteBlobs,
  MAX_PENDING_PER_CIPHER,
  MAX_UPLOAD_BYTES,
  MULTIPART_OVERHEAD,
  storeMultipartUpload,
  UPLOAD_CLAIM_TTL_MS,
  verifyBlobToken,
} from '../vault/blobs'
import { bumpRevision, requireCipher } from '../vault/ciphers'

type Ctx = Context<Env>

const requestSchema = z.object({
  fileName: z.string().min(1),
  key: z.string().min(1),
  fileSize: z.number().int().min(1),
  adminRequest: z.boolean().nullish(),
  lastKnownRevisionDate: z.string().nullish(),
})

const tooLarge = () => new ApiError(413, 'The file is too large.')

const cipherJsonFor = async (c: Ctx, cipherId: string) => {
  const db = createDb(c.env.DB)
  const row = await requireCipher(db, c.var.user.uuid, cipherId)
  const [json] = await cipherResponses(c.env, db, [row])
  return json
}

async function uploadData(c: Ctx, cipherId: string, attachmentId: string) {
  // The cipher in this response lists the attachment being reserved even though its blob is not
  // stored yet: the CLI keeps this copy as its local state once the upload finishes, so leaving the
  // attachment out made `bw create attachment` print an item without it. Sync and the other
  // routes still list completed uploads only.
  const cipher = (await cipherJsonFor(c, cipherId)) as {
    attachments: { id: string }[] | null
  }
  const row = await requireAttachment(createDb(c.env.DB), cipherId, attachmentId)
  const listed = (cipher.attachments ?? []).filter((a) => a.id !== attachmentId)
  const withPending = { ...cipher, attachments: [...listed, await attachmentJson(c.env, row)] }
  return {
    attachmentId,
    url: `${baseUrl(c.env)}/api/ciphers/${cipherId}/attachment/${attachmentId}`,
    fileUploadType: 0,
    cipherResponse: withPending,
    cipherMiniResponse: null,
    object: 'attachment-fileUpload',
  }
}

/** Marks the blob stored and moves the cipher and account revision dates forward. */
function completeStatements(c: Ctx, cipherId: string, attachmentId: string) {
  const db = createDb(c.env.DB)
  const now = Date.now()
  return [
    db
      .update(schema.attachments)
      .set({ uploadedAt: now })
      .where(eq(schema.attachments.id, attachmentId)),
    db.update(schema.ciphers).set({ updatedAt: now }).where(eq(schema.ciphers.uuid, cipherId)),
    bumpRevision(db, c.var.user.uuid, now),
  ]
}

export function registerAttachmentRoutes(r: Hono<Env>) {
  // Step 1 of the v2 flow: reserve an attachment id and tell the client where to POST the file.
  r.post('/api/ciphers/:id/attachment/v2', async (c) => {
    const cipherId = c.req.param('id') ?? ''
    const body = await parseBody(c, requestSchema)
    if (body.fileSize > MAX_UPLOAD_BYTES) throw tooLarge()
    const db = createDb(c.env.DB)
    await requireCipher(db, c.var.user.uuid, cipherId)
    const [pending] = await db
      .select({ n: count() })
      .from(schema.attachments)
      .where(
        and(
          eq(schema.attachments.cipherUuid, cipherId),
          isNull(schema.attachments.uploadedAt),
          gt(schema.attachments.createdAt, Date.now() - 24 * 60 * 60 * 1000),
        ),
      )
    if ((pending?.n ?? 0) >= MAX_PENDING_PER_CIPHER) {
      throw new ApiError(400, 'Too many unfinished attachment uploads for this cipher.')
    }
    const attachmentId = crypto.randomUUID().replaceAll('-', '')
    await runBatch(db, [
      db.insert(schema.attachments).values({
        id: attachmentId,
        cipherUuid: cipherId,
        fileName: body.fileName,
        fileSize: body.fileSize,
        key: body.key,
        r2Key: attachmentKey(cipherId, attachmentId),
        createdAt: Date.now(),
      }),
    ])
    return c.json(await uploadData(c, cipherId, attachmentId))
  })

  // Legacy single step upload: multipart with a `key` field and the file. Buffered in memory.
  r.post('/api/ciphers/:id/attachment', async (c) => {
    const cipherId = c.req.param('id') ?? ''
    const db = createDb(c.env.DB)
    await requireCipher(db, c.var.user.uuid, cipherId)
    // Reject before parsing: formData() buffers the whole body in memory.
    const length = Number(c.req.header('Content-Length') ?? Number.NaN)
    if (Number.isNaN(length)) throw new ApiError(411, 'Content-Length is required.')
    if (length > MAX_UPLOAD_BYTES + MULTIPART_OVERHEAD) throw tooLarge()
    const form = await c.req.formData().catch(() => null)
    const file = form?.get('data')
    const key = form?.get('key')
    if (!form || typeof file === 'string' || !file || typeof key !== 'string' || !key) {
      throw new ApiError(400, 'The request is invalid.')
    }
    if (file.size < 1 || file.size > MAX_UPLOAD_BYTES) throw tooLarge()
    const attachmentId = crypto.randomUUID().replaceAll('-', '')
    const r2Key = attachmentKey(cipherId, attachmentId)
    await c.env.ATTACHMENTS.put(r2Key, await file.arrayBuffer())
    const now = Date.now()
    await runBatch(db, [
      db.insert(schema.attachments).values({
        id: attachmentId,
        cipherUuid: cipherId,
        fileName: file.name,
        fileSize: file.size,
        key,
        r2Key,
        uploadedAt: now,
        createdAt: now,
      }),
      db.update(schema.ciphers).set({ updatedAt: now }).where(eq(schema.ciphers.uuid, cipherId)),
      bumpRevision(db, c.var.user.uuid, now),
    ])
    return c.json(await cipherJsonFor(c, cipherId))
  })

  // Step 2: the file, streamed into R2 and checked against the declared size.
  r.post('/api/ciphers/:id/attachment/:attachmentId', async (c) => {
    const cipherId = c.req.param('id') ?? ''
    const attachmentId = c.req.param('attachmentId') ?? ''
    const db = createDb(c.env.DB)
    await requireCipher(db, c.var.user.uuid, cipherId)
    const att = await requireAttachment(db, cipherId, attachmentId)
    if (att.uploadedAt != null) throw new ApiError(400, 'The attachment is already uploaded.')
    const started = Date.now()
    const claim = await db
      .update(schema.attachments)
      .set({ uploadStartedAt: started })
      .where(
        and(
          eq(schema.attachments.id, attachmentId),
          isNull(schema.attachments.uploadedAt),
          or(
            isNull(schema.attachments.uploadStartedAt),
            lt(schema.attachments.uploadStartedAt, started - UPLOAD_CLAIM_TTL_MS),
          ),
        ),
      )
    if (changes(claim) === 0)
      throw new ApiError(409, 'An upload for this attachment is in progress.')
    try {
      await storeMultipartUpload(c, att.r2Key, att.fileSize)
    } catch (e) {
      await db
        .update(schema.attachments)
        .set({ uploadStartedAt: null })
        .where(eq(schema.attachments.id, attachmentId))
      throw e
    }
    await runBatch(db, completeStatements(c, cipherId, attachmentId))
    return c.body(null, 200)
  })

  r.get('/api/ciphers/:id/attachment/:attachmentId/renew', async (c) => {
    const cipherId = c.req.param('id') ?? ''
    const attachmentId = c.req.param('attachmentId') ?? ''
    const db = createDb(c.env.DB)
    await requireCipher(db, c.var.user.uuid, cipherId)
    await requireAttachment(db, cipherId, attachmentId)
    return c.json(await uploadData(c, cipherId, attachmentId))
  })

  r.get('/api/ciphers/:id/attachment/:attachmentId', async (c) => {
    const db = createDb(c.env.DB)
    const cipherId = c.req.param('id') ?? ''
    await requireCipher(db, c.var.user.uuid, cipherId)
    const att = await requireAttachment(db, cipherId, c.req.param('attachmentId') ?? '')
    if (att.uploadedAt == null) throw new ApiError(404, 'Attachment not found.')
    return c.json(await attachmentJson(c.env, att))
  })

  const remove = async (c: Ctx) => {
    const cipherId = c.req.param('id') ?? ''
    const db = createDb(c.env.DB)
    await requireCipher(db, c.var.user.uuid, cipherId)
    const att = await requireAttachment(db, cipherId, c.req.param('attachmentId') ?? '')
    const now = Date.now()
    await runBatch(db, [
      db.delete(schema.attachments).where(eq(schema.attachments.id, att.id)),
      db.update(schema.ciphers).set({ updatedAt: now }).where(eq(schema.ciphers.uuid, cipherId)),
      bumpRevision(db, c.var.user.uuid, now),
    ])
    deleteBlobs(c, [att.r2Key])
    return c.json({ cipher: await cipherJsonFor(c, cipherId) })
  }
  r.delete('/api/ciphers/:id/attachment/:attachmentId', remove)
  r.post('/api/ciphers/:id/attachment/:attachmentId/delete', remove)
}

/** Signed download: `GET /attachments/:cipherId/:attachmentId?token=`. */
export async function downloadAttachment(c: Ctx) {
  const cipherId = c.req.param('cipherId') ?? ''
  const attachmentId = c.req.param('attachmentId') ?? ''
  const ok = await verifyBlobToken(
    c.env,
    ATTACHMENT_AUD,
    `${cipherId}/${attachmentId}`,
    c.req.query('token'),
  )
  if (!ok) throw new ApiError(401, 'Invalid or expired download link.')
  const att = await requireAttachment(createDb(c.env.DB), cipherId, attachmentId)
  const object = await c.env.ATTACHMENTS.get(att.r2Key)
  if (!object) throw new ApiError(404, 'Attachment not found.')
  return new Response(object.body, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(object.size),
      'Content-Disposition': 'attachment',
      'Cache-Control': 'private, no-store',
    },
  })
}
