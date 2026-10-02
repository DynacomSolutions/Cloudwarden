import { and, count, eq, gt, isNull, lt, or } from 'drizzle-orm'
import type { Context, Hono } from 'hono'
import { z } from 'zod'
import { changes, createDb, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { PushType } from '../notifications/publish'
import { notifyCipher } from '../notifications/vault-events'
import { bumpOrgRevision, canManageAllCiphers, requireMember } from '../orgs/access'
import {
  accessToCipher,
  adminItemAccess,
  folderLinks,
  type ItemAccess,
  loadCipherById,
  orgCipherJson,
  userCipherState,
} from '../orgs/ciphers'
import { cipherRecipients, notifyOrgCipher } from '../orgs/notify'
import { parseBody } from '../validation'
import {
  ATTACHMENT_AUD,
  attachmentJson,
  attachmentsByCipher,
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
import { bumpRevision } from '../vault/ciphers'

type Ctx = Context<Env>

const requestSchema = z.object({
  fileName: z.string().min(1),
  key: z.string().min(1),
  fileSize: z.number().int().min(1),
  adminRequest: z.boolean().nullish(),
  lastKnownRevisionDate: z.string().nullish(),
})

const tooLarge = () => new ApiError(413, 'The file is too large.')

type CipherRecord = typeof schema.ciphers.$inferSelect

/** A cipher the caller may reach: `access` is null for the caller's own personal items. */
interface Loaded {
  cipher: CipherRecord
  access: ItemAccess | null
}

/**
 * Resolves the cipher for an attachment route. Personal items belong to their owner. For
 * organisation items, reading needs access through a collection, writing needs edit access, and
 * the admin routes need the right to manage every item of the organisation.
 */
async function authorise(c: Ctx, cipherId: string, write: boolean, admin = false): Promise<Loaded> {
  const db = createDb(c.env.DB)
  const cipher = await loadCipherById(db, cipherId)
  if (!cipher) throw new ApiError(404, 'Cipher not found.')
  if (!cipher.organizationUuid) {
    if (cipher.userUuid !== c.var.user.uuid) throw new ApiError(404, 'Cipher not found.')
    return { cipher, access: null }
  }
  if (admin) {
    const member = await requireMember(db, c.var.user.uuid, cipher.organizationUuid)
    if (!canManageAllCiphers(member)) {
      throw new ApiError(403, 'You do not have permission to do this.')
    }
    return { cipher, access: await adminItemAccess(db, cipher) }
  }
  let access = await accessToCipher(db, c.var.user.uuid, cipher)
  if (!access) {
    // Owners and admins reach every item of their organisation (the admin upload's second step
    // posts to the plain URL).
    const member = await requireMember(db, c.var.user.uuid, cipher.organizationUuid).catch(
      () => null,
    )
    if (!canManageAllCiphers(member ?? undefined)) throw new ApiError(404, 'Cipher not found.')
    access = await adminItemAccess(db, cipher)
  }
  if (write && !access.edit) {
    throw new ApiError(403, 'You do not have permission to edit this item.')
  }
  return { cipher, access }
}

const cipherJsonFor = async (c: Ctx, loaded: Loaded) => {
  const db = createDb(c.env.DB)
  const cipher = (await loadCipherById(db, loaded.cipher.uuid)) ?? loaded.cipher
  const folders = await folderLinks(db, c.var.user.uuid)
  const folderId = folders.get(cipher.uuid) ?? null
  if (!loaded.access) {
    const [json] = await cipherResponses(c.env, db, [{ cipher, folderId }])
    return json
  }
  const files = (await attachmentsByCipher(c.env, db, [cipher.uuid])).get(cipher.uuid) ?? null
  const state = await userCipherState(db, c.var.user.uuid, cipher.uuid)
  return orgCipherJson({ cipher, folderId, access: loaded.access, state }, files)
}

async function uploadData(c: Ctx, loaded: Loaded, attachmentId: string) {
  const cipherId = loaded.cipher.uuid
  // The cipher in this response lists the attachment being reserved even though its blob is not
  // stored yet: the CLI keeps this copy as its local state once the upload finishes, so leaving the
  // attachment out made `bw create attachment` print an item without it. Sync and the other
  // routes still list completed uploads only.
  const cipher = (await cipherJsonFor(c, loaded)) as {
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

/** Moves the cipher and revision dates forward; organisation items also move every member's. */
function touchStatements(c: Ctx, loaded: Loaded, now: number) {
  const db = createDb(c.env.DB)
  const orgUuid = loaded.cipher.organizationUuid
  return [
    db
      .update(schema.ciphers)
      .set({ updatedAt: now })
      .where(eq(schema.ciphers.uuid, loaded.cipher.uuid)),
    bumpRevision(db, c.var.user.uuid, now),
    ...(orgUuid ? [bumpOrgRevision(db, orgUuid, now)] : []),
  ]
}

/** Marks the blob stored and moves the revision dates forward. */
function completeStatements(c: Ctx, loaded: Loaded, attachmentId: string, now = Date.now()) {
  const db = createDb(c.env.DB)
  return [
    db
      .update(schema.attachments)
      .set({ uploadedAt: now })
      .where(eq(schema.attachments.id, attachmentId)),
    ...touchStatements(c, loaded, now),
  ]
}

/** Tells the devices that can see the item that its attachments changed. */
async function announce(c: Ctx, loaded: Loaded, now: number) {
  if (!loaded.cipher.organizationUuid) {
    notifyCipher(c, PushType.SyncCipherUpdate, loaded.cipher.uuid, now)
    return
  }
  const db = createDb(c.env.DB)
  notifyOrgCipher(
    c,
    PushType.SyncCipherUpdate,
    loaded.cipher,
    await cipherRecipients(db, loaded.cipher),
    now,
  )
}

const isAdmin = (c: Ctx) => c.req.path.endsWith('/admin')

export function registerAttachmentRoutes(r: Hono<Env>) {
  // Step 1 of the v2 flow: reserve an attachment id and tell the client where to POST the file.
  r.post('/api/ciphers/:id/attachment/v2', async (c) => {
    const cipherId = c.req.param('id') ?? ''
    const body = await parseBody(c, requestSchema)
    if (body.fileSize > MAX_UPLOAD_BYTES) throw tooLarge()
    const db = createDb(c.env.DB)
    const loaded = await authorise(c, cipherId, true, body.adminRequest === true)
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
    return c.json(await uploadData(c, loaded, attachmentId))
  })

  // Legacy single step upload: multipart with a `key` field and the file. Buffered in memory.
  r.post('/api/ciphers/:id/attachment', async (c) => {
    const cipherId = c.req.param('id') ?? ''
    const db = createDb(c.env.DB)
    const loaded = await authorise(c, cipherId, true)
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
      ...touchStatements(c, loaded, now),
    ])
    await announce(c, loaded, now)
    return c.json(await cipherJsonFor(c, loaded))
  })

  // Step 2: the file, streamed into R2 and checked against the declared size.
  r.post('/api/ciphers/:id/attachment/:attachmentId', async (c) => {
    const cipherId = c.req.param('id') ?? ''
    const attachmentId = c.req.param('attachmentId') ?? ''
    const db = createDb(c.env.DB)
    const loaded = await authorise(c, cipherId, true)
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
    const now = Date.now()
    await runBatch(db, completeStatements(c, loaded, attachmentId, now))
    await announce(c, loaded, now)
    return c.body(null, 200)
  })

  // Replaces a stored attachment with the copy re-encrypted for the organisation when a cipher
  // is shared. The file name rides on the part's filename; a new wrapped key may come with it.
  r.post('/api/ciphers/:id/attachment/:attachmentId/share', async (c) => {
    const cipherId = c.req.param('id') ?? ''
    const attachmentId = c.req.param('attachmentId') ?? ''
    const db = createDb(c.env.DB)
    const loaded = await authorise(c, cipherId, true)
    const orgId = c.req.query('organizationId')
    if (!orgId) throw new ApiError(400, 'An organization is required.')
    if (loaded.cipher.organizationUuid ? loaded.cipher.organizationUuid !== orgId : false) {
      throw new ApiError(400, 'The item belongs to a different organization.')
    }
    if (!loaded.cipher.organizationUuid) {
      await requireMember(db, c.var.user.uuid, orgId)
    }
    const att = await requireAttachment(db, cipherId, attachmentId)
    if (att.uploadedAt == null) throw new ApiError(404, 'Attachment not found.')
    const length = Number(c.req.header('Content-Length') ?? Number.NaN)
    if (Number.isNaN(length)) throw new ApiError(411, 'Content-Length is required.')
    if (length > MAX_UPLOAD_BYTES + MULTIPART_OVERHEAD) throw tooLarge()
    const form = await c.req.formData().catch(() => null)
    const file = form?.get('data')
    const key = form?.get('key')
    if (!form || typeof file === 'string' || !file)
      throw new ApiError(400, 'The request is invalid.')
    if (file.size < 1 || file.size > MAX_UPLOAD_BYTES) throw tooLarge()
    await c.env.ATTACHMENTS.put(att.r2Key, await file.arrayBuffer())
    const now = Date.now()
    await runBatch(db, [
      db
        .update(schema.attachments)
        .set({
          fileSize: file.size,
          fileName: file.name || att.fileName,
          ...(typeof key === 'string' && key ? { key } : {}),
        })
        .where(eq(schema.attachments.id, att.id)),
      ...touchStatements(c, loaded, now),
    ])
    await announce(c, loaded, now)
    return c.body(null, 200)
  })

  r.get('/api/ciphers/:id/attachment/:attachmentId/renew', async (c) => {
    const cipherId = c.req.param('id') ?? ''
    const attachmentId = c.req.param('attachmentId') ?? ''
    const db = createDb(c.env.DB)
    const loaded = await authorise(c, cipherId, true)
    await requireAttachment(db, cipherId, attachmentId)
    return c.json(await uploadData(c, loaded, attachmentId))
  })

  const get = async (c: Ctx) => {
    const db = createDb(c.env.DB)
    const cipherId = c.req.param('id') ?? ''
    await authorise(c, cipherId, false, isAdmin(c))
    const att = await requireAttachment(db, cipherId, c.req.param('attachmentId') ?? '')
    if (att.uploadedAt == null) throw new ApiError(404, 'Attachment not found.')
    return c.json(await attachmentJson(c.env, att))
  }
  r.get('/api/ciphers/:id/attachment/:attachmentId', get)
  r.get('/api/ciphers/:id/attachment/:attachmentId/admin', get)

  const remove = async (c: Ctx) => {
    const cipherId = c.req.param('id') ?? ''
    const db = createDb(c.env.DB)
    const loaded = await authorise(c, cipherId, true, isAdmin(c))
    const att = await requireAttachment(db, cipherId, c.req.param('attachmentId') ?? '')
    const now = Date.now()
    await runBatch(db, [
      db.delete(schema.attachments).where(eq(schema.attachments.id, att.id)),
      ...touchStatements(c, loaded, now),
    ])
    deleteBlobs(c, [att.r2Key])
    await announce(c, loaded, now)
    return c.json({ cipher: await cipherJsonFor(c, loaded) })
  }
  r.delete('/api/ciphers/:id/attachment/:attachmentId', remove)
  r.delete('/api/ciphers/:id/attachment/:attachmentId/admin', remove)
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
