import { and, eq, isNull, lt, or } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { randomB64u, safeEqualStrings } from '../auth/crypto'
import { requireAuth } from '../auth/middleware'
import { changes, createDb, runBatch, schema } from '../db'
import { createEmailTransport } from '../email'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { PushType } from '../notifications/publish'
import { notifySend } from '../notifications/vault-events'
import { rateLimit } from '../ratelimit'
import { parseBody } from '../validation'
import {
  deleteBlobs,
  MAX_UPLOAD_BYTES,
  sendFileKey,
  storeMultipartUpload,
  UPLOAD_CLAIM_TTL_MS,
  verifyBlobToken,
} from '../vault/blobs'
import { bumpRevision } from '../vault/ciphers'
import {
  checkSendPassword,
  fileDownloadUrl,
  loadForAccess,
  notAvailable,
  passwordError,
  requestSendCode,
  sendFromBearer,
  verifySendCode,
} from '../vault/send-access'
import {
  authColumns,
  authTypeOf,
  claimAccess,
  fileUploadUrl,
  normaliseEmail,
  requireOwnedSend,
  SEND_AUTH_EMAIL,
  SEND_FILE,
  SEND_FILE_AUD,
  type SendBody,
  type SendRow,
  sendAccessJson,
  sendData,
  sendJson,
  sendSchema,
  sendValues,
  unavailable,
} from '../vault/sends'

export const sends = new Hono<Env>()

type Ctx = Context<Env>

const canMail = (c: Ctx) => createEmailTransport(c.env).configured

const list = (rows: ReturnType<typeof sendJson>[]) => ({
  data: rows,
  object: 'list',
  continuationToken: null,
})

// ---- Recipient access (no user authentication) ----

async function creatorEmail(c: Ctx, userUuid: string | null): Promise<string | null> {
  if (!userUuid) return null
  const [u] = await createDb(c.env.DB)
    .select({ email: schema.users.email })
    .from(schema.users)
    .where(eq(schema.users.uuid, userUuid))
    .limit(1)
  return u?.email ?? null
}

/** Returns the access payload, counting the access for text and item Sends. */
async function accessPayload(c: Ctx, sendUuid: string) {
  const db = createDb(c.env.DB)
  const send = await loadForAccess(db, sendUuid)
  if (send.atype !== SEND_FILE && !(await claimAccess(db, send.uuid, Date.now()))) {
    throw notAvailable()
  }
  return c.json(sendAccessJson(send, await creatorEmail(c, send.userUuid)))
}

const passwordBody = z.object({
  password: z.string().nullish(),
  email: z.string().nullish(),
  otp: z.string().nullish(),
})

/**
 * Legacy flows send the credentials with each request. Email-protected Sends take `email` (which
 * mails a code) and then `email` with `otp`; a code is single use, so a file download needs its
 * own. Current clients use the `send_access` grant instead and hold a token.
 */
async function checkLegacyAccess(
  c: Ctx,
  send: SendRow,
  body: z.infer<typeof passwordBody> | null | undefined,
) {
  if (authTypeOf(send) !== SEND_AUTH_EMAIL) {
    const bad = passwordError(await checkSendPassword(send, body?.password))
    if (bad) throw bad
    return
  }
  const db = createDb(c.env.DB)
  const email = normaliseEmail(body?.email ?? '')
  if (!email) throw new ApiError(401, 'Email required.')
  const otp = (body?.otp ?? '').trim()
  if (!otp) {
    if (!(await requestSendCode(c, db, send, email))) throw new ApiError(429, 'Too many requests.')
    throw new ApiError(401, 'Email and verification code required.')
  }
  if (!(await verifySendCode(c, db, send, email, otp))) {
    throw new ApiError(401, 'Email and verification code required.')
  }
}

// Newer clients: Bearer token from the `send_access` grant on the identity endpoint.
sends.post('/api/sends/access', rateLimit('send-access'), async (c) => {
  const db = createDb(c.env.DB)
  const bearer = await sendFromBearer(c.env, db, c.req.header('Authorization'))
  if (!bearer) throw new ApiError(401, 'Unauthorized')
  return accessPayload(c, bearer.uuid)
})

sends.post('/api/sends/access/file/:fileId', rateLimit('send-access'), async (c) => {
  const db = createDb(c.env.DB)
  const bearer = await sendFromBearer(c.env, db, c.req.header('Authorization'))
  if (!bearer) throw new ApiError(401, 'Unauthorized')
  const send = await loadForAccess(db, bearer.uuid)
  return c.json(await fileDownloadUrl(db, c.env, send, c.req.param('fileId') ?? ''))
})

// Legacy clients: the access id in the path and the password in the body.
sends.post('/api/sends/access/:accessId', rateLimit('send-access'), async (c) => {
  const body = await parseBody(c, passwordBody.nullish())
  const send = await loadForAccess(createDb(c.env.DB), c.req.param('accessId') ?? '')
  await checkLegacyAccess(c, send, body)
  return accessPayload(c, send.uuid)
})

sends.post('/api/sends/:id/access/file/:fileId', rateLimit('send-access'), async (c) => {
  const body = await parseBody(c, passwordBody.nullish())
  const db = createDb(c.env.DB)
  const send = await loadForAccess(db, c.req.param('id') ?? '')
  await checkLegacyAccess(c, send, body)
  return c.json(await fileDownloadUrl(db, c.env, send, c.req.param('fileId') ?? ''))
})

/** Signed download: `GET /send-files/:sendId/:fileId?token=`. */
export async function downloadSendFile(c: Ctx) {
  const sendId = c.req.param('sendId') ?? ''
  const fileId = c.req.param('fileId') ?? ''
  if (!(await verifyBlobToken(c.env, SEND_FILE_AUD, `${sendId}/${fileId}`, c.req.query('token')))) {
    throw new ApiError(401, 'Invalid or expired download link.')
  }
  const [send] = await createDb(c.env.DB)
    .select()
    .from(schema.sends)
    .where(eq(schema.sends.uuid, sendId))
    .limit(1)
  // The access was counted when the link was issued, so only the count is not re-checked.
  if (!send || unavailable(send, Date.now(), false)) throw notAvailable()
  const object = send.r2Key ? await c.env.ATTACHMENTS.get(send.r2Key) : null
  if (!object) throw notAvailable()
  return new Response(object.body, {
    headers: {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(object.size),
      'Content-Disposition': 'attachment',
      'Cache-Control': 'private, no-store',
    },
  })
}

// ---- Owner management ----

sends.get('/api/sends', requireAuth, async (c) => {
  const rows = await createDb(c.env.DB)
    .select()
    .from(schema.sends)
    .where(eq(schema.sends.userUuid, c.var.user.uuid))
  return c.json(list(rows.map(sendJson)))
})

async function respond(c: Ctx, id: string) {
  const row = await requireOwnedSend(createDb(c.env.DB), c.var.user.uuid, id)
  return sendJson(row)
}

sends.post('/api/sends', requireAuth, async (c) => {
  const body = await parseBody(c, sendSchema)
  if (body.type === SEND_FILE) throw new ApiError(400, 'File Sends are created with file/v2.')
  const db = createDb(c.env.DB)
  const user = c.var.user
  const id = crypto.randomUUID()
  const now = Date.now()
  await runBatch(db, [
    db.insert(schema.sends).values({
      uuid: id,
      userUuid: user.uuid,
      atype: body.type,
      data: sendData(body),
      akey: body.key,
      ...sendValues(body, now, true),
      ...(await authColumns(body, undefined, canMail(c))),
      createdAt: now,
      updatedAt: now,
    }),
    bumpRevision(db, user.uuid, now),
  ])
  notifySend(c, PushType.SyncSendCreate, id, now)
  return c.json(await respond(c, id))
})

sends.post('/api/sends/file/v2', requireAuth, async (c) => {
  const body = await parseBody(c, sendSchema)
  if (body.type !== SEND_FILE) throw new ApiError(400, 'Not a file Send.')
  const size = body.fileLength ?? 0
  if (size < 1 || size > MAX_UPLOAD_BYTES) throw new ApiError(413, 'The file is too large.')
  if (!body.file?.fileName)
    throw new ApiError(400, 'The request is invalid.', { file: ['File name is required.'] })
  const db = createDb(c.env.DB)
  const user = c.var.user
  const id = crypto.randomUUID()
  const fileId = randomB64u(12)
  const now = Date.now()
  await runBatch(db, [
    db.insert(schema.sends).values({
      uuid: id,
      userUuid: user.uuid,
      atype: SEND_FILE,
      data: sendData(body, fileId),
      akey: body.key,
      r2Key: sendFileKey(id, fileId),
      ...sendValues(body, now, true),
      ...(await authColumns(body, undefined, canMail(c))),
      createdAt: now,
      updatedAt: now,
    }),
  ])
  return c.json({
    fileUploadType: 0,
    url: fileUploadUrl(c.env, id, fileId),
    sendResponse: await respond(c, id),
    object: 'send-fileUpload',
  })
})

sends.get('/api/sends/:id', requireAuth, async (c) => c.json(await respond(c, c.req.param('id'))))

sends.put('/api/sends/:id', requireAuth, async (c) => {
  const body: SendBody = await parseBody(c, sendSchema)
  const db = createDb(c.env.DB)
  const user = c.var.user
  const existing = await requireOwnedSend(db, user.uuid, c.req.param('id'))
  if (body.type !== existing.atype) throw new ApiError(400, 'The Send type cannot be changed.')
  const now = Date.now()
  const fileData = existing.atype === SEND_FILE ? { data: existing.data } : { data: sendData(body) }
  await runBatch(db, [
    db
      .update(schema.sends)
      .set({
        ...fileData,
        ...sendValues(body, now),
        ...(await authColumns(body, existing, canMail(c))),
        updatedAt: now,
      })
      .where(eq(schema.sends.uuid, existing.uuid)),
    bumpRevision(db, user.uuid, now),
  ])
  notifySend(c, PushType.SyncSendUpdate, existing.uuid, now)
  return c.json(await respond(c, existing.uuid))
})

/** Drops the password (`remove-password`) or any recipient authentication (`remove-auth`). */
const removeAuth = (all: boolean) => async (c: Ctx) => {
  const db = createDb(c.env.DB)
  const user = c.var.user
  const existing = await requireOwnedSend(db, user.uuid, c.req.param('id') ?? '')
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.sends)
      .set({
        passwordHash: null,
        passwordSalt: null,
        passwordIter: null,
        ...(all ? { emails: null } : {}),
        updatedAt: now,
      })
      .where(eq(schema.sends.uuid, existing.uuid)),
    bumpRevision(db, user.uuid, now),
  ])
  notifySend(c, PushType.SyncSendUpdate, existing.uuid, now)
  return c.json(await respond(c, existing.uuid))
}
sends.put('/api/sends/:id/remove-password', requireAuth, removeAuth(false))
sends.put('/api/sends/:id/remove-auth', requireAuth, removeAuth(true))

sends.delete('/api/sends/:id', requireAuth, async (c) => {
  const db = createDb(c.env.DB)
  const user = c.var.user
  const existing = await requireOwnedSend(db, user.uuid, c.req.param('id'))
  await runBatch(db, [
    db.delete(schema.sends).where(eq(schema.sends.uuid, existing.uuid)),
    bumpRevision(db, user.uuid, Date.now()),
  ])
  deleteBlobs(c, existing.r2Key ? [existing.r2Key] : [])
  notifySend(c, PushType.SyncSendDelete, existing.uuid, Date.now())
  return c.body(null, 200)
})

async function ownedFileSend(c: Ctx) {
  const send = await requireOwnedSend(createDb(c.env.DB), c.var.user.uuid, c.req.param('id') ?? '')
  const fileId = c.req.param('fileId') ?? ''
  const data = JSON.parse(send.data) as { id?: string; size?: string }
  if (send.atype !== SEND_FILE || !data.id || !safeEqualStrings(data.id, fileId)) {
    throw new ApiError(404, 'Send not found.')
  }
  return { send, fileId, size: Number(data.size) }
}

sends.get('/api/sends/:id/file/:fileId', requireAuth, async (c) => {
  const { send, fileId } = await ownedFileSend(c)
  return c.json({
    fileUploadType: 0,
    url: fileUploadUrl(c.env, send.uuid, fileId),
    sendResponse: sendJson(send),
    object: 'send-fileUpload',
  })
})

sends.post('/api/sends/:id/file/:fileId', requireAuth, async (c) => {
  const { send, size } = await ownedFileSend(c)
  if (send.uploadedAt != null) throw new ApiError(400, 'The file is already uploaded.')
  if (!send.r2Key) throw new ApiError(404, 'Send not found.')
  const db = createDb(c.env.DB)
  const started = Date.now()
  const claim = await db
    .update(schema.sends)
    .set({ uploadStartedAt: started })
    .where(
      and(
        eq(schema.sends.uuid, send.uuid),
        isNull(schema.sends.uploadedAt),
        or(
          isNull(schema.sends.uploadStartedAt),
          lt(schema.sends.uploadStartedAt, started - UPLOAD_CLAIM_TTL_MS),
        ),
      ),
    )
  if (changes(claim) === 0) throw new ApiError(409, 'An upload for this file is in progress.')
  try {
    await storeMultipartUpload(c, send.r2Key, size)
  } catch (e) {
    await db
      .update(schema.sends)
      .set({ uploadStartedAt: null })
      .where(eq(schema.sends.uuid, send.uuid))
    throw e
  }
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.sends)
      .set({ uploadedAt: now, updatedAt: now })
      .where(and(eq(schema.sends.uuid, send.uuid), eq(schema.sends.userUuid, c.var.user.uuid))),
    bumpRevision(db, c.var.user.uuid, now),
  ])
  // A file Send becomes visible to other devices once its upload completes.
  notifySend(c, PushType.SyncSendCreate, send.uuid, now)
  return c.body(null, 200)
})
