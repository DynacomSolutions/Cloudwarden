import type { Context } from 'hono'
import { toB64u, utf8 } from '../auth/crypto'
import { signingSecret, signJwt, verificationSecrets, verifyJwt } from '../auth/jwt'
import type { Bindings, Env } from '../env'
import { ApiError } from '../errors'

/**
 * Largest accepted attachment or Send file. Workers cap request bodies at 100 MB on the
 * Free and Pro plans (200 MB Business, 500 MB Enterprise); the limit is kept at the lowest.
 */
export const MAX_UPLOAD_BYTES = 100 * 1024 * 1024
/** Multipart framing allowed on top of the file bytes when checking Content-Length. */
export const MULTIPART_OVERHEAD = 64 * 1024
export const DOWNLOAD_TTL_SECONDS = 300

export const attachmentKey = (cipherId: string, attachmentId: string) =>
  `attachments/${cipherId}/${attachmentId}`
export const sendFileKey = (sendId: string, fileId: string) => `sends/${sendId}/${fileId}`

export const sizeName = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} Bytes`
  const units = ['KB', 'MB', 'GB']
  let value = bytes
  let unit = ''
  for (const u of units) {
    value /= 1024
    unit = u
    if (value < 1024) break
  }
  return `${Math.round(value * 100) / 100} ${unit}`
}

export const baseUrl = (env: Bindings) => env.DOMAIN.replace(/\/+$/, '')

interface BlobClaims {
  aud: string
  sub: string
  nbf: number
  exp: number
}

/** Purpose-bound key: HMAC(secret, label), so these tokens never verify as any other token. */
async function derive(secret: string, label: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    utf8(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  return toB64u(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(label))))
}

export const signingKeyFor = (env: Bindings, label: string) => derive(signingSecret(env), label)
export const verificationKeysFor = (env: Bindings, label: string) =>
  Promise.all(verificationSecrets(env).map((s) => derive(s, label)))

/** Short-lived HMAC token naming one blob. `aud` separates attachments from Send files. */
export async function signBlobToken(env: Bindings, aud: string, sub: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const claims: BlobClaims = { aud, sub, nbf: now - 5, exp: now + DOWNLOAD_TTL_SECONDS }
  return signJwt(claims, await signingKeyFor(env, `blob:${aud}`))
}

/** Returns true when the token is valid, unexpired and was issued for exactly this blob. */
export async function verifyBlobToken(
  env: Bindings,
  aud: string,
  sub: string,
  token: string | undefined,
): Promise<boolean> {
  if (!token) return false
  const claims = await verifyJwt<BlobClaims>(token, await verificationKeysFor(env, `blob:${aud}`))
  return !!claims && claims.aud === aud && claims.sub === sub
}

const indexOf = (hay: Uint8Array, needle: Uint8Array): number =>
  Buffer.from(hay.buffer, hay.byteOffset, hay.byteLength).indexOf(needle)

/**
 * Transform that extracts the bytes of the first part of a multipart body without buffering
 * the file: the preamble and part headers are dropped and the closing delimiter is held back.
 */
function multipartFilePart(boundary: string): TransformStream<Uint8Array, Uint8Array> {
  const enc = new TextEncoder()
  const delim = enc.encode(`\r\n--${boundary}`)
  const headerEnd = enc.encode('\r\n\r\n')
  let state: 'preamble' | 'headers' | 'body' | 'done' = 'preamble'
  // A leading CRLF lets the first boundary match the same delimiter as later ones.
  let pending: Uint8Array = enc.encode('\r\n')
  const malformed = () => new ApiError(400, 'Malformed multipart body.')

  const append = (chunk: Uint8Array) => {
    const next = new Uint8Array(pending.length + chunk.length)
    next.set(pending)
    next.set(chunk, pending.length)
    pending = next
  }

  return new TransformStream({
    transform(chunk, controller) {
      if (state === 'done') return
      append(chunk)
      for (;;) {
        if (state === 'preamble') {
          const i = indexOf(pending, delim)
          if (i < 0) {
            pending = pending.slice(Math.max(0, pending.length - delim.length))
            return
          }
          pending = pending.slice(i + delim.length)
          state = 'headers'
        } else if (state === 'headers') {
          const i = indexOf(pending, headerEnd)
          if (i < 0) {
            if (pending.length > 8192) throw malformed()
            return
          }
          pending = pending.slice(i + headerEnd.length)
          state = 'body'
        } else {
          const i = indexOf(pending, delim)
          if (i >= 0) {
            if (i > 0) controller.enqueue(pending.slice(0, i))
            pending = new Uint8Array(0)
            state = 'done'
            return
          }
          const safe = pending.length - (delim.length - 1)
          if (safe > 0) {
            controller.enqueue(pending.slice(0, safe))
            pending = pending.slice(safe)
          }
          return
        }
      }
    },
    flush() {
      if (state !== 'done') throw malformed()
    },
  })
}

/**
 * Streams the single file part of a multipart upload into R2. The stored length must equal
 * `size`; otherwise nothing is kept and a 400 is thrown. The request body is never buffered.
 */
export async function storeMultipartUpload(
  c: Context<Env>,
  key: string,
  size: number,
): Promise<void> {
  const type = c.req.header('Content-Type') ?? ''
  const boundary = /^multipart\/form-data;.*boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(type)
  const b = boundary?.[1] ?? boundary?.[2]
  if (!b || !c.req.raw.body) throw new ApiError(400, 'Expected a multipart/form-data body.')
  const length = Number(c.req.header('Content-Length') ?? '0')
  if (length > MAX_UPLOAD_BYTES + MULTIPART_OVERHEAD) {
    throw new ApiError(413, 'The file is too large.')
  }
  const fixed = new FixedLengthStream(size)
  const stored = c.env.ATTACHMENTS.put(key, fixed.readable)
  const piped = c.req.raw.body.pipeThrough(multipartFilePart(b)).pipeTo(fixed.writable)
  try {
    await Promise.all([stored, piped])
  } catch {
    await c.env.ATTACHMENTS.delete(key).catch(() => {})
    throw new ApiError(400, 'The uploaded file does not match the declared size.')
  }
}

/** Removes blobs in the background; failures are left for the scheduled orphan sweep. */
export function deleteBlobs(c: Context<Env>, keys: string[]): void {
  if (keys.length === 0) return
  const work = deleteBlobsNow(c.env, keys).catch(() => {})
  try {
    c.executionCtx.waitUntil(work)
  } catch {
    // No execution context (direct app.fetch call): the promise still runs.
  }
}

export async function deleteBlobsNow(env: Bindings, keys: string[]): Promise<void> {
  for (let i = 0; i < keys.length; i += 1000) {
    await env.ATTACHMENTS.delete(keys.slice(i, i + 1000))
  }
}

/** An upload claim older than this is treated as abandoned and may be taken over. */
export const UPLOAD_CLAIM_TTL_MS = 10 * 60 * 1000
/** Reserved but unfinished attachment slots allowed per cipher. */
export const MAX_PENDING_PER_CIPHER = 10
