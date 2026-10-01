import { and, eq, sql } from 'drizzle-orm'
import { z } from 'zod'
import { fromB64u, toB64u } from '../auth/crypto'
import { hashMasterPassword } from '../auth/passwords'
import type { Db } from '../db'
import { schema } from '../db'
import type { Bindings } from '../env'
import { ApiError } from '../errors'
import { baseUrl, sizeName } from './blobs'

export type SendRow = typeof schema.sends.$inferSelect

export const SEND_TEXT = 0
export const SEND_FILE = 1
export const SEND_ITEM = 2
export const SEND_AUTH_EMAIL = 0
export const SEND_AUTH_PASSWORD = 1
export const SEND_AUTH_NONE = 2
export const SEND_FILE_AUD = 'send-file'
const MAX_DELETION_DAYS = 31

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const iso = (ms: number | null) => (ms == null ? null : new Date(ms).toISOString())

/** Public identifier used in share links: the Send UUID bytes, base64url encoded. */
export function accessIdOf(uuid: string): string {
  const hex = uuid.replaceAll('-', '')
  const bytes = new Uint8Array(16)
  for (let i = 0; i < 16; i++) bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return toB64u(bytes)
}

/** Accepts either a Send UUID or its access id, returns the UUID (or null if neither). */
export function sendUuidFrom(idOrAccess: string): string | null {
  if (UUID.test(idOrAccess)) return idOrAccess.toLowerCase()
  const bytes = fromB64u(idOrAccess)
  if (!bytes) return null
  if (bytes.length !== 16) return null
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

const parseData = (s: string): Record<string, unknown> => {
  try {
    return JSON.parse(s) as Record<string, unknown>
  } catch {
    return {}
  }
}

/** The type specific payload split into the three response properties. */
function payload(send: SendRow) {
  const data = parseData(send.data)
  return {
    text: send.atype === SEND_TEXT ? data : null,
    file: send.atype === SEND_FILE ? data : null,
    data: send.atype === SEND_ITEM ? data : null,
  }
}

export function sendJson(send: SendRow) {
  return {
    object: 'send',
    id: send.uuid,
    accessId: accessIdOf(send.uuid),
    type: send.atype,
    authType: send.passwordHash ? SEND_AUTH_PASSWORD : SEND_AUTH_NONE,
    name: send.name,
    notes: send.notes,
    key: send.akey,
    maxAccessCount: send.maxAccessCount,
    accessCount: send.accessCount,
    revisionDate: iso(send.updatedAt),
    expirationDate: iso(send.expirationDate),
    deletionDate: iso(send.deletionDate),
    password: send.passwordHash,
    emails: null,
    disabled: send.disabled,
    hideEmail: send.hideEmail ?? false,
    ...payload(send),
  }
}

/** What a recipient sees: no counters, no key material beyond the encrypted fields. */
export function sendAccessJson(send: SendRow, creatorEmail: string | null) {
  const { text, file, data } = payload(send)
  return {
    object: 'send-access',
    id: accessIdOf(send.uuid),
    type: send.atype,
    name: send.name,
    text,
    file,
    data,
    expirationDate: iso(send.expirationDate),
    creatorIdentifier: send.hideEmail ? null : creatorEmail,
  }
}

const enc = z.string().min(1)
const text = z.object({ text: z.string().nullish(), hidden: z.boolean().nullish() }).passthrough()
const file = z
  .object({
    id: z.string().nullish(),
    fileName: z.string().nullish(),
    size: z.union([z.string(), z.number()]).nullish(),
    sizeName: z.string().nullish(),
  })
  .passthrough()

export const sendSchema = z.object({
  type: z.number().int().min(0).max(2),
  name: enc,
  notes: z.string().nullish(),
  key: enc,
  maxAccessCount: z.number().int().min(1).nullish(),
  expirationDate: z.string().nullish(),
  deletionDate: z.string().min(1),
  text: text.nullish(),
  file: file.nullish(),
  data: z.record(z.string(), z.unknown()).nullish(),
  fileLength: z.number().int().nullish(),
  password: z.string().nullish(),
  emails: z.string().nullish(),
  disabled: z.boolean().nullish(),
  hideEmail: z.boolean().nullish(),
  authType: z.number().int().nullish(),
})
export type SendBody = z.infer<typeof sendSchema>

const invalid = (field: string, message: string) =>
  new ApiError(400, 'The request is invalid.', { [field]: [message] })

function parseDate(value: string, field: string): number {
  const ms = Date.parse(value)
  if (Number.isNaN(ms)) throw invalid(field, 'Invalid date.')
  return ms
}

/** Validates dates and the type payload; returns the column values shared by create and update. */
export function sendValues(body: SendBody, now: number, creating = false) {
  if (body.authType === SEND_AUTH_EMAIL || body.emails) {
    throw new ApiError(400, 'Email-protected Sends are not supported.')
  }
  const deletionDate = parseDate(body.deletionDate, 'deletionDate')
  if (deletionDate > now + MAX_DELETION_DAYS * 86_400_000) {
    throw invalid('deletionDate', 'The deletion date is too far in the future.')
  }
  if (creating && deletionDate < now - 300_000)
    throw invalid('deletionDate', 'The deletion date is in the past.')
  const expirationDate = body.expirationDate
    ? parseDate(body.expirationDate, 'expirationDate')
    : null
  if (expirationDate != null && expirationDate > deletionDate) {
    throw invalid('expirationDate', 'The expiration date is after the deletion date.')
  }
  return {
    name: body.name,
    notes: body.notes ?? null,
    maxAccessCount: body.maxAccessCount ?? null,
    expirationDate,
    deletionDate,
    disabled: body.disabled ?? false,
    hideEmail: body.hideEmail ?? false,
  }
}

/** The stored `data` JSON for the Send type; File Sends keep the server issued file id. */
export function sendData(body: SendBody, fileId?: string): string {
  if (body.type === SEND_TEXT) {
    if (!body.text) throw invalid('text', 'Text is required.')
    return JSON.stringify({ text: body.text.text ?? null, hidden: body.text.hidden ?? false })
  }
  if (body.type === SEND_ITEM) {
    if (!body.data) throw invalid('data', 'Data is required.')
    return JSON.stringify(body.data)
  }
  const size = body.fileLength ?? 0
  return JSON.stringify({
    id: fileId,
    fileName: body.file?.fileName ?? null,
    size: String(size),
    sizeName: sizeName(size),
  })
}

export async function passwordColumns(password: string | null | undefined) {
  if (!password) return {}
  const h = await hashMasterPassword(password)
  return { passwordHash: h.passwordHash, passwordSalt: h.salt, passwordIter: h.passwordIterations }
}

export async function requireOwnedSend(db: Db, userUuid: string, id: string): Promise<SendRow> {
  const uuid = sendUuidFrom(id)
  const [row] = uuid
    ? await db
        .select()
        .from(schema.sends)
        .where(and(eq(schema.sends.uuid, uuid), eq(schema.sends.userUuid, userUuid)))
        .limit(1)
    : []
  if (!row) throw new ApiError(404, 'Send not found.')
  return row
}

/** R2 keys of every Send file blob owned by a user. */
export async function userSendKeys(db: Db, userUuid: string): Promise<string[]> {
  const rows = await db
    .select({ key: schema.sends.r2Key })
    .from(schema.sends)
    .where(eq(schema.sends.userUuid, userUuid))
  return rows.flatMap((r) => (r.key ? [r.key] : []))
}

export const fileUploadUrl = (env: Bindings, sendId: string, fileId: string) =>
  `${baseUrl(env)}/api/sends/${sendId}/file/${fileId}`

/** Reasons a recipient cannot use a Send right now. Null means available. */
export function unavailable(send: SendRow, now: number, checkCount = true): string | null {
  if (send.disabled) return 'disabled'
  if (send.deletionDate <= now) return 'deleted'
  if (send.expirationDate != null && send.expirationDate <= now) return 'expired'
  if (checkCount && send.maxAccessCount != null && send.accessCount >= send.maxAccessCount)
    return 'exhausted'
  if (send.atype === SEND_FILE && send.uploadedAt == null) return 'pending'
  return null
}

/**
 * Counts one access atomically. The conditions repeat the availability checks so two
 * concurrent recipients cannot both take the last allowed access.
 */
export async function claimAccess(db: Db, uuid: string, now: number): Promise<boolean> {
  const result = await db
    .update(schema.sends)
    .set({ accessCount: sql`${schema.sends.accessCount} + 1` })
    .where(
      and(
        eq(schema.sends.uuid, uuid),
        eq(schema.sends.disabled, false),
        sql`${schema.sends.deletionDate} > ${now}`,
        sql`(${schema.sends.expirationDate} is null or ${schema.sends.expirationDate} > ${now})`,
        sql`(${schema.sends.maxAccessCount} is null or ${schema.sends.accessCount} < ${schema.sends.maxAccessCount})`,
        sql`(${schema.sends.atype} != 1 or ${schema.sends.uploadedAt} is not null)`,
      ),
    )
  return result.meta.changes > 0
}
