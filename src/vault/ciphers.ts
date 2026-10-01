import { and, eq, sql } from 'drizzle-orm'
import { z } from 'zod'
import type { Db } from '../db'
import { schema } from '../db'
import { ApiError } from '../errors'

export const CIPHER_PAYLOAD_KEYS = ['login', 'card', 'identity', 'secureNote', 'sshKey'] as const
type PayloadKey = (typeof CIPHER_PAYLOAD_KEYS)[number]

/** Cipher type number to the request/response property holding its payload. */
const TYPE_KEYS: Record<number, PayloadKey> = {
  1: 'login',
  2: 'secureNote',
  3: 'card',
  4: 'identity',
  5: 'sshKey',
}

export const STALE_MESSAGE =
  'The client copy of this cipher is out of date. Resync the client and try again.'

/** Max ids per statement: D1 allows 100 bound parameters, minus the ones used for filters. */
export const ID_CHUNK = 80

export const chunk = <T>(items: T[], size = ID_CHUNK): T[][] => {
  const out: T[][] = []
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size))
  return out
}

const opaque = z.unknown()
const nullishString = z.string().nullish()

/** Wire model for create/update. Type payloads are opaque: they hold encrypted strings. */
export const cipherSchema = z.object({
  type: z.number().int().min(1).max(5),
  name: z.string().min(1),
  notes: nullishString,
  folderId: nullishString,
  organizationId: nullishString,
  favorite: z.boolean().nullish(),
  reprompt: z.number().int().min(0).max(1).nullish(),
  key: nullishString,
  fields: opaque.optional(),
  passwordHistory: opaque.optional(),
  login: opaque.optional(),
  card: opaque.optional(),
  identity: opaque.optional(),
  secureNote: opaque.optional(),
  sshKey: opaque.optional(),
  lastKnownRevisionDate: nullishString,
})
export type CipherBody = z.infer<typeof cipherSchema>

/**
 * The stored `data` layout: a JSON object holding only the payload for the cipher's type.
 * Key rotation uses the same layout. With no type, every payload present is kept.
 */
export function packPayload(body: Record<string, unknown>, type?: number | null): string {
  const keys = type != null && TYPE_KEYS[type] ? [TYPE_KEYS[type]] : [...CIPHER_PAYLOAD_KEYS]
  return JSON.stringify(
    Object.fromEntries(keys.filter((k) => body[k] != null).map((k) => [k, body[k]])),
  )
}

const parseJson = (s: string | null): unknown => {
  if (s == null) return null
  try {
    return JSON.parse(s)
  } catch {
    return null
  }
}

const iso = (ms: number) => new Date(ms).toISOString()

export interface CipherRow {
  cipher: typeof schema.ciphers.$inferSelect
  folderId: string | null
}

export function cipherJson({ cipher, folderId }: CipherRow) {
  const data = (parseJson(cipher.data) ?? {}) as Partial<Record<PayloadKey, unknown>>
  const payload = Object.fromEntries(CIPHER_PAYLOAD_KEYS.map((k) => [k, data[k] ?? null]))
  return {
    object: 'cipherDetails',
    id: cipher.uuid,
    organizationId: null,
    folderId,
    type: cipher.atype,
    name: cipher.name,
    notes: cipher.notes,
    ...payload,
    favorite: cipher.favorite,
    fields: parseJson(cipher.fields),
    passwordHistory: parseJson(cipher.passwordHistory),
    attachments: null,
    organizationUseTotp: false,
    revisionDate: iso(cipher.updatedAt),
    creationDate: iso(cipher.createdAt),
    deletedDate: cipher.deletedAt == null ? null : iso(cipher.deletedAt),
    archivedDate: null,
    reprompt: cipher.reprompt ?? 0,
    key: cipher.key,
    edit: true,
    viewPassword: true,
    permissions: { delete: true, restore: true },
    collectionIds: [],
    data: data[TYPE_KEYS[cipher.atype] ?? 'login'] ?? null,
  }
}

/** All of a user's ciphers with their folder, newest first. No id lists, so no param limits. */
export async function listCipherRows(db: Db, userUuid: string): Promise<CipherRow[]> {
  const rows = await db
    .select({ cipher: schema.ciphers, folderId: schema.foldersCiphers.folderUuid })
    .from(schema.ciphers)
    .leftJoin(schema.foldersCiphers, eq(schema.foldersCiphers.cipherUuid, schema.ciphers.uuid))
    .where(eq(schema.ciphers.userUuid, userUuid))
    .orderBy(sql`${schema.ciphers.createdAt} desc`)
  return rows
}

export async function getCipherRow(
  db: Db,
  userUuid: string,
  id: string,
): Promise<CipherRow | undefined> {
  const [row] = await db
    .select({ cipher: schema.ciphers, folderId: schema.foldersCiphers.folderUuid })
    .from(schema.ciphers)
    .leftJoin(schema.foldersCiphers, eq(schema.foldersCiphers.cipherUuid, schema.ciphers.uuid))
    .where(and(eq(schema.ciphers.uuid, id), eq(schema.ciphers.userUuid, userUuid)))
    .limit(1)
  return row
}

export async function requireCipher(db: Db, userUuid: string, id: string): Promise<CipherRow> {
  const row = await getCipherRow(db, userUuid, id)
  if (!row) throw new ApiError(404, 'Cipher not found.')
  return row
}

/** Throws unless the folder exists and belongs to the user. */
export async function requireFolder(db: Db, userUuid: string, folderId: string): Promise<void> {
  const [f] = await db
    .select({ id: schema.folders.uuid })
    .from(schema.folders)
    .where(and(eq(schema.folders.uuid, folderId), eq(schema.folders.userUuid, userUuid)))
    .limit(1)
  if (!f) throw new ApiError(400, 'Invalid folder.', { folderId: ['Folder does not exist.'] })
}

export function rejectUnsupported(body: { organizationId?: string | null }) {
  // TODO(TASKS #63): organisation ciphers arrive with Phase 3.
  if (body.organizationId) throw new ApiError(400, 'Organizations are not supported yet.')
}

/** Column values shared by insert and update. */
export function cipherValues(body: CipherBody) {
  return {
    atype: body.type,
    name: body.name,
    notes: body.notes ?? null,
    fields: body.fields == null ? null : JSON.stringify(body.fields),
    data: packPayload(body, body.type),
    passwordHistory: body.passwordHistory == null ? null : JSON.stringify(body.passwordHistory),
    reprompt: body.reprompt ?? 0,
    key: body.key ?? null,
    favorite: body.favorite ?? false,
  }
}

/** Statements that point a cipher at a folder (or none), replacing any previous link. */
export function setFolderStatements(db: Db, cipherUuid: string, folderId: string | null) {
  const unlink = db
    .delete(schema.foldersCiphers)
    .where(eq(schema.foldersCiphers.cipherUuid, cipherUuid))
  return folderId
    ? [unlink, db.insert(schema.foldersCiphers).values({ cipherUuid, folderUuid: folderId })]
    : [unlink]
}

/** Rejects an update made from a client copy older than the stored cipher. */
export function checkRevision(cipher: { updatedAt: number }, lastKnown: string | null | undefined) {
  if (!lastKnown) return
  const known = Date.parse(lastKnown)
  if (Number.isNaN(known)) {
    throw new ApiError(400, 'The request is invalid.', {
      lastKnownRevisionDate: ['Invalid date.'],
    })
  }
  // Allow one second of slack for clients that round-trip dates at lower precision.
  if (cipher.updatedAt - known > 1000) throw new ApiError(400, STALE_MESSAGE)
}

/** Moves the user's revision date forward; include in every vault write batch. */
export const bumpRevision = (db: Db, userUuid: string, now: number) =>
  db.update(schema.users).set({ updatedAt: now }).where(eq(schema.users.uuid, userUuid))
