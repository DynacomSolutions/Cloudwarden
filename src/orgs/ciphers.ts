import { and, eq, inArray } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import { ApiError } from '../errors'
import { chunk, cipherJson } from '../vault/ciphers'
import {
  canManageAllCiphers,
  collectionAccess,
  loadUserAccess,
  type Member,
  mergeAccess,
  type UserAccess,
} from './access'

type CipherRecord = typeof schema.ciphers.$inferSelect

/** What a user may do with one organisation item, and the collections that grant it. */
export interface ItemAccess {
  edit: boolean
  viewPassword: boolean
  manage: boolean
  collectionIds: string[]
}

export interface OrgCipherRow {
  cipher: CipherRecord
  folderId: string | null
  access: ItemAccess
}

export function orgCipherJson(
  { cipher, folderId, access }: OrgCipherRow,
  attachments: Parameters<typeof cipherJson>[1] = null,
) {
  const canDelete = access.edit || access.manage
  return {
    ...cipherJson({ cipher, folderId }, attachments),
    organizationId: cipher.organizationUuid,
    organizationUseTotp: true,
    edit: access.edit,
    viewPassword: access.viewPassword,
    permissions: { delete: canDelete, restore: canDelete },
    collectionIds: access.collectionIds,
  }
}

/** The user's own folder for each cipher; folders are private even when ciphers are shared. */
export async function folderLinks(db: Db, userUuid: string): Promise<Map<string, string>> {
  const rows = await db
    .select({ cipher: schema.foldersCiphers.cipherUuid, folder: schema.foldersCiphers.folderUuid })
    .from(schema.foldersCiphers)
    .innerJoin(schema.folders, eq(schema.folders.uuid, schema.foldersCiphers.folderUuid))
    .where(eq(schema.folders.userUuid, userUuid))
  return new Map(rows.map((r) => [r.cipher, r.folder]))
}

/** Collection ids of each cipher, for the given organisations. */
async function collectionLinks(db: Db, orgUuids: string[]): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>()
  for (const part of chunk(orgUuids)) {
    const rows = await db
      .select({
        cipher: schema.ciphersCollections.cipherUuid,
        collection: schema.ciphersCollections.collectionUuid,
      })
      .from(schema.ciphersCollections)
      .innerJoin(
        schema.collections,
        eq(schema.collections.uuid, schema.ciphersCollections.collectionUuid),
      )
      .where(inArray(schema.collections.organizationUuid, part))
    for (const r of rows) out.set(r.cipher, [...(out.get(r.cipher) ?? []), r.collection])
  }
  return out
}

/** Effective access to an item through the user's own, group and blanket grants. */
export function itemAccess(ua: UserAccess, orgUuid: string, linked: string[]): ItemAccess | null {
  if (ua.accessAllOrgs.has(orgUuid)) {
    return { edit: true, viewPassword: true, manage: true, collectionIds: linked }
  }
  let merged: ReturnType<typeof mergeAccess> | undefined
  const ids: string[] = []
  for (const id of linked) {
    const a = collectionAccess(ua, orgUuid, id)
    if (!a) continue
    ids.push(id)
    merged = mergeAccess(merged, a)
  }
  if (!merged) return null
  return {
    edit: !merged.readOnly,
    viewPassword: !merged.hidePasswords,
    manage: merged.manage,
    collectionIds: ids,
  }
}

/** Every organisation item the user can reach, for sync. */
export async function listOrgCipherRows(
  db: Db,
  userUuid: string,
  ua?: UserAccess,
): Promise<OrgCipherRow[]> {
  const access = ua ?? (await loadUserAccess(db, userUuid))
  if (access.members.length === 0) return []
  const found = new Map<string, CipherRecord>()
  for (const part of chunk([...access.accessAllOrgs])) {
    const rows = await db
      .select()
      .from(schema.ciphers)
      .where(inArray(schema.ciphers.organizationUuid, part))
    for (const r of rows) found.set(r.uuid, r)
  }
  for (const part of chunk([...access.grants.keys()])) {
    const rows = await db
      .select({ c: schema.ciphers })
      .from(schema.ciphers)
      .innerJoin(
        schema.ciphersCollections,
        eq(schema.ciphersCollections.cipherUuid, schema.ciphers.uuid),
      )
      .where(inArray(schema.ciphersCollections.collectionUuid, part))
    for (const r of rows) found.set(r.c.uuid, r.c)
  }
  if (found.size === 0) return []
  const [links, folders] = await Promise.all([
    collectionLinks(
      db,
      access.members.map((m) => m.organizationUuid),
    ),
    folderLinks(db, userUuid),
  ])
  const out: OrgCipherRow[] = []
  for (const cipher of found.values()) {
    const a = itemAccess(access, cipher.organizationUuid as string, links.get(cipher.uuid) ?? [])
    if (a) out.push({ cipher, folderId: folders.get(cipher.uuid) ?? null, access: a })
  }
  return out.sort((a, b) => b.cipher.createdAt - a.cipher.createdAt)
}

export async function loadCipherById(db: Db, id: string): Promise<CipherRecord | undefined> {
  const [row] = await db.select().from(schema.ciphers).where(eq(schema.ciphers.uuid, id)).limit(1)
  return row
}

export async function linkedCollections(db: Db, cipherUuid: string): Promise<string[]> {
  const rows = await db
    .select({ id: schema.ciphersCollections.collectionUuid })
    .from(schema.ciphersCollections)
    .where(eq(schema.ciphersCollections.cipherUuid, cipherUuid))
  return rows.map((r) => r.id)
}

/** The user's access to an organisation item, or null when they cannot see it. */
export async function accessToCipher(
  db: Db,
  userUuid: string,
  cipher: CipherRecord,
  ua?: UserAccess,
): Promise<ItemAccess | null> {
  const access = ua ?? (await loadUserAccess(db, userUuid))
  return itemAccess(
    access,
    cipher.organizationUuid as string,
    await linkedCollections(db, cipher.uuid),
  )
}

/** Full access, as held by members who may manage every item (admin endpoints). */
export async function adminItemAccess(db: Db, cipher: CipherRecord): Promise<ItemAccess> {
  return {
    edit: true,
    viewPassword: true,
    manage: true,
    collectionIds: await linkedCollections(db, cipher.uuid),
  }
}

/** Throws unless every collection exists in the organisation and the member may add items to it. */
export async function assertWritableCollections(
  db: Db,
  userUuid: string,
  member: Member,
  orgUuid: string,
  collectionIds: string[],
) {
  const ids = [...new Set(collectionIds)]
  if (ids.length === 0) return
  let found = 0
  for (const part of chunk(ids)) {
    const rows = await db
      .select({ id: schema.collections.uuid })
      .from(schema.collections)
      .where(
        and(
          eq(schema.collections.organizationUuid, orgUuid),
          inArray(schema.collections.uuid, part),
        ),
      )
    found += rows.length
  }
  if (found !== ids.length) throw new ApiError(404, 'Collection not found.')
  if (canManageAllCiphers(member)) return
  const ua = await loadUserAccess(db, userUuid)
  for (const id of ids) {
    const a = collectionAccess(ua, orgUuid, id)
    if (!a) throw new ApiError(404, 'Collection not found.')
    if (a.readOnly)
      throw new ApiError(403, 'You do not have permission to add items to this collection.')
  }
}

/** Replaces the link between a cipher and the caller's folders (other members' folders are untouched). */
export function userFolderStatements(
  db: Db,
  userUuid: string,
  cipherUuid: string,
  folderId: string | null,
) {
  const unlink = db
    .delete(schema.foldersCiphers)
    .where(
      and(
        eq(schema.foldersCiphers.cipherUuid, cipherUuid),
        inArray(
          schema.foldersCiphers.folderUuid,
          db
            .select({ id: schema.folders.uuid })
            .from(schema.folders)
            .where(eq(schema.folders.userUuid, userUuid)),
        ),
      ),
    )
  return folderId
    ? [unlink, db.insert(schema.foldersCiphers).values({ cipherUuid, folderUuid: folderId })]
    : [unlink]
}
