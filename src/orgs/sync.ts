import type { Db } from '../db'
import type { Bindings } from '../env'
import { attachmentsByCipher } from '../vault/attachments'
import { listAccessibleCollections, loadUserAccess } from './access'
import { listOrgCipherRows, orgCipherJson } from './ciphers'
import { listUserPolicies, policyJson } from './policies'
import { collectionDetailsJson } from './views'

/** The organisation parts of a sync response: collections, shared items and policies. */
export async function orgSyncData(env: Bindings, db: Db, userUuid: string) {
  const ua = await loadUserAccess(db, userUuid)
  const [collections, ciphers, policies] = await Promise.all([
    listAccessibleCollections(db, userUuid, ua),
    listOrgCipherRows(db, userUuid, ua),
    listUserPolicies(db, userUuid),
  ])
  const attachments = await attachmentsByCipher(
    env,
    db,
    ciphers.map((r) => r.cipher.uuid),
  )
  return {
    collections: collections.map((r) => collectionDetailsJson(r.collection, r.access)),
    ciphers: ciphers.map((r) => orgCipherJson(r, attachments.get(r.cipher.uuid) ?? null)),
    policies: policies.map(policyJson),
  }
}
