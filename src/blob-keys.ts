/**
 * R2 key namespace guard. The `ATTACHMENTS` bucket also holds backups (`backups/`), so no code path
 * that reads, serves, signs or deletes blobs from a key derived from user data may touch that prefix.
 */
export const RESERVED_PREFIXES = ['backups/']

export function isReservedBlobKey(key: string): boolean {
  const k = key.replace(/^\/+/, '').toLowerCase()
  return RESERVED_PREFIXES.some(
    (p) => k.startsWith(p) || k.includes(`/../${p}`) || k.startsWith(`../${p}`),
  )
}

/** Throws when a user-influenced key points into a reserved prefix. Call before any blob access. */
export function assertUserBlobKey(key: string): string {
  if (isReservedBlobKey(key)) throw new Error('reserved blob key')
  return key
}
