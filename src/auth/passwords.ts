import { fromB64u, pbkdf2Sha256, timingSafeEqual, toB64u } from './crypto'

/** Workers cap PBKDF2 at 100000 iterations. See docs/adr/0002-password-hashing.md. */
export const SERVER_PBKDF2_ITERATIONS = 100_000

export interface StoredPassword {
  passwordHash: string
  salt: string
  passwordIterations: number
}

/** Re-hashes the client-supplied masterPasswordHash for storage. */
export async function hashMasterPassword(masterPasswordHash: string): Promise<StoredPassword> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const hash = await pbkdf2Sha256(masterPasswordHash, salt, SERVER_PBKDF2_ITERATIONS)
  return {
    passwordHash: toB64u(hash),
    salt: toB64u(salt),
    passwordIterations: SERVER_PBKDF2_ITERATIONS,
  }
}

// Used so unknown accounts cost the same as known ones (no timing oracle).
const DUMMY_SALT = crypto.getRandomValues(new Uint8Array(16))
const DUMMY_HASH = crypto.getRandomValues(new Uint8Array(32))

/** Constant-time verification. Pass null for an unknown account; it always returns false. */
export async function verifyMasterPassword(
  stored: StoredPassword | null,
  masterPasswordHash: string,
): Promise<boolean> {
  const salt = (stored && fromB64u(stored.salt)) || DUMMY_SALT
  const expected = (stored && fromB64u(stored.passwordHash)) || DUMMY_HASH
  const derived = await pbkdf2Sha256(
    masterPasswordHash,
    salt,
    stored?.passwordIterations ?? SERVER_PBKDF2_ITERATIONS,
  )
  return timingSafeEqual(derived, expected) && stored !== null
}
