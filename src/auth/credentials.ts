import { z } from 'zod'
import { ApiError } from '../errors'
import { type KdfParams, kdfProblem } from '../validation'

/** Nested KDF object used by clients 2026.9 and later. */
export const nestedKdf = z.object({
  kdfType: z.number().int(),
  iterations: z.number().int(),
  memory: z.number().int().nullish(),
  parallelism: z.number().int().nullish(),
})

/** `masterPasswordAuthentication` / `authenticationData`. */
export const authenticationData = z.object({
  salt: z.string().min(1),
  kdf: nestedKdf,
  masterPasswordAuthenticationHash: z.string().min(1),
})

/** `masterPasswordUnlock` / `unlockData`. */
export const unlockData = z.object({
  salt: z.string().min(1),
  kdf: nestedKdf,
  masterKeyWrappedUserKey: z.string().min(1),
})

export type AuthenticationData = z.infer<typeof authenticationData>
export type UnlockData = z.infer<typeof unlockData>

export const toKdfParams = (k: z.infer<typeof nestedKdf>): KdfParams => ({
  kdf: k.kdfType,
  kdfIterations: k.iterations,
  kdfMemory: k.memory ?? null,
  kdfParallelism: k.parallelism ?? null,
})

/**
 * Checks the nested payload is internally consistent and that its salt (the account email,
 * which is the KDF salt) matches `email`. Returns the validated KDF.
 */
export function checkNested(
  auth: AuthenticationData,
  unlock: UnlockData,
  email: string,
): KdfParams {
  const a = toKdfParams(auth.kdf)
  const u = toKdfParams(unlock.kdf)
  const same =
    a.kdf === u.kdf &&
    a.kdfIterations === u.kdfIterations &&
    (a.kdfMemory ?? null) === (u.kdfMemory ?? null) &&
    (a.kdfParallelism ?? null) === (u.kdfParallelism ?? null)
  if (!same) throw new ApiError(400, 'Authentication and unlock KDF settings differ.')
  const norm = (s: string) => s.trim().toLowerCase()
  if (norm(auth.salt) !== norm(email) || norm(unlock.salt) !== norm(email)) {
    throw new ApiError(400, 'The salt must match the account email.')
  }
  const problem = kdfProblem(a)
  if (problem) throw new ApiError(400, problem)
  return a
}
