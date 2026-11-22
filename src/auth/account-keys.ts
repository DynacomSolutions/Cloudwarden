import { z } from 'zod'
import type { User } from '../env'
import type { AccountKeysV2 } from './session'

// Account key shapes of the 2026.11 clients (`AccountKeysRequestModel` and its parts).
export const publicKeyPair = z.object({
  wrappedPrivateKey: z.string().min(1),
  publicKey: z.string().min(1),
  signedPublicKey: z.string().nullish(),
})
export const signatureKeyPair = z.object({
  signatureAlgorithm: z.string().nullish(),
  wrappedSigningKey: z.string().nullish(),
  verifyingKey: z.string().nullish(),
})
export const securityState = z.object({
  securityState: z.string().nullish(),
  securityVersion: z.number().int(),
})

/** The V2 parts of account keys as stored, or null when the account has none. */
export function v2KeysOf(keys: {
  publicKeyEncryptionKeyPair?: z.infer<typeof publicKeyPair> | null
  signatureKeyPair?: z.infer<typeof signatureKeyPair> | null
  securityState?: z.infer<typeof securityState> | null
}): AccountKeysV2 | null {
  const signedPublicKey = keys.publicKeyEncryptionKeyPair?.signedPublicKey ?? null
  if (!signedPublicKey && !keys.signatureKeyPair && !keys.securityState) return null
  const sig = keys.signatureKeyPair
  const state = keys.securityState
  return {
    signedPublicKey,
    signatureKeyPair: sig
      ? {
          signatureAlgorithm: sig.signatureAlgorithm ?? null,
          wrappedSigningKey: sig.wrappedSigningKey ?? null,
          verifyingKey: sig.verifyingKey ?? null,
        }
      : null,
    securityState: state
      ? { securityState: state.securityState ?? null, securityVersion: state.securityVersion }
      : null,
  }
}

/** The request body `AccountKeysRequestModel` (SSO JIT finish, key rotation). */
export const accountKeysRequest = z.object({
  userKeyEncryptedAccountPrivateKey: z.string().min(1).nullish(),
  accountPublicKey: z.string().nullish(),
  publicKeyEncryptionKeyPair: publicKeyPair.nullish(),
  signatureKeyPair: signatureKeyPair.nullish(),
  securityState: securityState.nullish(),
})

/** The public and wrapped private key of an account keys request, with its V2 parts. */
export function resolveAccountKeys(keys: z.infer<typeof accountKeysRequest>) {
  const pair = keys.publicKeyEncryptionKeyPair
  const publicKey = keys.accountPublicKey ?? pair?.publicKey ?? null
  const privateKey = keys.userKeyEncryptedAccountPrivateKey ?? pair?.wrappedPrivateKey ?? null
  return { publicKey, privateKey, v2: v2KeysOf(keys) }
}

/** Column values that set the keys of an account that has none; an account that has them keeps them. */
export function newAccountKeyColumns(
  user: Pick<User, 'publicKey' | 'privateKey'>,
  keys: { publicKey: string | null; privateKey: string | null; v2: AccountKeysV2 | null },
) {
  if (user.publicKey || user.privateKey || !keys.publicKey || !keys.privateKey) return {}
  return {
    publicKey: keys.publicKey,
    privateKey: keys.privateKey,
    accountKeysV2: keys.v2 ? JSON.stringify(keys.v2) : null,
  }
}
