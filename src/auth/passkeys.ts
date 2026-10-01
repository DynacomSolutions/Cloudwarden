// Passkey login (TASKS #125): credential rows, challenge purposes, option builders and the
// shared assertion check used by the token endpoint and the "enable encryption" update.
import { and, eq, lt } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import type { Bindings } from '../env'
import { toB64u, utf8 } from './crypto'
import { signPurposeToken, verifyPurposeToken } from './purpose-token'
import { clock, dig, lowerKeys } from './twofactor'
import {
  COSE_ES256,
  COSE_RS256,
  checkChallenge,
  createChallenge,
  originFor,
  rpIdFor,
  type StoredCredential,
  verifyAssertion,
  WebAuthnError,
} from './webauthn'

export type PasskeyRow = typeof schema.webauthnCredentials.$inferSelect

export const MAX_PASSKEYS = 5

/** Challenge purposes. Each is bound into the HMAC, so one cannot stand in for another. */
export const PASSKEY_CREATE = 'passkey-create'
export const PASSKEY_ASSERT = 'passkey-assert'
export const PASSKEY_LOGIN = 'passkey-login'
/** Subject of anonymous (pre-login) challenges. */
const ANONYMOUS = 'anonymous'

const TOKEN_TTL_S = 5 * 60

/** Values of `WebauthnLoginCredentialPrfStatus` in the web client. */
export const PrfStatus = { Enabled: 0, Supported: 1, Unsupported: 2 } as const

export const prfStatus = (r: PasskeyRow): number =>
  r.encryptedUserKey && r.encryptedPublicKey && r.encryptedPrivateKey
    ? PrfStatus.Enabled
    : r.supportsPrf
      ? PrfStatus.Supported
      : PrfStatus.Unsupported

/** One row of `GET /api/webauthn`. Keys are only echoed when a keyset exists. */
export const credentialJson = (r: PasskeyRow) => ({
  id: r.uuid,
  name: r.name,
  prfStatus: prfStatus(r),
  encryptedPublicKey: r.encryptedPublicKey,
  encryptedUserKey: r.encryptedUserKey,
  object: 'webauthnCredential',
})

/** `WebAuthnPrfOption` as the identity and sync responses carry it, or null without a keyset. */
export function prfOptionJson(r: PasskeyRow) {
  if (prfStatus(r) !== PrfStatus.Enabled) return null
  return {
    EncryptedPrivateKey: r.encryptedPrivateKey,
    EncryptedUserKey: r.encryptedUserKey,
    CredentialId: r.credentialId,
    Transports: parseTransports(r.transports),
  }
}

export function parseTransports(raw: string): string[] {
  try {
    const v = JSON.parse(raw)
    return Array.isArray(v) ? v.filter((t): t is string => typeof t === 'string') : []
  } catch {
    return []
  }
}

/** Keeps only transport names the WebAuthn spec defines. */
export const KNOWN_TRANSPORTS = ['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card']
export const cleanTransports = (v: unknown): string[] =>
  Array.isArray(v) ? [...new Set(v.filter((t) => KNOWN_TRANSPORTS.includes(t as string)))] : []

export const storedCredential = (r: PasskeyRow): StoredCredential => ({
  id: 0,
  name: r.name,
  credentialId: r.credentialId,
  alg: r.alg,
  jwk: JSON.parse(r.jwk) as JsonWebKey,
  signCount: r.signCount,
})

const descriptor = (r: PasskeyRow) => ({
  type: 'public-key',
  id: r.credentialId,
  transports: parseTransports(r.transports),
})

/** A challenge plus the opaque token the client must send back with its response. */
async function challengeWithToken(env: Bindings, purpose: string, subject: string) {
  const challenge = await createChallenge(env, purpose, subject, clock.now())
  const token = await signPurposeToken(
    env,
    purpose,
    { sub: subject, email: '', ref: challenge },
    TOKEN_TTL_S,
  )
  return { challenge, token }
}

/** Challenge extracted from a token, when it is genuine and for this purpose and subject. */
async function challengeFromToken(env: Bindings, purpose: string, subject: string, t: string) {
  const claims = await verifyPurposeToken(env, purpose, t)
  if (claims?.sub !== subject || !claims.ref) return null
  const ts = await checkChallenge(env, purpose, subject, claims.ref, clock.now())
  return ts === null ? null : { challenge: claims.ref, ts }
}

export async function creationOptions(
  env: Bindings,
  user: { uuid: string; email: string; name: string },
  existing: PasskeyRow[],
) {
  const { challenge, token } = await challengeWithToken(env, PASSKEY_CREATE, user.uuid)
  return {
    options: {
      challenge,
      rp: { id: rpIdFor(env), name: 'Cloudwarden' },
      user: { id: toB64u(utf8(user.uuid)), name: user.email, displayName: user.name || user.email },
      pubKeyCredParams: [
        { type: 'public-key', alg: COSE_ES256 },
        { type: 'public-key', alg: COSE_RS256 },
      ],
      timeout: 60000,
      attestation: 'none',
      excludeCredentials: existing.map(descriptor),
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
      extensions: {},
    },
    token,
    object: 'webauthnCredentialCreateOptions',
  }
}

/** Assertion options for the signed in "enable encryption" step (user's own credentials). */
export async function ownAssertionOptions(env: Bindings, userUuid: string, own: PasskeyRow[]) {
  const { challenge, token } = await challengeWithToken(env, PASSKEY_ASSERT, userUuid)
  return {
    options: {
      challenge,
      timeout: 60000,
      rpId: rpIdFor(env),
      allowCredentials: own.map(descriptor),
      userVerification: 'required',
      extensions: {},
    },
    token,
    object: 'webauthnCredentialAssertionOptions',
  }
}

/** Assertion options for login. No account is known yet, so credentials are discoverable. */
export async function loginAssertionOptions(env: Bindings) {
  const { challenge, token } = await challengeWithToken(env, PASSKEY_LOGIN, ANONYMOUS)
  return {
    options: {
      challenge,
      timeout: 60000,
      rpId: rpIdFor(env),
      allowCredentials: [],
      userVerification: 'required',
      extensions: {},
    },
    token,
    object: 'webAuthnLoginAssertionOptions',
  }
}

/** `seen.ts` receives the challenge time so the caller can spend it (single use). */
export const registrationChallengeOk =
  (env: Bindings, userUuid: string, token: string, seen: { ts?: number } = {}) =>
  async (challenge: string) => {
    const got = await challengeFromToken(env, PASSKEY_CREATE, userUuid, token)
    if (got === null || got.challenge !== challenge) return false
    seen.ts = got.ts
    return true
  }

/** Spends a creation challenge: true only for the first use of anything newer than the last. */
export async function spendCreateChallenge(db: Db, userUuid: string, ts: number) {
  const result = await db
    .update(schema.users)
    .set({ passkeyCreateAt: ts })
    .where(and(eq(schema.users.uuid, userUuid), lt(schema.users.passkeyCreateAt, ts)))
  return result.meta.changes > 0
}

export interface VerifiedAssertion {
  credential: PasskeyRow
  signCount: number
  challengeAt: number
}

/** Credential id from an assertion response, whichever casing the client used. */
export function assertionCredentialId(deviceResponse: unknown): string {
  const lower = lowerKeys(deviceResponse)
  const id = dig(lower, 'rawid') ?? dig(lower, 'id')
  return typeof id === 'string' ? id : ''
}

/**
 * Verifies a passkey assertion against `credential` (user verification required) and the
 * challenge named by `token`. Throws WebAuthnError on any problem.
 */
export async function verifyPasskeyAssertion(
  env: Bindings,
  opts: {
    purpose: string
    subject: string
    token: string
    deviceResponse: unknown
    credential: PasskeyRow
  },
): Promise<VerifiedAssertion> {
  const lower = lowerKeys(opts.deviceResponse)
  const field = (name: string) => {
    const v = dig(lower, 'response', name)
    return typeof v === 'string' ? v : ''
  }
  let challengeAt: number | null = null
  const signCount = await verifyAssertion({
    credential: storedCredential(opts.credential),
    authenticatorData: field('authenticatordata'),
    clientDataJSON: field('clientdatajson'),
    signature: field('signature'),
    rpId: rpIdFor(env),
    origin: originFor(env),
    requireUv: true,
    challengeOk: async (challenge) => {
      const got = await challengeFromToken(env, opts.purpose, opts.subject, opts.token)
      if (!got || got.challenge !== challenge) return false
      challengeAt = got.ts
      return true
    },
  })
  if (challengeAt === null) throw new WebAuthnError('Invalid challenge')
  // userHandle, when the authenticator returns one, must name the account that owns the key.
  const handle = dig(lower, 'response', 'userhandle')
  if (typeof handle === 'string' && handle !== '') {
    if (handle !== toB64u(utf8(opts.credential.userUuid))) {
      throw new WebAuthnError('User handle mismatch')
    }
  }
  return { credential: opts.credential, signCount, challengeAt }
}

/**
 * Records a verified assertion. The WHERE clause makes a challenge usable once: a replay finds
 * `last_challenge_at` already at or past its time and changes nothing. Returns true on success.
 */
export async function spendAssertion(
  db: Db,
  v: VerifiedAssertion,
  extra: Partial<PasskeyRow> = {},
): Promise<boolean> {
  const result = await db
    .update(schema.webauthnCredentials)
    .set({ ...extra, signCount: v.signCount, lastChallengeAt: v.challengeAt })
    .where(
      and(
        eq(schema.webauthnCredentials.uuid, v.credential.uuid),
        lt(schema.webauthnCredentials.lastChallengeAt, v.challengeAt),
      ),
    )
  return result.meta.changes > 0
}
