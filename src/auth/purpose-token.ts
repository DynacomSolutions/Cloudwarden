import type { Bindings } from '../env'
import { toB64u, utf8 } from './crypto'
import { signingSecret, signJwt, verificationSecrets, verifyJwt } from './jwt'
import { issuerFor } from './middleware'

export interface PurposeClaims {
  nbf: number
  exp: number
  iss: string
  sub: string
  purpose: string
  email: string
  /** Optional extra subject, such as the organization id. */
  ref?: string
}

/** Purposes whose tokens only ever verify under their own derived key (no legacy fallback). */
const DERIVED_ONLY = new Set(['delete-organization'])

/** HKDF-SHA256 key for one purpose, so a token signed for it never verifies for another. */
async function purposeSecret(secret: string, purpose: string): Promise<string> {
  const base = await crypto.subtle.importKey('raw', utf8(secret), 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: utf8(`purpose-token:${purpose}`),
    },
    base,
    256,
  )
  return toB64u(new Uint8Array(bits))
}

/** Signs a short-lived, purpose-bound token (invitation links). Not usable as an access token. */
export async function signPurposeToken(
  env: Bindings,
  purpose: string,
  claims: { sub: string; email: string; ref?: string },
  ttlSeconds: number,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  const body: PurposeClaims = {
    nbf: now - 5,
    exp: now + ttlSeconds,
    iss: issuerFor(env.DOMAIN),
    purpose,
    ...claims,
  }
  return signJwt(body, await purposeSecret(signingSecret(env), purpose))
}

/** Verifies signature, expiry, issuer and purpose. Returns null on any mismatch. */
export async function verifyPurposeToken(
  env: Bindings,
  purpose: string,
  token: string,
): Promise<PurposeClaims | null> {
  const secrets = verificationSecrets(env)
  const derived = await Promise.all(secrets.map((x) => purposeSecret(x, purpose)))
  // Tokens issued before per-purpose keys (invitations, links) stay valid until they expire.
  const claims = await verifyJwt<PurposeClaims>(
    token,
    DERIVED_ONLY.has(purpose) ? derived : [...derived, ...secrets],
  )
  if (!claims || claims.purpose !== purpose || claims.iss !== issuerFor(env.DOMAIN)) return null
  return claims
}
