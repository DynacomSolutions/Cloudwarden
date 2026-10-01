import type { Bindings } from '../env'
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
  return signJwt(body, signingSecret(env))
}

/** Verifies signature, expiry, issuer and purpose. Returns null on any mismatch. */
export async function verifyPurposeToken(
  env: Bindings,
  purpose: string,
  token: string,
): Promise<PurposeClaims | null> {
  const claims = await verifyJwt<PurposeClaims>(token, verificationSecrets(env))
  if (!claims || claims.purpose !== purpose || claims.iss !== issuerFor(env.DOMAIN)) return null
  return claims
}
