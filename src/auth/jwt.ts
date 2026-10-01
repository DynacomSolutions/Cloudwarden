import type { Bindings } from '../env'
import { fromB64u, toB64u, utf8 } from './crypto'

const HEADER = toB64u(utf8(JSON.stringify({ alg: 'HS256', typ: 'JWT' })))

const hmacKey = (secret: string, usage: 'sign' | 'verify') =>
  crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [usage])

/** Signing secret from `JWT_SECRET`. Refuses to run with a missing or short secret. */
export function signingSecret(env: Bindings): string {
  const secret = env.JWT_SECRET
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET must be set to at least 32 characters')
  }
  return secret
}

export async function signJwt(payload: object, secret: string): Promise<string> {
  const body = `${HEADER}.${toB64u(utf8(JSON.stringify(payload)))}`
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(secret, 'sign'), utf8(body))
  return `${body}.${toB64u(new Uint8Array(sig))}`
}

/**
 * Verifies an HS256 token against each candidate secret (current first, then the
 * previous one during rotation) and checks `nbf` and `exp`. Returns null on any failure.
 */
export async function verifyJwt<T extends { nbf?: number; exp?: number }>(
  token: string,
  secrets: string[],
  now = Math.floor(Date.now() / 1000),
): Promise<T | null> {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [h, p, s] = parts as [string, string, string]
  if (h !== HEADER) return null
  const sig = fromB64u(s)
  if (!sig) return null
  let valid = false
  for (const secret of secrets) {
    const ok = await crypto.subtle.verify(
      'HMAC',
      await hmacKey(secret, 'verify'),
      sig,
      utf8(`${h}.${p}`),
    )
    valid = valid || ok
  }
  if (!valid) return null
  const raw = fromB64u(p)
  if (!raw) return null
  try {
    const claims = JSON.parse(new TextDecoder().decode(raw)) as T
    if (typeof claims.exp !== 'number' || claims.exp <= now) return null
    if (typeof claims.nbf === 'number' && claims.nbf > now) return null
    return claims
  } catch {
    return null
  }
}

export const verificationSecrets = (env: Bindings): string[] => {
  const current = signingSecret(env)
  return env.JWT_SECRET_PREVIOUS ? [current, env.JWT_SECRET_PREVIOUS] : [current]
}
