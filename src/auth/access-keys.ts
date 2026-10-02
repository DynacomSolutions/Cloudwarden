import type { Bindings } from '../env'
import { fromB64u, toB64u, utf8 } from './crypto'
import { signingSecret, signJwt, verificationSecrets, verifyJwt } from './jwt'

/**
 * Asymmetric access tokens (TASKS #285). With `JWT_SIGNING_KEY` set (a P-256 private key, PKCS#8,
 * base64 DER or PEM) access tokens are signed ES256 with a `kid`, and the public keys are
 * published as a JWKS next to an OpenID discovery document, so third-party services such as a
 * Key Connector can validate them. Without it, tokens stay HS256 (`JWT_SECRET`). HS256 tokens are
 * always accepted while they are valid, and `JWT_SIGNING_KEY_PREVIOUS` keeps an old key's tokens
 * valid during a rotation.
 */

const ALG = { name: 'ECDSA', namedCurve: 'P-256' } as const

interface KeyPair {
  kid: string
  privateKey: CryptoKey
  publicJwk: JsonWebKey
  publicKey: CryptoKey
}

const cache = new Map<string, Promise<KeyPair>>()

function pkcs8From(value: string): Uint8Array {
  const body = value.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, '').replace(/\s+/g, '')
  const der = fromB64u(body)
  if (!der) throw new Error('JWT_SIGNING_KEY is not valid base64')
  return der
}

async function load(value: string): Promise<KeyPair> {
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8From(value), ALG, true, ['sign'])
  const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey
  const publicJwk: JsonWebKey = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }
  // RFC 7638 thumbprint as the key id.
  const thumb = await crypto.subtle.digest(
    'SHA-256',
    utf8(JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y })),
  )
  const kid = toB64u(new Uint8Array(thumb))
  const publicKey = await crypto.subtle.importKey('jwk', publicJwk, ALG, true, ['verify'])
  return { kid, privateKey, publicJwk, publicKey }
}

const keyPair = (value: string) => {
  let p = cache.get(value)
  if (!p) {
    p = load(value)
    cache.set(value, p)
  }
  return p
}

async function publicKeys(env: Bindings): Promise<KeyPair[]> {
  const values = [env.JWT_SIGNING_KEY, env.JWT_SIGNING_KEY_PREVIOUS].filter((v): v is string => !!v)
  return Promise.all(values.map(keyPair))
}

/** Signs access token claims: ES256 when a signing key is configured, else HS256. */
export async function signAccessJwt(env: Bindings, claims: object): Promise<string> {
  if (!env.JWT_SIGNING_KEY) return signJwt(claims, signingSecret(env))
  const k = await keyPair(env.JWT_SIGNING_KEY)
  const header = toB64u(utf8(JSON.stringify({ alg: 'ES256', kid: k.kid, typ: 'JWT' })))
  const body = `${header}.${toB64u(utf8(JSON.stringify(claims)))}`
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.privateKey, utf8(body))
  return `${body}.${toB64u(new Uint8Array(sig))}`
}

/** Verifies an access token signed either way; checks `exp` and `nbf`. Null on any failure. */
export async function verifyAccessJwt<T extends { nbf?: number; exp?: number }>(
  env: Bindings,
  token: string,
  now = Math.floor(Date.now() / 1000),
): Promise<T | null> {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  const [h, p, s] = parts as [string, string, string]
  let header: { alg?: string; kid?: string }
  try {
    header = JSON.parse(new TextDecoder().decode(fromB64u(h) ?? new Uint8Array()))
  } catch {
    return null
  }
  if (header.alg === 'HS256') return verifyJwt<T>(token, verificationSecrets(env), now)
  if (header.alg !== 'ES256' || typeof header.kid !== 'string') return null
  const key = (await publicKeys(env)).find((k) => k.kid === header.kid)
  const sig = fromB64u(s)
  if (!key || !sig) return null
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key.publicKey,
    sig,
    utf8(`${h}.${p}`),
  )
  if (!ok) return null
  try {
    const claims = JSON.parse(new TextDecoder().decode(fromB64u(p) ?? new Uint8Array())) as T
    if (typeof claims.exp !== 'number' || claims.exp <= now) return null
    if (typeof claims.nbf === 'number' && claims.nbf > now) return null
    return claims
  } catch {
    return null
  }
}

/** The JWKS document: current and previous public keys. Empty without a signing key. */
export async function jwks(env: Bindings) {
  return {
    keys: (await publicKeys(env)).map((k) => ({
      ...k.publicJwk,
      kid: k.kid,
      use: 'sig',
      alg: 'ES256',
    })),
  }
}
