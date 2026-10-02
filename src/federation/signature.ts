// HTTP Message Signatures (RFC 9421) with Ed25519 and Content-Digest (RFC 9530) for every
// server-to-server federation request (TASKS #301). The covered components are fixed, so a
// verifier never has to trust a component list chosen by the sender.
import { fromB64u, toB64u, utf8 } from '../auth/crypto'

export const SIGNATURE_LABEL = 'fed'
export const USER_HEADER = 'cloudwarden-federated-user'
export const DEVICE_HEADER = 'cloudwarden-federated-device'
export const COMPONENTS = [
  '@method',
  '@target-uri',
  'content-type',
  'content-digest',
  USER_HEADER,
  DEVICE_HEADER,
] as const
/** Accepted clock skew and signature lifetime. */
export const MAX_SKEW_SECONDS = 300
const TAG = 'cloudwarden-federation'

const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))
const fromB64 = (s: string): Uint8Array | null => {
  try {
    return Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0))
  } catch {
    return null
  }
}

export async function contentDigest(body: Uint8Array): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', body))
  // Encoded in chunks: spreading a large array into String.fromCharCode overflows the stack.
  let bin = ''
  for (let i = 0; i < d.length; i += 4096) bin += String.fromCharCode(...d.subarray(i, i + 4096))
  return `sha-256=:${btoa(bin)}:`
}

export interface SignedParams {
  created: number
  expires: number
  nonce: string
  keyid: string
}

const paramsString = (p: SignedParams) =>
  `(${COMPONENTS.map((c) => `"${c}"`).join(' ')});created=${p.created};expires=${p.expires};nonce="${p.nonce}";keyid="${p.keyid}";alg="ed25519";tag="${TAG}"`

export function signatureBase(
  req: { method: string; url: string; headers: Headers },
  params: SignedParams,
): string {
  const value = (c: (typeof COMPONENTS)[number]) => {
    if (c === '@method') return req.method.toUpperCase()
    if (c === '@target-uri') return req.url
    return (req.headers.get(c) ?? '').trim()
  }
  return [
    ...COMPONENTS.map((c) => `"${c}": ${value(c)}`),
    `"@signature-params": ${paramsString(params)}`,
  ].join('\n')
}

/** Adds Content-Digest, Signature-Input and Signature to `headers`. */
export async function signRequest(
  method: string,
  url: string,
  headers: Headers,
  body: Uint8Array,
  keyid: string,
  privateKey: CryptoKey,
  now = Date.now(),
): Promise<void> {
  headers.set('content-digest', await contentDigest(body))
  if (!headers.has(USER_HEADER)) headers.set(USER_HEADER, '-')
  if (!headers.has(DEVICE_HEADER)) headers.set(DEVICE_HEADER, '-')
  const created = Math.floor(now / 1000)
  const params: SignedParams = {
    created,
    expires: created + MAX_SKEW_SECONDS,
    nonce: toB64u(crypto.getRandomValues(new Uint8Array(18))),
    keyid,
  }
  const base = signatureBase({ method, url, headers }, params)
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', privateKey, utf8(base)))
  headers.set('signature-input', `${SIGNATURE_LABEL}=${paramsString(params)}`)
  headers.set('signature', `${SIGNATURE_LABEL}=:${b64(sig)}:`)
}

export interface ParsedSignature {
  params: SignedParams
  signature: Uint8Array
}

/** Parses our own fixed signature shape; anything else is rejected. */
export function parseSignature(headers: Headers): ParsedSignature | null {
  const input = headers.get('signature-input') ?? ''
  const sig = headers.get('signature') ?? ''
  const expected = `(${COMPONENTS.map((c) => `"${c}"`).join(' ')})`
  const m =
    /^fed=(\([^)]*\));created=(\d+);expires=(\d+);nonce="([A-Za-z0-9_-]{16,64})";keyid="([0-9a-f-]{36})";alg="ed25519";tag="cloudwarden-federation"$/.exec(
      input,
    )
  const s = /^fed=:([A-Za-z0-9+/=]+):$/.exec(sig)
  if (!m || !s || m[1] !== expected) return null
  const signature = fromB64(s[1] as string)
  if (!signature) return null
  return {
    params: {
      created: Number(m[2]),
      expires: Number(m[3]),
      nonce: m[4] as string,
      keyid: m[5] as string,
    },
    signature,
  }
}

export type VerifyFailure = 'malformed' | 'expired' | 'digest' | 'signature'

/**
 * Checks the time window, the body digest and the signature against `publicKeyB64u`.
 * Replay protection (the nonce) is the caller's job, since it needs storage.
 */
export async function verifyRequest(
  req: { method: string; url: string; headers: Headers },
  body: Uint8Array,
  parsed: ParsedSignature,
  publicKeyB64u: string,
  now = Date.now(),
): Promise<VerifyFailure | null> {
  const t = Math.floor(now / 1000)
  const { created, expires } = parsed.params
  if (
    created > t + MAX_SKEW_SECONDS ||
    created < t - MAX_SKEW_SECONDS ||
    expires < t ||
    expires - created > MAX_SKEW_SECONDS
  ) {
    return 'expired'
  }
  if ((req.headers.get('content-digest') ?? '') !== (await contentDigest(body))) return 'digest'
  const raw = fromB64u(publicKeyB64u)
  if (!raw) return 'malformed'
  const key = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify'])
  const ok = await crypto.subtle.verify(
    'Ed25519',
    key,
    parsed.signature,
    utf8(signatureBase(req, parsed.params)),
  )
  return ok ? null : 'signature'
}
