// Synthetic WebAuthn authenticator used by the tests. It builds real attestation objects
// and assertions signed with WebCrypto, so the server verifies genuine signatures.
import { toB64u } from '../src/auth/crypto'

type Cbor = number | string | Uint8Array | Cbor[] | Map<Cbor, Cbor>

const head = (major: number, n: number): number[] => {
  if (n < 24) return [(major << 5) | n]
  if (n < 256) return [(major << 5) | 24, n]
  return [(major << 5) | 25, n >> 8, n & 0xff]
}

export function cborEncode(v: Cbor): Uint8Array {
  const out: number[] = []
  const walk = (x: Cbor) => {
    if (typeof x === 'number') {
      out.push(...(x >= 0 ? head(0, x) : head(1, -1 - x)))
    } else if (typeof x === 'string') {
      const b = new TextEncoder().encode(x)
      out.push(...head(3, b.length), ...b)
    } else if (x instanceof Uint8Array) {
      out.push(...head(2, x.length), ...x)
    } else if (Array.isArray(x)) {
      out.push(...head(4, x.length))
      for (const i of x) walk(i)
    } else {
      out.push(...head(5, x.size))
      for (const [k, val] of x) {
        walk(k)
        walk(val)
      }
    }
  }
  walk(v)
  return Uint8Array.from(out)
}

const sha256 = async (d: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', d))
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}
const u32 = (n: number) => Uint8Array.from([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255])

const derInt = (b: Uint8Array) => {
  let i = 0
  while (i < b.length - 1 && b[i] === 0) i++
  let v = b.subarray(i)
  if ((v[0] as number) & 0x80) v = concat(Uint8Array.of(0), v)
  return concat(Uint8Array.of(0x02, v.length), v)
}
export function rawToDer(raw: Uint8Array): Uint8Array {
  const body = concat(derInt(raw.subarray(0, 32)), derInt(raw.subarray(32)))
  return concat(Uint8Array.of(0x30, body.length), body)
}

export interface Authenticator {
  alg: -7 | -257
  credentialId: Uint8Array
  signCount: number
  privateKey: CryptoKey
  cose: Map<Cbor, Cbor>
}

export async function newAuthenticator(alg: -7 | -257 = -7): Promise<Authenticator> {
  const credentialId = crypto.getRandomValues(new Uint8Array(32))
  if (alg === -7) {
    const kp = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
    ])) as CryptoKeyPair
    const jwk = (await crypto.subtle.exportKey('jwk', kp.publicKey)) as JsonWebKey
    const dec = (s: string) =>
      Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
    const cose = new Map<Cbor, Cbor>([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, dec(jwk.x as string)],
      [-3, dec(jwk.y as string)],
    ])
    return { alg, credentialId, signCount: 0, privateKey: kp.privateKey, cose }
  }
  const kp = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: Uint8Array.of(1, 0, 1),
      hash: 'SHA-256',
    },
    true,
    ['sign'],
  )) as CryptoKeyPair
  const jwk = (await crypto.subtle.exportKey('jwk', kp.publicKey)) as JsonWebKey
  const dec = (s: string) =>
    Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
  const cose = new Map<Cbor, Cbor>([
    [1, 3],
    [3, -257],
    [-1, dec(jwk.n as string)],
    [-2, dec(jwk.e as string)],
  ])
  return { alg, credentialId, signCount: 0, privateKey: kp.privateKey, cose }
}

export const clientData = (type: string, challenge: string, origin: string) =>
  new TextEncoder().encode(JSON.stringify({ type, challenge, origin, crossOrigin: false }))

export interface Overrides {
  rpId?: string
  flags?: number
  origin?: string
  fmt?: string
  /** Transports reported with a registration. */
  transports?: string[]
}

/** Registration response in the shape the web client sends for the 2FA setup. */
export async function register(
  a: Authenticator,
  challenge: string,
  rpId: string,
  origin: string,
  o: Overrides = {},
) {
  const cd = clientData('webauthn.create', challenge, o.origin ?? origin)
  const coseBytes = cborEncode(a.cose)
  const authData = concat(
    await sha256(new TextEncoder().encode(o.rpId ?? rpId)),
    Uint8Array.of(o.flags ?? 0x41),
    u32(a.signCount),
    new Uint8Array(16),
    Uint8Array.of(a.credentialId.length >> 8, a.credentialId.length & 255),
    a.credentialId,
    coseBytes,
  )
  const attestationObject = cborEncode(
    new Map<Cbor, Cbor>([
      ['fmt', o.fmt ?? 'none'],
      ['attStmt', new Map()],
      ['authData', authData],
    ]),
  )
  return {
    id: toB64u(a.credentialId),
    rawId: toB64u(a.credentialId),
    type: 'public-key',
    extensions: {},
    response: {
      AttestationObject: toB64u(attestationObject),
      clientDataJson: toB64u(cd),
      ...(o.transports ? { transports: o.transports } : {}),
    },
  }
}

export interface AssertionOpts extends Overrides {
  signCount?: number
  /** Raw user handle bytes returned with the assertion (null when absent). */
  userHandle?: Uint8Array | null
}

export async function assert(
  a: Authenticator,
  challenge: string,
  rpId: string,
  origin: string,
  o: AssertionOpts = {},
) {
  a.signCount = o.signCount ?? a.signCount + 1
  const cd = clientData('webauthn.get', challenge, o.origin ?? origin)
  const authData = concat(
    await sha256(new TextEncoder().encode(o.rpId ?? rpId)),
    Uint8Array.of(o.flags ?? 0x01),
    u32(a.signCount),
  )
  const signed = concat(authData, await sha256(cd))
  const raw = new Uint8Array(
    await crypto.subtle.sign(
      a.alg === -7 ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSASSA-PKCS1-v1_5' },
      a.privateKey,
      signed,
    ),
  )
  const sig = a.alg === -7 ? rawToDer(raw) : raw
  return {
    id: toB64u(a.credentialId),
    rawId: toB64u(a.credentialId),
    type: 'public-key',
    extensions: {},
    response: {
      authenticatorData: toB64u(authData),
      clientDataJson: toB64u(cd),
      signature: toB64u(sig),
      userHandle: o.userHandle ? toB64u(o.userHandle) : null,
    },
  }
}
