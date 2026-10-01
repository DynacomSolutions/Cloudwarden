import type { Bindings } from '../env'
import { type CborValue, decodeCbor, decodeCborPrefix } from './cbor'
import { fromB64u, timingSafeEqual, toB64u, utf8 } from './crypto'
import { signingSecret, verificationSecrets } from './jwt'

/** How long a registration or assertion challenge stays valid. */
export const CHALLENGE_TTL_MS = 5 * 60 * 1000

export const COSE_ES256 = -7
export const COSE_RS256 = -257

export const rpIdFor = (env: Pick<Bindings, 'DOMAIN'>): string => new URL(env.DOMAIN).hostname
export const originFor = (env: Pick<Bindings, 'DOMAIN'>): string => new URL(env.DOMAIN).origin

const hmac = async (secret: string, data: Uint8Array) =>
  new Uint8Array(
    await crypto.subtle.sign(
      'HMAC',
      await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
        'sign',
      ]),
      data,
    ),
  )

const macInput = (purpose: string, userUuid: string, head: Uint8Array) => {
  const prefix = utf8(`${purpose}\0${userUuid}\0`)
  const out = new Uint8Array(prefix.length + head.length)
  out.set(prefix)
  out.set(head, prefix.length)
  return out
}

/**
 * Stateless challenge: 8 byte timestamp, 16 random bytes, then an HMAC binding both to the
 * purpose and the user. Nothing is stored; the server recognises its own challenges.
 */
export async function createChallenge(
  env: Bindings,
  purpose: string,
  userUuid: string,
  now = Date.now(),
): Promise<string> {
  const head = new Uint8Array(24)
  new DataView(head.buffer).setBigUint64(0, BigInt(now))
  head.set(crypto.getRandomValues(new Uint8Array(16)), 8)
  const mac = await hmac(signingSecret(env), macInput(purpose, userUuid, head))
  const out = new Uint8Array(56)
  out.set(head)
  out.set(mac, 24)
  return toB64u(out)
}

/** Returns the challenge timestamp when it is genuine, unexpired and for this user. */
export async function checkChallenge(
  env: Bindings,
  purpose: string,
  userUuid: string,
  challenge: string,
  now = Date.now(),
): Promise<number | null> {
  const raw = fromB64u(challenge)
  if (raw?.length !== 56) return null
  const head = raw.subarray(0, 24)
  let ok = false
  for (const secret of verificationSecrets(env)) {
    const mac = await hmac(secret, macInput(purpose, userUuid, head))
    ok = timingSafeEqual(mac, raw.subarray(24)) || ok
  }
  if (!ok) return null
  const ts = Number(new DataView(raw.buffer, raw.byteOffset).getBigUint64(0))
  if (ts > now + 60_000 || now - ts > CHALLENGE_TTL_MS) return null
  return ts
}

export interface StoredCredential {
  /** Small integer chosen by the client (1 to 5), shown in the settings page. */
  id: number
  name: string
  /** Credential ID, base64url. */
  credentialId: string
  alg: number
  /** Public key as a JWK. */
  jwk: JsonWebKey
  signCount: number
}

interface ClientData {
  type?: unknown
  challenge?: unknown
  origin?: unknown
  crossOrigin?: unknown
}

export class WebAuthnError extends Error {}

const need = <T>(v: T | null | undefined, msg: string): T => {
  if (v === null || v === undefined) throw new WebAuthnError(msg)
  return v
}

function parseClientData(
  raw: Uint8Array,
  type: string,
  origin: string,
): ClientData & { challenge: string } {
  let cd: ClientData
  try {
    cd = JSON.parse(new TextDecoder().decode(raw)) as ClientData
  } catch {
    throw new WebAuthnError('Malformed client data')
  }
  if (cd.type !== type) throw new WebAuthnError('Unexpected client data type')
  if (typeof cd.challenge !== 'string') throw new WebAuthnError('Missing challenge')
  if (cd.origin !== origin) throw new WebAuthnError('Unexpected origin')
  if (cd.crossOrigin === true) throw new WebAuthnError('Cross-origin requests are not accepted')
  return cd as ClientData & { challenge: string }
}

interface AuthData {
  rpIdHash: Uint8Array
  flags: number
  signCount: number
  attested?: { credentialId: Uint8Array; publicKey: CborValue }
}

export const FLAG_UP = 0x01
export const FLAG_AT = 0x40

function parseAuthData(data: Uint8Array, expectAttested: boolean): AuthData {
  if (data.length < 37) throw new WebAuthnError('Authenticator data is too short')
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const out: AuthData = {
    rpIdHash: data.subarray(0, 32),
    flags: data[32] as number,
    signCount: view.getUint32(33),
  }
  if (expectAttested) {
    if (!(out.flags & FLAG_AT) || data.length < 55) {
      throw new WebAuthnError('No attested credential data')
    }
    const idLen = view.getUint16(53)
    if (idLen < 1 || idLen > 1023 || data.length < 55 + idLen) {
      throw new WebAuthnError('Invalid credential id')
    }
    const credentialId = data.slice(55, 55 + idLen)
    const { value } = decodeCborPrefix(data.subarray(55 + idLen))
    out.attested = { credentialId, publicKey: value }
  }
  return out
}

const sha256 = async (d: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', d))

async function checkRpAndPresence(auth: AuthData, rpId: string) {
  if (!timingSafeEqual(auth.rpIdHash, await sha256(utf8(rpId)))) {
    throw new WebAuthnError('Relying party mismatch')
  }
  if (!(auth.flags & FLAG_UP)) throw new WebAuthnError('User presence is required')
}

const cose = (m: Map<CborValue, CborValue>, k: number) => m.get(k)
const coseBytes = (m: Map<CborValue, CborValue>, k: number) => {
  const v = cose(m, k)
  if (!(v instanceof Uint8Array)) throw new WebAuthnError('Invalid COSE key')
  return toB64u(v)
}

/** Converts a COSE_Key (ES256 or RS256) to a JWK. */
export function coseToJwk(key: CborValue): { alg: number; jwk: JsonWebKey } {
  if (!(key instanceof Map)) throw new WebAuthnError('Invalid COSE key')
  const alg = cose(key, 3)
  const kty = cose(key, 1)
  if (alg === COSE_ES256 && kty === 2 && cose(key, -1) === 1) {
    const x = coseBytes(key, -2)
    const y = coseBytes(key, -3)
    return { alg, jwk: { kty: 'EC', crv: 'P-256', x, y } }
  }
  if (alg === COSE_RS256 && kty === 3) {
    return { alg, jwk: { kty: 'RSA', alg: 'RS256', n: coseBytes(key, -1), e: coseBytes(key, -2) } }
  }
  throw new WebAuthnError('Unsupported credential algorithm')
}

export interface RegistrationInput {
  attestationObject: string
  clientDataJSON: string
  rpId: string
  origin: string
  /** Validates the challenge from the client data; returns true when it is acceptable. */
  challengeOk: (challenge: string) => Promise<boolean>
}

export interface RegistrationResult {
  credentialId: string
  alg: number
  jwk: JsonWebKey
  signCount: number
}

/** Verifies a registration. Attestation statements are not checked (attestation "none"). */
export async function verifyRegistration(i: RegistrationInput): Promise<RegistrationResult> {
  const clientDataRaw = need(fromB64u(i.clientDataJSON), 'Malformed client data')
  const cd = parseClientData(clientDataRaw, 'webauthn.create', i.origin)
  if (!(await i.challengeOk(cd.challenge))) throw new WebAuthnError('Invalid challenge')

  let att: CborValue
  try {
    att = decodeCbor(need(fromB64u(i.attestationObject), 'Malformed attestation'))
  } catch {
    throw new WebAuthnError('Malformed attestation')
  }
  if (!(att instanceof Map)) throw new WebAuthnError('Malformed attestation')
  const authDataRaw = att.get('authData')
  if (!(authDataRaw instanceof Uint8Array)) throw new WebAuthnError('Malformed attestation')

  let auth: AuthData
  try {
    auth = parseAuthData(authDataRaw, true)
  } catch (err) {
    if (err instanceof WebAuthnError) throw err
    throw new WebAuthnError('Malformed authenticator data')
  }
  await checkRpAndPresence(auth, i.rpId)
  const attested = need(auth.attested, 'No attested credential data')
  const { alg, jwk } = coseToJwk(attested.publicKey)
  return {
    credentialId: toB64u(attested.credentialId),
    alg,
    jwk,
    signCount: auth.signCount,
  }
}

/**
 * ECDSA signatures arrive DER encoded; WebCrypto wants fixed width r || s. Parsing is strict:
 * the whole input must be consumed, lengths minimally encoded, integers positive and minimal.
 */
export function derToRawEcdsa(der: Uint8Array, size = 32): Uint8Array | null {
  if (der.length < 8 || der[0] !== 0x30) return null
  let p = 2
  let len = der[1] as number
  if (len === 0x81) {
    len = der[2] as number
    p = 3
    if (len < 0x80) return null
  } else if (len >= 0x80) {
    return null
  }
  if (p + len !== der.length) return null
  const out = new Uint8Array(size * 2)
  for (let part = 0; part < 2; part++) {
    if (der[p++] !== 0x02) return null
    const l = der[p++]
    if (l === undefined || l < 1 || l >= 0x80 || p + l > der.length) return null
    let int = der.subarray(p, p + l)
    p += l
    if ((int[0] as number) & 0x80) return null
    if (int.length > 1 && int[0] === 0) {
      if (!((int[1] as number) & 0x80)) return null
      int = int.subarray(1)
    }
    if (int.length > size || int.every((b) => b === 0)) return null
    out.set(int, part * size + (size - int.length))
  }
  return p === der.length ? out : null
}

export interface AssertionInput {
  credential: StoredCredential
  authenticatorData: string
  clientDataJSON: string
  signature: string
  rpId: string
  origin: string
  challengeOk: (challenge: string) => Promise<boolean>
}

/** Verifies an assertion and returns the new signature counter. Throws WebAuthnError. */
export async function verifyAssertion(i: AssertionInput): Promise<number> {
  const clientDataRaw = need(fromB64u(i.clientDataJSON), 'Malformed client data')
  const cd = parseClientData(clientDataRaw, 'webauthn.get', i.origin)
  if (!(await i.challengeOk(cd.challenge))) throw new WebAuthnError('Invalid challenge')

  const authRaw = need(fromB64u(i.authenticatorData), 'Malformed authenticator data')
  const auth = parseAuthData(authRaw, false)
  await checkRpAndPresence(auth, i.rpId)

  const sig = need(fromB64u(i.signature), 'Malformed signature')
  const signed = new Uint8Array(authRaw.length + 32)
  signed.set(authRaw)
  signed.set(await sha256(clientDataRaw), authRaw.length)

  let valid = false
  try {
    if (i.credential.alg === COSE_ES256) {
      const raw = derToRawEcdsa(sig)
      const key = await crypto.subtle.importKey(
        'jwk',
        i.credential.jwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      )
      valid =
        raw !== null &&
        (await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, raw, signed))
    } else if (i.credential.alg === COSE_RS256) {
      const key = await crypto.subtle.importKey(
        'jwk',
        i.credential.jwk,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify'],
      )
      valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig, signed)
    }
  } catch {
    valid = false
  }
  if (!valid) throw new WebAuthnError('Invalid signature')

  // A counter that does not advance signals a cloned authenticator. Zero means unsupported.
  if (
    (auth.signCount > 0 || i.credential.signCount > 0) &&
    auth.signCount <= i.credential.signCount
  ) {
    throw new WebAuthnError('Signature counter did not advance')
  }
  return auth.signCount
}
