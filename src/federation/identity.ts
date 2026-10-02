// Instance signing identity: an Ed25519 key pair, the private half encrypted at rest (TASKS #300).
import { eq } from 'drizzle-orm'
import { fromB64u, toB64u, utf8 } from '../auth/crypto'
import { createDb, schema } from '../db'
import type { Bindings } from '../env'
import { ApiError } from '../errors'

export const PROTOCOL = 'cloudwarden-federation'
export const PROTOCOL_VERSION = 1
export const WELL_KNOWN_PATH = '/.well-known/cloudwarden-federation'

export const federationEnabled = (env: Pick<Bindings, 'FEDERATION_ENABLED'>) =>
  env.FEDERATION_ENABLED === 'true'

export function requireFederation(env: Bindings) {
  if (!federationEnabled(env)) throw new ApiError(404, 'Federation is not enabled on this server.')
}

/** Host (and port, if any) of this instance, lower case. */
export const ownDomain = (env: Pick<Bindings, 'DOMAIN'>) => new URL(env.DOMAIN).host.toLowerCase()

export const baseUrl = (domain: string) => `https://${domain}`

/** Upper-case hex SHA-256 of the raw public key in groups of four, as admins compare it. */
export async function fingerprintOf(publicKeyB64u: string): Promise<string> {
  const raw = fromB64u(publicKeyB64u)
  if (!raw) throw new ApiError(400, 'Invalid public key.')
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', raw))
  const hex = [...digest].map((b) => b.toString(16).padStart(2, '0')).join('')
  return (hex.toUpperCase().match(/.{4}/g) ?? []).join(':')
}

/** Accepts a fingerprint typed with any separators or case. */
export const normaliseFingerprint = (s: string) => s.replace(/[^0-9a-f]/gi, '').toUpperCase()

async function wrappingKey(env: Bindings): Promise<CryptoKey> {
  const secret = env.FEDERATION_KEY_SECRET || env.JWT_SECRET
  if (!secret || secret.length < 32) {
    throw new ApiError(
      500,
      'Federation needs FEDERATION_KEY_SECRET or JWT_SECRET (32+ characters).',
    )
  }
  const ikm = await crypto.subtle.importKey('raw', utf8(secret), 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: utf8(PROTOCOL), info: utf8('identity-key-v1') },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

async function seal(env: Bindings, plain: Uint8Array): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await wrappingKey(env), plain)
  return `v1.${toB64u(iv)}.${toB64u(new Uint8Array(ct))}`
}

async function open(env: Bindings, sealed: string): Promise<Uint8Array> {
  const [v, ivS, ctS] = sealed.split('.')
  const iv = ivS ? fromB64u(ivS) : null
  const ct = ctS ? fromB64u(ctS) : null
  if (v !== 'v1' || !iv || !ct) throw new Error('federation key: bad format')
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, await wrappingKey(env), ct),
  )
}

export interface Identity {
  instanceId: string
  publicKey: string
  privateKey: CryptoKey
}

/** Loads the identity, creating it on first use. A lost race reloads the winner's row. */
export async function loadIdentity(env: Bindings): Promise<Identity> {
  const db = createDb(env.DB)
  const read = async () =>
    (
      await db
        .select()
        .from(schema.federationIdentity)
        .where(eq(schema.federationIdentity.id, 'self'))
        .limit(1)
    )[0]
  let row = await read()
  if (!row) {
    const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const pub = new Uint8Array(
      (await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer,
    )
    const pkcs8 = new Uint8Array(
      (await crypto.subtle.exportKey('pkcs8', pair.privateKey)) as ArrayBuffer,
    )
    await db
      .insert(schema.federationIdentity)
      .values({
        id: 'self',
        instanceId: crypto.randomUUID(),
        publicKey: toB64u(pub),
        privateKeyEnc: await seal(env, pkcs8),
        createdAt: Date.now(),
      })
      .onConflictDoNothing()
    row = await read()
  }
  if (!row) throw new Error('federation identity missing')
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    await open(env, row.privateKeyEnc),
    { name: 'Ed25519' },
    false,
    ['sign'],
  )
  return { instanceId: row.instanceId, publicKey: row.publicKey, privateKey }
}

export async function descriptor(env: Bindings) {
  const id = await loadIdentity(env)
  return {
    protocol: PROTOCOL,
    version: PROTOCOL_VERSION,
    instanceId: id.instanceId,
    domain: ownDomain(env),
    algorithm: 'ed25519',
    publicKey: id.publicKey,
    fingerprint: await fingerprintOf(id.publicKey),
    endpoints: { api: '/federation/v1' },
  }
}
export type Descriptor = Awaited<ReturnType<typeof descriptor>>
