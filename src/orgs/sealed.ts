// Encryption at rest for server-held secrets (TASKS #270): organisation API keys, SCIM keys and
// integration tokens. AES-256-GCM under a key derived with HKDF-SHA256 from `DATA_ENCRYPTION_KEY`
// (a Worker secret). Without it the key is derived from `JWT_SECRET` under a different label, so a
// deployment keeps working; setting `DATA_ENCRYPTION_KEY` later still opens old values because each
// value records which source sealed it.

import { fromB64u, toB64u, utf8 } from '../auth/crypto'
import { signingSecret } from '../auth/jwt'
import type { Bindings } from '../env'

const INFO = 'cloudwarden-sealed-v1'
type Source = 'd' | 'j'

async function keyFor(env: Bindings, source: Source): Promise<CryptoKey> {
  const material = source === 'd' ? env.DATA_ENCRYPTION_KEY : `jwt-derived:${signingSecret(env)}`
  if (!material || material.length < 32) {
    throw new Error('DATA_ENCRYPTION_KEY must be at least 32 characters')
  }
  const base = await crypto.subtle.importKey('raw', utf8(material), 'HKDF', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: utf8(INFO) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

const currentSource = (env: Bindings): Source => (env.DATA_ENCRYPTION_KEY ? 'd' : 'j')

/** `v1.<source>.<iv>.<ciphertext>`; the purpose is bound as additional data. */
export async function seal(env: Bindings, purpose: string, plaintext: string): Promise<string> {
  const source = currentSource(env)
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: utf8(purpose) },
    await keyFor(env, source),
    utf8(plaintext),
  )
  return `v1.${source}.${toB64u(iv)}.${toB64u(new Uint8Array(ct))}`
}

/** Opens a sealed value; throws when it was tampered with or sealed for another purpose. */
export async function unseal(env: Bindings, purpose: string, sealed: string): Promise<string> {
  const [v, source, ivPart, ctPart] = sealed.split('.')
  const iv = fromB64u(ivPart ?? '')
  const ct = fromB64u(ctPart ?? '')
  if (v !== 'v1' || (source !== 'd' && source !== 'j') || !iv || !ct) {
    throw new Error('Malformed sealed value')
  }
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: utf8(purpose) },
    await keyFor(env, source),
    ct,
  )
  return new TextDecoder().decode(pt)
}
