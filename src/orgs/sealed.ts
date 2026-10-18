// Encryption at rest for server-held secrets (TASKS #270): organisation API keys, SCIM keys and
// integration tokens. AES-256-GCM under a key derived with HKDF-SHA256 from `DATA_ENCRYPTION_KEY`
// (a Worker secret). Without it the key is derived from `JWT_SECRET` under a different label, so a
// deployment keeps working; setting `DATA_ENCRYPTION_KEY` later still opens old values because each
// value records which source sealed it.

import { fromB64u, toB64u, utf8 } from '../auth/crypto'
import { signingSecret, verificationSecrets } from '../auth/jwt'
import type { Bindings } from '../env'

const INFO = 'cloudwarden-sealed-v1'
type Source = 'd' | 'j'

async function keyFor(env: Bindings, source: Source, jwtSecret?: string): Promise<CryptoKey> {
  const material =
    source === 'd' ? env.DATA_ENCRYPTION_KEY : `jwt-derived:${jwtSecret ?? signingSecret(env)}`
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

/**
 * Opens a sealed value; throws when it was tampered with or sealed for another purpose. A value
 * sealed under the `JWT_SECRET` fallback also opens with `JWT_SECRET_PREVIOUS` (ADR 0003 rotation);
 * `stale` then tells the caller to seal it again under the current secret.
 */
export async function unsealWithInfo(
  env: Bindings,
  purpose: string,
  sealed: string,
): Promise<{ value: string; stale: boolean }> {
  const [v, source, ivPart, ctPart] = sealed.split('.')
  const iv = fromB64u(ivPart ?? '')
  const ct = fromB64u(ctPart ?? '')
  if (v !== 'v1' || (source !== 'd' && source !== 'j') || !iv || !ct) {
    throw new Error('Malformed sealed value')
  }
  const secrets = source === 'j' ? verificationSecrets(env) : [undefined]
  let lastError: unknown
  for (const [i, secret] of secrets.entries()) {
    try {
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: utf8(purpose) },
        await keyFor(env, source, secret),
        ct,
      )
      return {
        value: new TextDecoder().decode(pt),
        stale: i > 0 || source !== currentSource(env),
      }
    } catch (err) {
      lastError = err
    }
  }
  throw lastError
}

export async function unseal(env: Bindings, purpose: string, sealed: string): Promise<string> {
  return (await unsealWithInfo(env, purpose, sealed)).value
}
