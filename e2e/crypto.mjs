// Client-side account key derivation, as the official clients do it (PBKDF2 KDF, type 2 EncStrings).
import { createHmac, randomBytes, webcrypto } from 'node:crypto'

const { subtle } = webcrypto
const b64 = (buf) => Buffer.from(buf).toString('base64')

async function pbkdf2(password, salt, iterations) {
  const key = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits'])
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    256,
  )
  return Buffer.from(bits)
}

// HKDF-Expand only (RFC 5869 step 2), with the master key used directly as the PRK.
function hkdfExpand(prk, info, length) {
  const out = []
  let prev = Buffer.alloc(0)
  for (let i = 1; Buffer.concat(out).length < length; i++) {
    prev = createHmac('sha256', prk)
      .update(Buffer.concat([prev, Buffer.from(info), Buffer.from([i])]))
      .digest()
    out.push(prev)
  }
  return Buffer.concat(out).subarray(0, length)
}

/** Encrypts `data` with a 64 byte key (32 enc + 32 mac) into a type 2 EncString. */
async function encType2(data, key) {
  const iv = randomBytes(16)
  const aes = await subtle.importKey('raw', key.subarray(0, 32), 'AES-CBC', false, ['encrypt'])
  const ct = Buffer.from(await subtle.encrypt({ name: 'AES-CBC', iv }, aes, data))
  const mac = createHmac('sha256', key.subarray(32))
    .update(Buffer.concat([iv, ct]))
    .digest()
  return `2.${b64(iv)}|${b64(ct)}|${b64(mac)}`
}

/** Builds the registration body for `email` and `password`. */
export async function buildAccount(email, password, iterations = 600000) {
  const salt = Buffer.from(email.trim().toLowerCase())
  const masterKey = await pbkdf2(Buffer.from(password), salt, iterations)
  const masterPasswordHash = b64(await pbkdf2(masterKey, Buffer.from(password), 1))
  const stretched = Buffer.concat([
    hkdfExpand(masterKey, 'enc', 32),
    hkdfExpand(masterKey, 'mac', 32),
  ])

  const userKey = randomBytes(64)
  const key = await encType2(userKey, stretched)
  const pair = await subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-1',
    },
    true,
    ['encrypt', 'decrypt'],
  )
  const publicKey = b64(await subtle.exportKey('spki', pair.publicKey))
  const encryptedPrivateKey = await encType2(
    Buffer.from(await subtle.exportKey('pkcs8', pair.privateKey)),
    userKey,
  )
  return {
    masterPasswordHash,
    body: {
      email,
      name: 'E2E User',
      masterPasswordHash,
      masterPasswordHint: '',
      key,
      keys: { publicKey, encryptedPrivateKey },
      kdf: 0,
      kdfIterations: iterations,
    },
  }
}
