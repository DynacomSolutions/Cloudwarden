#!/usr/bin/env node
// Copies a personal vault from another Bitwarden-compatible server into Cloudwarden (TASKS #163).
//
// Only public client API endpoints are used on both sides: prelogin, the password grant token
// endpoint, sync, register and ciphers/import. The source vault is decrypted client side with the
// account owner's master password, so the credentials never leave this machine except as the
// usual master password hash sent to each server. Data only: logins, cards, identities, notes,
// SSH keys and folders. No source code of other servers is used.
//
// Usage: node scripts/import-from-server.mjs --source https://old.example.com \
//          --source-email me@example.com --target https://vault.example.com [--register]
// Passwords come from SOURCE_PASSWORD and TARGET_PASSWORD or a hidden prompt.
import { createPrivateKey, createPublicKey, randomUUID } from 'node:crypto'
import { createInterface } from 'node:readline'
import { argon2idAsync } from '@noble/hashes/argon2.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { decType2, encType2, hkdfExpand } from '../e2e/crypto.mjs'

const { subtle } = globalThis.crypto
const b64 = (buf) => Buffer.from(buf).toString('base64')
const ENC_STRING = /^2\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+$/
const MAX_IMPORT_CIPHERS = 6000
const MAX_IMPORT_FOLDERS = 700

// ---------------------------------------------------------------------------
// Key derivation (the standard client scheme)
// ---------------------------------------------------------------------------

async function pbkdf2(password, salt, iterations) {
  const key = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits'])
  return Buffer.from(
    await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256),
  )
}

/** Master key from the password and the account's KDF settings (prelogin response). */
export async function deriveMasterKey(email, password, kdf) {
  const normalised = email.trim().toLowerCase()
  const pw = Buffer.from(password)
  if (kdf.kdf === 1) {
    return Buffer.from(
      await argon2idAsync(pw, sha256(Buffer.from(normalised)), {
        t: kdf.kdfIterations,
        m: (kdf.kdfMemory ?? 64) * 1024,
        p: kdf.kdfParallelism ?? 4,
        dkLen: 32,
      }),
    )
  }
  return pbkdf2(pw, Buffer.from(normalised), kdf.kdfIterations)
}

export const authHash = async (masterKey, password) =>
  b64(await pbkdf2(masterKey, Buffer.from(password), 1))

export const stretch = (masterKey) =>
  Buffer.concat([hkdfExpand(masterKey, 'enc', 32), hkdfExpand(masterKey, 'mac', 32)])

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

const HEADERS = {
  'Bitwarden-Client-Name': 'cli',
  'Bitwarden-Client-Version': '2026.9.0',
  'Device-Type': '24',
}

export class TwoFactorRequired extends Error {
  constructor(providers) {
    super(`Two-factor authentication is required (provider types: ${providers.join(', ')})`)
    this.providers = providers
  }
}

async function request(base, path, { method = 'GET', token, json, form } = {}) {
  const headers = { ...HEADERS }
  if (token) headers.Authorization = `Bearer ${token}`
  let body
  if (json !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(json)
  } else if (form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    body = new URLSearchParams(form).toString()
  }
  const res = await fetch(new URL(path, base), { method, headers, body })
  const text = await res.text()
  let data = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = null
  }
  return { status: res.status, data, text }
}

const apiError = (what, res) =>
  new Error(
    `${what} failed (HTTP ${res.status}): ${res.data?.message ?? res.data?.error_description ?? res.data?.ErrorModel?.Message ?? 'no message'}`,
  )

/** Logs in with the password grant. Returns the token response and the decrypted user key. */
export async function loginAndUnlock(base, email, password, twoFactor = {}) {
  const pre = await request(base, '/identity/accounts/prelogin', {
    method: 'POST',
    json: { email },
  })
  if (pre.status !== 200) throw apiError('prelogin', pre)
  const kdf = {
    kdf: pre.data.kdf ?? pre.data.Kdf ?? 0,
    kdfIterations: pre.data.kdfIterations ?? pre.data.KdfIterations ?? 600000,
    kdfMemory: pre.data.kdfMemory ?? pre.data.KdfMemory ?? null,
    kdfParallelism: pre.data.kdfParallelism ?? pre.data.KdfParallelism ?? null,
  }
  const masterKey = await deriveMasterKey(email, password, kdf)
  const form = {
    grant_type: 'password',
    username: email,
    password: await authHash(masterKey, password),
    scope: 'api offline_access',
    client_id: 'cli',
    deviceType: '24',
    deviceName: 'cloudwarden-import',
    deviceIdentifier: randomUUID(),
  }
  if (twoFactor.token) {
    form.twoFactorToken = twoFactor.token
    form.twoFactorProvider = String(twoFactor.provider ?? 0)
    form.twoFactorRemember = '0'
  }
  const res = await request(base, '/identity/connect/token', { method: 'POST', form })
  if (res.status !== 200) {
    const providers = res.data?.TwoFactorProviders ?? res.data?.twoFactorProviders
    if (providers) throw new TwoFactorRequired(providers)
    throw apiError('login', res)
  }
  const wrapped = res.data.Key ?? res.data.key
  if (!wrapped) throw new Error('The server returned no wrapped user key.')
  const userKey = await decType2(wrapped, stretch(masterKey))
  return {
    accessToken: res.data.access_token,
    userKey,
    wrappedKey: wrapped,
    privateKey: res.data.PrivateKey ?? res.data.privateKey ?? null,
    kdf,
  }
}

// ---------------------------------------------------------------------------
// Vault transformation
// ---------------------------------------------------------------------------

/** Re-encrypts one EncString from the source user key to the target one. */
async function rewrap(value, from, to) {
  return encType2(await decType2(value, from), to)
}

/** Walks any JSON value and re-encrypts every EncString it finds. */
async function rewrapDeep(value, from, to) {
  if (typeof value === 'string') return ENC_STRING.test(value) ? rewrap(value, from, to) : value
  if (Array.isArray(value)) return Promise.all(value.map((v) => rewrapDeep(v, from, to)))
  if (value && typeof value === 'object') {
    const out = {}
    for (const [k, v] of Object.entries(value)) out[k] = await rewrapDeep(v, from, to)
    return out
  }
  return value
}

const CIPHER_FIELDS = [
  'type',
  'name',
  'notes',
  'favorite',
  'reprompt',
  'login',
  'card',
  'identity',
  'secureNote',
  'sshKey',
  'fields',
  'passwordHistory',
]

/**
 * Converts a synced cipher to an import item for the target. With identical user keys the
 * ciphertexts are carried over unchanged. Otherwise an item key is re-wrapped (its fields stay
 * as they are) and an item without one has every field re-encrypted.
 */
export async function convertCipher(cipher, from, to) {
  const out = {}
  for (const f of CIPHER_FIELDS)
    if (cipher[f] !== undefined && cipher[f] !== null) out[f] = cipher[f]
  if (cipher.key) out.key = cipher.key
  if (from.equals(to)) return out
  if (cipher.key) {
    out.key = await rewrap(cipher.key, from, to)
    return out
  }
  return rewrapDeep(out, from, to)
}

/** Builds the import body (folders, ciphers, relationships) from a sync response. */
export async function buildImport(sync, from, to, { skipErrors = false } = {}) {
  const warnings = []
  const folders = []
  const folderIndex = new Map()
  for (const f of sync.folders ?? sync.Folders ?? []) {
    try {
      folderIndex.set(f.id, folders.length)
      folders.push({ name: from.equals(to) ? f.name : await rewrap(f.name, from, to) })
    } catch (err) {
      folderIndex.delete(f.id)
      if (!skipErrors) throw new Error(`Folder ${f.id}: ${err.message}`)
      warnings.push(`skipped folder ${f.id}: ${err.message}`)
    }
  }
  const ciphers = []
  const relationships = []
  let organisation = 0
  let trashed = 0
  for (const c of sync.ciphers ?? sync.Ciphers ?? []) {
    if (c.organizationId) {
      organisation++
      continue
    }
    if (c.deletedDate) {
      trashed++
      continue
    }
    try {
      const item = await convertCipher(c, from, to)
      if (c.folderId && folderIndex.has(c.folderId)) {
        relationships.push({ key: ciphers.length, value: folderIndex.get(c.folderId) })
      }
      ciphers.push(item)
    } catch (err) {
      if (!skipErrors) throw new Error(`Item ${c.id}: ${err.message}`)
      warnings.push(`skipped item ${c.id}: ${err.message}`)
    }
  }
  return { folders, ciphers, folderRelationships: relationships, organisation, trashed, warnings }
}

/** Splits an import into requests the server accepts, keeping only the folders each one uses. */
export function chunkImport({ folders, ciphers, folderRelationships }) {
  const folderOf = new Map(folderRelationships.map((r) => [r.key, r.value]))
  const parts = []
  for (let start = 0; start === 0 || start < ciphers.length; start += MAX_IMPORT_CIPHERS) {
    const slice = ciphers.slice(start, start + MAX_IMPORT_CIPHERS)
    const used = new Map()
    const rel = []
    slice.forEach((_, i) => {
      const f = folderOf.get(start + i)
      if (f === undefined) return
      if (!used.has(f)) used.set(f, used.size)
      rel.push({ key: i, value: used.get(f) })
    })
    const list =
      start === 0 && ciphers.length <= MAX_IMPORT_CIPHERS
        ? folders
        : [...used.keys()].map((f) => folders[f])
    const remap = start === 0 && ciphers.length <= MAX_IMPORT_CIPHERS ? folderRelationships : rel
    if (list.length > MAX_IMPORT_FOLDERS) {
      throw new Error(`Too many folders for one import request (${list.length}).`)
    }
    parts.push({ folders: list, ciphers: slice, folderRelationships: remap })
  }
  return parts
}

// ---------------------------------------------------------------------------
// Registering the target account
// ---------------------------------------------------------------------------

/** Public key (SPKI, base64) of the account's RSA key pair, from its encrypted private key. */
export async function publicKeyFromPrivate(encryptedPrivateKey, userKey) {
  const pkcs8 = await decType2(encryptedPrivateKey, userKey)
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' })
  return createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64')
}

/**
 * Registers `email` on the target with the source account's user key and key pair, wrapped under
 * the new master key. Items then need no re-encryption.
 */
export async function registerTarget(base, email, password, source, { iterations = 600000 } = {}) {
  const masterKey = await deriveMasterKey(email, password, { kdf: 0, kdfIterations: iterations })
  const wrapped = await encType2(source.userKey, stretch(masterKey))
  const privateKey = source.privateKey
  const body = {
    email,
    name: source.name ?? '',
    masterPasswordHash: await authHash(masterKey, password),
    masterPasswordHint: '',
    key: wrapped,
    kdf: 0,
    kdfIterations: iterations,
  }
  if (privateKey) {
    body.keys = {
      publicKey: await publicKeyFromPrivate(privateKey, source.userKey),
      encryptedPrivateKey: privateKey,
    }
  }
  const res = await request(base, '/identity/accounts/register', { method: 'POST', json: body })
  if (res.status !== 200) throw apiError('register', res)
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const out = { flags: new Set() }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (!a.startsWith('--')) throw new Error(`Unexpected argument ${a}`)
    const name = a.slice(2)
    if (['register', 'dry-run', 'skip-errors', 'help'].includes(name)) out.flags.add(name)
    else out[name] = argv[++i]
  }
  return out
}

const USAGE = `Usage: node scripts/import-from-server.mjs --source URL --source-email EMAIL --target URL [options]

  --target-email EMAIL        Account on Cloudwarden (default: the source email)
  --register                  Create the target account first (same user key, so items are copied as is)
  --target-iterations N       PBKDF2 iterations for the new account with --register (default 600000)
  --dry-run                   Decrypt and count, change nothing on the target
  --skip-errors               Skip items that cannot be converted instead of stopping
  --source-2fa-provider N     Two-factor provider type of the source account (0 authenticator, 1 email, ...)
  --source-2fa-token CODE     Its code
  --target-2fa-provider N / --target-2fa-token CODE   The same for an existing target account

Passwords: SOURCE_PASSWORD and TARGET_PASSWORD (defaults to the source password with --register),
or a hidden prompt. Copies logins, cards, identities, notes, SSH keys and folders of the personal
vault. Organisations, Sends, attachments, trash and devices are not copied.`

function prompt(question) {
  return new Promise((ok) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true })
    const write = rl._writeToOutput
    rl._writeToOutput = (s) => (s.startsWith(question) ? write.call(rl, s) : undefined)
    rl.question(question, (answer) => {
      rl.close()
      process.stderr.write('\n')
      ok(answer)
    })
  })
}

async function password(envName, label, fallback) {
  if (process.env[envName]) return process.env[envName]
  if (fallback) return fallback
  if (!process.stdin.isTTY) throw new Error(`Set ${envName} (no terminal to prompt on).`)
  return prompt(`${label} master password: `)
}

export async function main(argv, log = console.log) {
  const args = parseArgs(argv)
  if (args.flags.has('help') || !args.source || !args['source-email'] || !args.target) {
    log(USAGE)
    return args.flags.has('help') ? 0 : 2
  }
  const dry = args.flags.has('dry-run')
  const sourcePassword = await password('SOURCE_PASSWORD', 'Source', null)
  const source = await loginAndUnlock(args.source, args['source-email'], sourcePassword, {
    provider: args['source-2fa-provider'],
    token: args['source-2fa-token'],
  })
  const sync = await request(args.source, '/api/sync?excludeDomains=true', {
    token: source.accessToken,
  })
  if (sync.status !== 200) throw apiError('source sync', sync)
  log('Source vault read and decrypted with the account credentials.')

  const targetEmail = args['target-email'] ?? args['source-email']
  let target = { userKey: source.userKey }
  if (!dry) {
    const targetPassword = await password(
      'TARGET_PASSWORD',
      'Target',
      args.flags.has('register') ? sourcePassword : null,
    )
    if (args.flags.has('register')) {
      await registerTarget(
        args.target,
        targetEmail,
        targetPassword,
        { ...source, name: sync.data.profile?.name ?? sync.data.Profile?.Name ?? '' },
        { iterations: Number(args['target-iterations'] ?? 600000) },
      )
      log(`Registered ${targetEmail} on the target.`)
    }
    target = await loginAndUnlock(args.target, targetEmail, targetPassword, {
      provider: args['target-2fa-provider'],
      token: args['target-2fa-token'],
    })
  }
  const built = await buildImport(sync.data, source.userKey, target.userKey, {
    skipErrors: args.flags.has('skip-errors'),
  })
  for (const w of built.warnings) log(`warning: ${w}`)
  log(
    `${built.ciphers.length} items and ${built.folders.length} folders ready` +
      ` (not copied: ${built.organisation} organisation items, ${built.trashed} trashed).`,
  )
  if (dry) {
    log('Dry run: nothing was written to the target.')
    return 0
  }
  for (const part of chunkImport(built)) {
    if (part.ciphers.length === 0 && part.folders.length === 0) continue
    const res = await request(args.target, '/api/ciphers/import', {
      method: 'POST',
      token: target.accessToken,
      json: part,
    })
    if (res.status !== 200) throw apiError('import', res)
  }
  log('Import finished.')
  return 0
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      console.error(
        err instanceof TwoFactorRequired
          ? `${err.message}. Pass --source-2fa-provider and --source-2fa-token (or the target equivalents).`
          : `Error: ${err.message}`,
      )
      process.exit(1)
    },
  )
}
