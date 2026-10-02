// Minimal Secrets Manager machine client for the end-to-end run (TASKS #220).
//
// It stands in for `bws`, whose source and binaries are under the Bitwarden SDK License (see
// docs/secrets-manager.md). It follows the wire contract of the GPL-3.0 crates in
// github.com/bitwarden/sdk-internal: access token format and key derivation (`bitwarden-core`
// auth/access_token.rs, `bitwarden-crypto` keys/shareable_key.rs), the token request
// (auth/api/request/access_token_request.rs) and the API paths (`bitwarden-api-api`).
//
// Usage: node e2e/sm-client.mjs <server> <access token> list <organizationId>
//        node e2e/sm-client.mjs <server> <access token> get <secretId>
//        node e2e/sm-client.mjs <server> <access token> sync <organizationId> [lastSyncedDate]
// Prints decrypted JSON. Exits 1 with the HTTP status on failure.
import { createHmac } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { decType2, hkdfExpand } from './crypto.mjs'

/** `0.<id>.<clientSecret>:<seed b64>` into its parts and the derived 64 byte key. */
export function parseAccessToken(token) {
  const [first, seed] = token.split(':')
  if (!seed) throw new Error('access token has no key')
  const [version, id, clientSecret, ...extra] = first.split('.')
  if (version !== '0' || !id || !clientSecret || extra.length) {
    throw new Error('malformed access token')
  }
  const raw = Buffer.from(seed, 'base64')
  if (raw.length !== 16) throw new Error('access token key must be 16 bytes')
  return { id, clientSecret, key: deriveAccessTokenKey(raw) }
}

/** HMAC-SHA256 keyed `bitwarden-accesstoken` over the seed, then HKDF-Expand `sm-access-token`. */
export function deriveAccessTokenKey(seed) {
  const prk = createHmac('sha256', 'bitwarden-accesstoken').update(seed).digest()
  return hkdfExpand(prk, 'sm-access-token', 64)
}

async function login(server, token) {
  const res = await fetch(`${server}/identity/connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      scope: 'api.secrets',
      client_id: token.id,
      client_secret: token.clientSecret,
      grant_type: 'client_credentials',
    }),
  })
  if (!res.ok) throw Object.assign(new Error(`login failed: ${res.status}`), { status: res.status })
  const body = await res.json()
  const payload = JSON.parse((await decType2(body.encrypted_payload, token.key)).toString())
  const claims = JSON.parse(Buffer.from(body.access_token.split('.')[1], 'base64url').toString())
  return {
    accessToken: body.access_token,
    organizationId: claims.organization,
    orgKey: Buffer.from(payload.encryptionKey, 'base64'),
  }
}

export async function run(server, rawToken, command, arg, extra) {
  const token = parseAccessToken(rawToken)
  const session = await login(server, token)
  const api = async (path, init = {}) => {
    const res = await fetch(`${server}/api${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${session.accessToken}`,
        'Content-Type': 'application/json',
      },
    })
    if (!res.ok) throw Object.assign(new Error(`${path}: ${res.status}`), { status: res.status })
    return res.json()
  }
  const dec = async (s) => (s ? (await decType2(s, session.orgKey)).toString() : '')
  const secret = async (s) => ({
    id: s.id,
    organizationId: s.organizationId,
    projectId: s.projects?.[0]?.id ?? null,
    key: await dec(s.key),
    value: await dec(s.value),
    note: await dec(s.note),
  })
  if (command === 'list') {
    const listed = await api(`/organizations/${arg}/secrets`)
    if (listed.secrets.length === 0) return []
    const full = await api('/secrets/get-by-ids', {
      method: 'POST',
      body: JSON.stringify({ ids: listed.secrets.map((s) => s.id) }),
    })
    return Promise.all(full.data.map(secret))
  }
  if (command === 'get') return secret(await api(`/secrets/${arg}`))
  if (command === 'sync') {
    const q = extra ? `?lastSyncedDate=${encodeURIComponent(extra)}` : ''
    const r = await api(`/organizations/${arg}/secrets/sync${q}`)
    return {
      hasChanges: r.hasChanges,
      secrets: r.secrets ? await Promise.all(r.secrets.data.map(secret)) : null,
    }
  }
  throw new Error(`unknown command ${command}`)
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const [server, token, command, arg, extra] = process.argv.slice(2)
  run(server, token, command, arg, extra)
    .then((out) => console.log(JSON.stringify(out)))
    .catch((err) => {
      console.error(err.message)
      process.exit(1)
    })
}
