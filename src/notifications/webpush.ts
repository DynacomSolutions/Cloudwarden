// Web Push for browsers (TASKS #342): the web vault gets live sync from a push service when the
// notification hub is unavailable. Encryption is RFC 8291 (aes128gcm), authorisation is RFC 8292
// (VAPID), both with WebCrypto. The VAPID key pair is generated once and kept in instance settings
// with the private half sealed at rest. Subscriptions are only accepted for, and only delivered to,
// https endpoints of the known push services, and redirects are never followed (SSRF safe).
import { and, eq, inArray, isNotNull, ne } from 'drizzle-orm'
import { fromB64u, toB64u, utf8 } from '../auth/crypto'
import { createDb, schema } from '../db'
import type { Bindings } from '../env'
import { errorKind, log } from '../log'
import { seal, unseal } from '../orgs/sealed'

export const WEB_PUSH_KEY = 'webpush'
const KEY_PURPOSE = 'instance-setting:webpush:vapid-private-key'
const CACHE_MS = 10_000

/** Push services whose endpoints are accepted: FCM, Mozilla autopush, Apple web push and WNS. */
const ALLOWED_HOSTS: (string | RegExp)[] = [
  'fcm.googleapis.com',
  'android.googleapis.com',
  'updates.push.services.mozilla.com',
  /^[a-z0-9-]+(\.[a-z0-9-]+)*\.push\.services\.mozilla\.(com|org)$/,
  'web.push.apple.com',
  /^[a-z0-9-]+\.push\.apple\.com$/,
  /^[a-z0-9-]+\.notify\.windows\.com$/,
]

/** The normalised endpoint when it is a plain https URL of a known push service, else null. */
export function validatePushEndpoint(raw: unknown): string | null {
  if (typeof raw !== 'string' || raw.length > 2048) return null
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.port !== '') return null
  if (url.hash) return null
  const host = url.hostname.toLowerCase()
  const ok = ALLOWED_HOSTS.some((h) => (typeof h === 'string' ? h === host : h.test(host)))
  return ok ? url.toString() : null
}

/** A P-256 point in uncompressed form (65 bytes) and a 16 byte auth secret, both base64url. */
export function validateSubscriptionKeys(p256dh: unknown, auth: unknown): boolean {
  if (typeof p256dh !== 'string' || typeof auth !== 'string') return false
  const key = fromB64u(p256dh.replace(/=+$/, ''))
  const secret = fromB64u(auth.replace(/=+$/, ''))
  return key?.length === 65 && key[0] === 4 && secret?.length === 16
}

/** Most browsers one account may register for web push. */
export const MAX_WEB_PUSH_SUBSCRIPTIONS = 20
/** Most pushes in flight at once for one event. */
const SEND_CONCURRENCY = 5

/** True when `p256dh` is a point on the P-256 curve (the browser's key), not just 65 bytes. */
export async function validPublicKey(p256dh: string): Promise<boolean> {
  const raw = fromB64u(p256dh)
  if (!raw) return false
  try {
    await crypto.subtle.importKey('raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
    return true
  } catch {
    return false
  }
}

export interface WebPushState {
  enabled: boolean
  /** Uncompressed P-256 public key, base64url: `applicationServerKey` for browsers. */
  publicKey: string
  signKey: CryptoKey
}

let cache: { at: number; value: WebPushState | null; present: boolean } | null = null
export const invalidateWebPush = () => {
  cache = null
}

async function readRow(env: Bindings) {
  return env.DB.prepare(
    'SELECT config, sealed_secrets, updated_at FROM instance_settings WHERE key = ?1',
  )
    .bind(WEB_PUSH_KEY)
    .first<{ config: string; sealed_secrets: string | null; updated_at: number }>()
}

async function generate(env: Bindings): Promise<void> {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair
  const publicKey = toB64u(
    new Uint8Array((await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer),
  )
  const pkcs8 = toB64u(
    new Uint8Array((await crypto.subtle.exportKey('pkcs8', pair.privateKey)) as ArrayBuffer),
  )
  const sealed = await seal(env, KEY_PURPOSE, pkcs8)
  // Concurrent first requests all generate a pair; the first insert wins and the rest are dropped.
  await env.DB.prepare(
    `INSERT INTO instance_settings (key, config, sealed_secrets, updated_at, updated_by)
     VALUES (?1, ?2, ?3, ?4, NULL) ON CONFLICT (key) DO NOTHING`,
  )
    .bind(WEB_PUSH_KEY, JSON.stringify({ publicKey, enabled: true }), sealed, Date.now())
    .run()
}

/**
 * The VAPID state, or null when web push is unavailable (the stored key cannot be opened). With
 * `create` the key pair is generated on first use; without it a missing row yields null, which
 * is how delivery stays free of database work until some browser has ever asked for the key.
 * A disabled state is returned (with `enabled: false`) so the admin page can show it.
 */
export async function loadWebPush(
  env: Bindings,
  opts: { create?: boolean } = {},
): Promise<WebPushState | null> {
  if (cache && Date.now() - cache.at < CACHE_MS && (cache.present || !opts.create)) {
    return cache.value
  }
  let value: WebPushState | null = null
  let present = false
  try {
    let row = await readRow(env)
    if (!row && opts.create) {
      await generate(env)
      row = await readRow(env)
    }
    if (row?.sealed_secrets) {
      present = true
      const cfg = JSON.parse(row.config) as { publicKey?: string; enabled?: boolean }
      const pkcs8 = fromB64u(await unseal(env, KEY_PURPOSE, row.sealed_secrets))
      if (cfg.publicKey && pkcs8) {
        value = {
          enabled: cfg.enabled !== false,
          publicKey: cfg.publicKey,
          signKey: await crypto.subtle.importKey(
            'pkcs8',
            pkcs8,
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['sign'],
          ),
        }
      }
    }
  } catch (err) {
    log('warn', 'webpush.settings_read_failed', { errorKind: errorKind(err) }, env)
  }
  cache = { at: Date.now(), value, present }
  return value
}

/** The public key to advertise in `/api/config`, or null when web push is off or unavailable. */
export async function advertisedVapidKey(env: Bindings): Promise<string | null> {
  const s = await loadWebPush(env, { create: true })
  return s?.enabled ? s.publicKey : null
}

/** Admin switch. Generates the key pair if none exists yet. */
export async function setWebPushEnabled(env: Bindings, enabled: boolean): Promise<boolean> {
  invalidateWebPush()
  const s = await loadWebPush(env, { create: true })
  if (!s) return false
  await env.DB.prepare(
    `UPDATE instance_settings SET config = json_set(config, '$.enabled', json(?2)), updated_at = ?3
     WHERE key = ?1`,
  )
    .bind(WEB_PUSH_KEY, enabled ? 'true' : 'false', Date.now())
    .run()
  invalidateWebPush()
  return true
}

// ----- RFC 8291 payload encryption -----

const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) {
    out.set(p, o)
    o += p.length
  }
  return out
}

async function hkdf(
  salt: Uint8Array,
  ikm: Uint8Array,
  info: Uint8Array,
  bytes: number,
): Promise<Uint8Array> {
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, base, bytes * 8),
  )
}

/**
 * Encrypts `plaintext` for one subscription as a single aes128gcm record (RFC 8188 with the RFC
 * 8291 key schedule). `ephemeral` and `salt` exist so tests can reproduce the RFC 8291 vector.
 */
export async function encryptWebPush(
  plaintext: Uint8Array,
  p256dh: Uint8Array,
  authSecret: Uint8Array,
  ephemeral?: CryptoKeyPair,
  salt: Uint8Array = crypto.getRandomValues(new Uint8Array(16)),
): Promise<Uint8Array> {
  const as =
    ephemeral ??
    ((await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ])) as CryptoKeyPair)
  const asPublic = new Uint8Array(
    (await crypto.subtle.exportKey('raw', as.publicKey)) as ArrayBuffer,
  )
  const uaKey = await crypto.subtle.importKey(
    'raw',
    p256dh,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )
  const secret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: uaKey } as unknown as SubtleCryptoDeriveKeyAlgorithm,
      as.privateKey,
      256,
    ),
  )
  const ikm = await hkdf(authSecret, secret, concat(utf8('WebPush: info\0'), p256dh, asPublic), 32)
  const cek = await hkdf(salt, ikm, utf8('Content-Encoding: aes128gcm\0'), 16)
  const nonce = await hkdf(salt, ikm, utf8('Content-Encoding: nonce\0'), 12)
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt'])
  // 0x02 marks the last (only) record; no padding.
  const record = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      key,
      concat(plaintext, Uint8Array.of(2)),
    ),
  )
  const header = new Uint8Array(21)
  header.set(salt, 0)
  new DataView(header.buffer).setUint32(16, 4096)
  header[20] = asPublic.length
  return concat(header, asPublic, record)
}

/** RFC 8292 `Authorization` header value for a push service origin. */
export async function vapidAuthorization(
  state: Pick<WebPushState, 'publicKey' | 'signKey'>,
  audience: string,
  subject: string,
  now = Date.now(),
): Promise<string> {
  const part = (o: unknown) => toB64u(utf8(JSON.stringify(o)))
  const input = `${part({ typ: 'JWT', alg: 'ES256' })}.${part({
    aud: audience,
    exp: Math.floor(now / 1000) + 12 * 3600,
    sub: subject,
  })}`
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, state.signKey, utf8(input)),
  )
  return `vapid t=${input}.${toB64u(sig)}, k=${state.publicKey}`
}

// ----- Delivery -----

/** A push message must fit one 4096 byte record with the header and padding byte. */
const MAX_PLAINTEXT = 3800

export interface WebPushMessage {
  type: number
  payload: unknown
  contextId: string | null
}

/** The JSON the web vault's service worker reads: `new NotificationResponse(event.data.json().data)`. */
export function webPushBody(m: WebPushMessage): Uint8Array {
  const full = utf8(
    JSON.stringify({ data: { ContextId: m.contextId, Type: m.type, Payload: m.payload } }),
  )
  if (full.length <= MAX_PLAINTEXT) return full
  return utf8(JSON.stringify({ data: { ContextId: m.contextId, Type: m.type, Payload: {} } }))
}

const subjectFor = (env: Bindings) => env.DOMAIN.replace(/\/+$/, '')

type Sub = { uuid: string; endpoint: string; p256dh: string; auth: string }

/** Sends to one subscription. Returns true when the subscription is gone and must be removed. */
async function deliver(env: Bindings, state: WebPushState, sub: Sub, body: Uint8Array) {
  const endpoint = validatePushEndpoint(sub.endpoint)
  if (!endpoint) return true
  const p256dh = fromB64u(sub.p256dh)
  const auth = fromB64u(sub.auth)
  if (!p256dh || !auth) return true
  let payload: Uint8Array
  try {
    payload = await encryptWebPush(body, p256dh, auth)
  } catch {
    // The stored key cannot be used (not a curve point): the subscription is useless.
    return true
  }
  const res = await fetch(endpoint, {
    method: 'POST',
    redirect: 'manual',
    signal: AbortSignal.timeout(5000),
    headers: {
      Authorization: await vapidAuthorization(state, new URL(endpoint).origin, subjectFor(env)),
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      TTL: '300',
      Urgency: 'normal',
    },
    body: payload,
  })
  // Drain so the connection is released; the body is never needed.
  await res.body?.cancel().catch(() => undefined)
  if (res.status === 404 || res.status === 410) return true
  if (!res.ok) log('warn', 'webpush.rejected', { status: res.status }, env)
  return false
}

/**
 * Delivers one notification to every web push subscriber of a user, except the device that made
 * the change. Never rejects, and does nothing (no database work) before any browser asked for the
 * VAPID key or when the instance admin turned web push off.
 */
export async function sendWebPush(
  env: Bindings,
  userUuid: string,
  message: WebPushMessage,
  excludeDeviceIdentifier?: string | null,
): Promise<void> {
  try {
    const state = await loadWebPush(env)
    if (!state?.enabled) return
    const db = createDb(env.DB)
    const rows = await db
      .select({
        uuid: schema.devices.uuid,
        identifier: schema.devices.identifier,
        endpoint: schema.devices.webPushEndpoint,
        p256dh: schema.devices.webPushP256dh,
        auth: schema.devices.webPushAuth,
      })
      .from(schema.devices)
      .where(
        and(
          eq(schema.devices.userUuid, userUuid),
          isNotNull(schema.devices.webPushEndpoint),
          excludeDeviceIdentifier
            ? ne(schema.devices.identifier, excludeDeviceIdentifier)
            : undefined,
        ),
      )
    if (rows.length === 0) return
    const body = webPushBody(message)
    const gone: string[] = []
    const work = rows.filter((r) => r.endpoint && r.p256dh && r.auth)
    for (let i = 0; i < work.length; i += SEND_CONCURRENCY) {
      await Promise.all(
        work.slice(i, i + SEND_CONCURRENCY).map(async (r) => {
          try {
            const sub = {
              uuid: r.uuid,
              endpoint: r.endpoint as string,
              p256dh: r.p256dh as string,
              auth: r.auth as string,
            }
            if (await deliver(env, state, sub, body)) gone.push(r.uuid)
          } catch (err) {
            log('warn', 'webpush.send_failed', { errorKind: errorKind(err) }, env)
          }
        }),
      )
    }
    if (gone.length > 0) {
      await db
        .update(schema.devices)
        .set({ webPushEndpoint: null, webPushP256dh: null, webPushAuth: null })
        .where(inArray(schema.devices.uuid, gone))
    }
  } catch (err) {
    log('warn', 'webpush.failed', { errorKind: errorKind(err) }, env)
  }
}
