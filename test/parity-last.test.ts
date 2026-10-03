// Last parity gaps (TASKS #340 to #348): Key Connector enrolment, device push token clearing, real
// Web Push, the organisation public key, organisation connections, the SSO cookie vendor and the
// upstream SSO paths.
import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { fromB64u, toB64u, utf8 } from '../src/auth/crypto'
import { PushType, pushUserUpdate } from '../src/notifications/publish'
import {
  encryptWebPush,
  invalidateWebPush,
  validatePushEndpoint,
  validateSubscriptionKeys,
  vapidAuthorization,
  webPushBody,
} from '../src/notifications/webpush'
import { authed, BASE, createSession, login, withEnv } from './helpers'
import type { OidcIdp } from './oidc-idp'
import { actor, addMember, createOrg } from './org-helpers'
import {
  authedCall,
  callback,
  codeFrom,
  configureOidc,
  call as inproc,
  oidcLogin,
  pkce,
  redeem,
  startIdp,
} from './sso-helpers'

let n = 0
const unique = (p: string) => `${p}-${Date.now()}-${++n}`
const uemail = (p: string) => `${unique(p)}@example.com`

// ----- Web Push: crypto -----

describe('Web Push encryption and VAPID', () => {
  // RFC 8291 appendix A.
  const A = {
    plaintext: 'When I grow up, I want to be a watermelon',
    asPrivate: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
    asPublic:
      'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
    uaPublic:
      'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
    auth: 'BTBZMqHH6r4Tts7J_aSIgg', // gitleaks:allow (RFC 8291 test vector)
    salt: 'DGv6ra1nlYgDCS1FRnbzlw',
    body: 'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN',
  }

  it('reproduces the RFC 8291 test vector', async () => {
    const pub = fromB64u(A.asPublic) as Uint8Array
    const jwk = { kty: 'EC', crv: 'P-256', x: toB64u(pub.slice(1, 33)), y: toB64u(pub.slice(33)) }
    const ephemeral = {
      publicKey: await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        [],
      ),
      privateKey: await crypto.subtle.importKey(
        'jwk',
        { ...jwk, d: A.asPrivate },
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        ['deriveBits'],
      ),
    } as CryptoKeyPair
    const out = await encryptWebPush(
      utf8(A.plaintext),
      fromB64u(A.uaPublic) as Uint8Array,
      fromB64u(A.auth) as Uint8Array,
      ephemeral,
      fromB64u(A.salt) as Uint8Array,
    )
    expect(toB64u(out)).toBe(A.body)
  })

  it('signs a VAPID token that verifies with the advertised key', async () => {
    const pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const publicKey = toB64u(
      new Uint8Array((await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer),
    )
    const header = await vapidAuthorization(
      { publicKey, signKey: pair.privateKey },
      'https://fcm.googleapis.com',
      'https://vault.example.com',
      1_700_000_000_000,
    )
    const m = /^vapid t=([\w-]+)\.([\w-]+)\.([\w-]+), k=([\w-]+)$/.exec(header)
    expect(m).not.toBeNull()
    const [, h, c, sig, k] = m as RegExpExecArray
    expect(k).toBe(publicKey)
    expect(JSON.parse(new TextDecoder().decode(fromB64u(h as string) as Uint8Array))).toEqual({
      typ: 'JWT',
      alg: 'ES256',
    })
    expect(JSON.parse(new TextDecoder().decode(fromB64u(c as string) as Uint8Array))).toEqual({
      aud: 'https://fcm.googleapis.com',
      exp: 1_700_000_000 + 12 * 3600,
      sub: 'https://vault.example.com',
    })
    expect(
      await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        pair.publicKey,
        fromB64u(sig as string) as Uint8Array,
        utf8(`${h}.${c}`),
      ),
    ).toBe(true)
  })

  it('keeps an oversize payload within one record by dropping the payload body', () => {
    const big = webPushBody({ type: 5, payload: { Blob: 'x'.repeat(5000) }, contextId: 'c' })
    expect(big.length).toBeLessThan(200)
    expect(JSON.parse(new TextDecoder().decode(big))).toEqual({
      data: { ContextId: 'c', Type: 5, Payload: {} },
    })
  })
})

describe('push endpoint and key validation', () => {
  it('accepts https endpoints of known push services only', () => {
    for (const ok of [
      'https://fcm.googleapis.com/fcm/send/abc',
      'https://fcm.googleapis.com/wp/abc',
      'https://updates.push.services.mozilla.com/wpush/v2/abc',
      'https://autopush.prod.mozaws.push.services.mozilla.com/x',
      'https://web.push.apple.com/QAbc',
      'https://wns2-par02p.notify.windows.com/w/?token=abc',
    ]) {
      expect(validatePushEndpoint(ok), ok).not.toBeNull()
    }
    for (const bad of [
      'http://fcm.googleapis.com/fcm/send/abc',
      'https://fcm.googleapis.com.evil.example.com/x',
      'https://evilfcm.googleapis.com/x',
      'https://evil.example.com/fcm.googleapis.com',
      'https://user:pw@fcm.googleapis.com/x',
      'https://fcm.googleapis.com:8443/x',
      'https://127.0.0.1/x',
      'https://localhost/x',
      'https://[::1]/x',
      'https://169.254.169.254/latest',
      'https://notify.windows.com.evil.example.com/x',
      'https://windows.com/x',
      'ftp://fcm.googleapis.com/x',
      'not a url',
      '',
      42,
    ]) {
      expect(validatePushEndpoint(bad), String(bad)).toBeNull()
    }
  })

  it('checks the subscription key sizes', () => {
    const key = toB64u(Uint8Array.of(4, ...new Uint8Array(64)))
    const auth = toB64u(new Uint8Array(16))
    expect(validateSubscriptionKeys(key, auth)).toBe(true)
    expect(validateSubscriptionKeys(key, toB64u(new Uint8Array(15)))).toBe(false)
    expect(validateSubscriptionKeys(toB64u(new Uint8Array(65)), auth)).toBe(false)
    expect(validateSubscriptionKeys(toB64u(new Uint8Array(33)), auth)).toBe(false)
    expect(validateSubscriptionKeys(undefined, auth)).toBe(false)
  })
})

// ----- Web Push: routes, config and delivery -----

interface Ua {
  endpoint: string
  keys: { p256dh: string; auth: string }
  priv: CryptoKey
}

async function browser(host = 'https://fcm.googleapis.com/fcm/send/'): Promise<Ua> {
  const pair = (await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair
  return {
    endpoint: `${host}${unique('sub')}`,
    keys: {
      p256dh: toB64u(
        new Uint8Array((await crypto.subtle.exportKey('raw', pair.publicKey)) as ArrayBuffer),
      ),
      auth: toB64u(crypto.getRandomValues(new Uint8Array(16))),
    },
    priv: pair.privateKey,
  }
}

/** Decrypts an RFC 8291 body the way a browser would. */
async function decrypt(body: Uint8Array, ua: Ua): Promise<string> {
  const salt = body.slice(0, 16)
  const idlen = body[20] as number
  const asPub = body.slice(21, 21 + idlen)
  const record = body.slice(21 + idlen)
  const uaPub = fromB64u(ua.keys.p256dh) as Uint8Array
  const asKey = await crypto.subtle.importKey(
    'raw',
    asPub,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )
  const secret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: asKey } as unknown as SubtleCryptoDeriveKeyAlgorithm,
      ua.priv,
      256,
    ),
  )
  const hk = async (s: Uint8Array, ikm: Uint8Array, info: Uint8Array, len: number) =>
    new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: s, info },
        await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']),
        len * 8,
      ),
    )
  const cat = (...p: Uint8Array[]) => Uint8Array.from(p.flatMap((x) => [...x]))
  const ikm = await hk(
    fromB64u(ua.keys.auth) as Uint8Array,
    secret,
    cat(utf8('WebPush: info\0'), uaPub, asPub),
    32,
  )
  const cek = await hk(salt, ikm, utf8('Content-Encoding: aes128gcm\0'), 16)
  const nonce = await hk(salt, ikm, utf8('Content-Encoding: nonce\0'), 12)
  const plain = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['decrypt']),
      record,
    ),
  )
  expect(plain[plain.length - 1]).toBe(2)
  return new TextDecoder().decode(plain.slice(0, -1))
}

interface Sent {
  url: string
  init: RequestInit
}
let sent: Sent[] = []
let pushStatus = 201
let realFetch: typeof fetch
beforeEach(async () => {
  invalidateWebPush()
  await env.DB.prepare("DELETE FROM instance_settings WHERE key = 'webpush'").run()
  sent = []
  pushStatus = 201
  realFetch = globalThis.fetch
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input)
    if (/^https:\/\/(fcm\.googleapis|updates\.push|web\.push)/.test(url)) {
      sent.push({ url, init: init ?? {} })
      return new Response(null, { status: pushStatus })
    }
    return realFetch(input, init)
  }) as typeof fetch
})
afterEach(() => {
  globalThis.fetch = realFetch
})

const subscribe = (token: string, ua: Ua, id = 'device-1', method = 'POST') =>
  authed(`/api/devices/identifier/${id}/web-push-auth`, token, method, {
    endpoint: ua.endpoint,
    ...ua.keys,
  })

const rowOf = (email: string, identifier: string) =>
  env.DB.prepare(
    'SELECT d.web_push_endpoint AS endpoint, d.web_push_p256dh AS p256dh, d.push_token AS pushToken FROM devices d JOIN users u ON u.uuid = d.user_uuid WHERE u.email = ?1 AND d.identifier = ?2',
  )
    .bind(email, identifier)
    .first<{ endpoint: string | null; p256dh: string | null; pushToken: string | null }>()

const userUuid = async (email: string) =>
  (
    await env.DB.prepare('SELECT uuid FROM users WHERE email = ?1')
      .bind(email)
      .first<{ uuid: string }>()
  )?.uuid as string

describe('device routes', () => {
  it('stores a web push subscription with POST and PUT and rejects bad ones', async () => {
    const email = uemail('wp')
    const s = await createSession(email)
    const ua = await browser()
    expect((await subscribe(s.access_token, ua)).status).toBe(200)
    expect((await rowOf(email, 'device-1'))?.endpoint).toBe(ua.endpoint)
    const ua2 = await browser('https://updates.push.services.mozilla.com/wpush/v2/')
    expect((await subscribe(s.access_token, ua2, 'device-1', 'PUT')).status).toBe(200)
    expect((await rowOf(email, 'device-1'))?.endpoint).toBe(ua2.endpoint)

    for (const body of [
      { endpoint: 'https://evil.example.com/x', ...ua.keys },
      { endpoint: 'http://fcm.googleapis.com/x', ...ua.keys },
      { endpoint: 'https://169.254.169.254/x', ...ua.keys },
      { endpoint: ua.endpoint, p256dh: 'AAAA', auth: ua.keys.auth },
      { endpoint: ua.endpoint, p256dh: ua.keys.p256dh, auth: 'AAAA' },
      { endpoint: ua.endpoint },
    ]) {
      const res = await authed(
        '/api/devices/identifier/device-1/web-push-auth',
        s.access_token,
        'POST',
        body,
      )
      expect(res.status, JSON.stringify(body)).toBe(400)
    }
    // Unchanged by the rejected requests.
    expect((await rowOf(email, 'device-1'))?.endpoint).toBe(ua2.endpoint)
  })

  it('requires sign-in and an own device', async () => {
    const a = await createSession(uemail('wpa'))
    const b = await createSession(uemail('wpb'), { deviceIdentifier: 'only-b' })
    const ua = await browser()
    expect((await subscribe(a.access_token, ua, 'only-b')).status).toBe(404)
    expect((await subscribe(b.access_token, ua, 'only-b')).status).toBe(200)
    const anon = await SELF.fetch(`${BASE}/api/devices/identifier/device-1/web-push-auth`, {
      method: 'POST',
      body: '{}',
      headers: { 'Content-Type': 'application/json' },
    })
    expect(anon.status).toBe(401)
  })

  it('clears the push token with PUT and POST', async () => {
    const email = uemail('clr')
    const s = await createSession(email)
    await authed('/api/devices/identifier/device-1/token', s.access_token, 'PUT', {
      pushToken: 'mobile-token',
    })
    expect((await rowOf(email, 'device-1'))?.pushToken).toBe('mobile-token')
    expect(
      (await authed('/api/devices/identifier/device-1/clear-token', s.access_token, 'PUT')).status,
    ).toBe(200)
    expect((await rowOf(email, 'device-1'))?.pushToken).toBeNull()
    await authed('/api/devices/identifier/device-1/token', s.access_token, 'PUT', {
      pushToken: 'again',
    })
    expect(
      (await authed('/api/devices/identifier/device-1/clear-token', s.access_token, 'POST')).status,
    ).toBe(200)
    expect((await rowOf(email, 'device-1'))?.pushToken).toBeNull()
    expect(
      (await authed('/api/devices/identifier/nope/clear-token', s.access_token, 'PUT')).status,
    ).toBe(404)
    expect(
      (await SELF.fetch(`${BASE}/api/devices/identifier/device-1/clear-token`, { method: 'PUT' }))
        .status,
    ).toBe(401)
  })
})

describe('web push registration limits', () => {
  it('rejects a key that is not a curve point and caps subscriptions per account', async () => {
    const email = uemail('cap')
    const s = await createSession(email)
    const ua = await browser()
    const offCurve = toB64u(Uint8Array.of(4, ...new Uint8Array(64).fill(1)))
    const bad = await authed(
      '/api/devices/identifier/device-1/web-push-auth',
      s.access_token,
      'POST',
      {
        endpoint: ua.endpoint,
        p256dh: offCurve,
        auth: ua.keys.auth,
      },
    )
    expect(bad.status).toBe(400)
    // Fill the account to the cap with extra device rows, then one more is refused.
    const uuid = await userUuid(email)
    for (let i = 0; i < 20; i++) {
      await env.DB.prepare(
        "INSERT INTO devices (uuid, identifier, user_uuid, name, type, refresh_token, web_push_endpoint, web_push_p256dh, web_push_auth, created_at, updated_at) VALUES (?1, ?2, ?3, 'x', 9, 'r', 'https://fcm.googleapis.com/x', ?4, ?5, 1, 1)",
      )
        .bind(crypto.randomUUID(), `cap-${i}`, uuid, ua.keys.p256dh, ua.keys.auth)
        .run()
    }
    expect((await subscribe(s.access_token, ua)).status).toBe(400)
    // Replacing an existing subscription is still fine.
    expect((await subscribe(s.access_token, ua, 'cap-0')).status).toBe(200)
  })
})

describe('/api/config web push', () => {
  const cfg = async () =>
    (await (await SELF.fetch(`${BASE}/api/config`)).json()) as { push: Record<string, unknown> }

  it('advertises a VAPID key generated once and sealed at rest', async () => {
    const first = await cfg()
    expect(first.push.pushTechnology).toBe(1)
    const key = first.push.vapidPublicKey as string
    expect((fromB64u(key) as Uint8Array).length).toBe(65)
    invalidateWebPush()
    expect((await cfg()).push.vapidPublicKey).toBe(key)
    const row = await env.DB.prepare(
      "SELECT config, sealed_secrets FROM instance_settings WHERE key = 'webpush'",
    ).first<{ config: string; sealed_secrets: string }>()
    expect(JSON.parse(row?.config ?? '{}')).toEqual({ publicKey: key, enabled: true })
    expect(row?.sealed_secrets).toMatch(/^v1\./)
    expect(row?.config).not.toMatch(/PRIVATE|"d"/)
  })

  it('concurrent first requests end up with one key', async () => {
    const keys = await Promise.all([cfg(), cfg(), cfg(), cfg()])
    invalidateWebPush()
    const settled = (await cfg()).push.vapidPublicKey
    const rows = await env.DB.prepare(
      "SELECT COUNT(*) AS n FROM instance_settings WHERE key = 'webpush'",
    ).first<{ n: number }>()
    expect(rows?.n).toBe(1)
    expect(keys.map((k) => k.push.vapidPublicKey).includes(settled)).toBe(true)
  })
})

describe('instance admin web push switch', () => {
  async function admin() {
    const email = uemail('wpadmin')
    const s = await createSession(email)
    const over = { ADMIN_ENABLED: 'true', ADMIN_EMAILS: email }
    const call = (method: string, body?: unknown, token = s.access_token) =>
      withEnv(over, '/api/cloudwarden/admin/web-push', {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      })
    return { call, over, email }
  }

  it('shows state, switches off and on, audits, and refuses non-admins', async () => {
    const a = await admin()
    const view = (await (await a.call('GET')).json()) as any
    expect(view).toMatchObject({ enabled: true, available: true })
    const before = view.subscriptions as number
    const sub = await createSession(uemail('wpcount'))
    await subscribe(sub.access_token, await browser())
    expect(((await (await a.call('GET')).json()) as any).subscriptions).toBe(before + 1)
    expect(view.publicKey).toMatch(/^[\w-]{87}$/)
    expect(JSON.stringify(view)).not.toMatch(/sealed|private/i)

    const off = (await (await a.call('PUT', { enabled: false })).json()) as any
    expect(off.enabled).toBe(false)
    const cfg = (await (await SELF.fetch(`${BASE}/api/config`)).json()) as any
    expect(cfg.push).toEqual({ pushTechnology: 0 })
    const on = (await (await a.call('PUT', { enabled: true })).json()) as any
    expect(on).toMatchObject({ enabled: true, publicKey: view.publicKey })
    expect(((await (await SELF.fetch(`${BASE}/api/config`)).json()) as any).push).toEqual({
      pushTechnology: 1,
      vapidPublicKey: view.publicKey,
    })
    const events = await env.DB.prepare(
      'SELECT COUNT(*) AS n FROM events WHERE event_type = 9012',
    ).first<{ n: number }>()
    expect(events?.n).toBeGreaterThanOrEqual(2)

    expect((await a.call('PUT', { enabled: 'yes' })).status).toBe(400)
    expect((await a.call('PUT', {})).status).toBe(400)
    const other = await createSession(uemail('notadmin'))
    expect((await a.call('GET', undefined, other.access_token)).status).toBe(403)
    expect((await a.call('PUT', { enabled: false }, other.access_token)).status).toBe(403)
  })
})

describe('web push delivery', () => {
  async function setup() {
    const email = uemail('dlv')
    const s = await createSession(email)
    const s2 = (await (
      await login(email, 'client-derived-hash', { deviceIdentifier: 'device-2' })
    ).json()) as any
    const ua1 = await browser()
    const ua2 = await browser('https://updates.push.services.mozilla.com/wpush/v2/')
    await subscribe(s.access_token, ua1, 'device-1')
    await subscribe(s2.access_token, ua2, 'device-2')
    await SELF.fetch(`${BASE}/api/config`)
    return { email, s, ua1, ua2, uuid: await userUuid(email) }
  }
  const fire = (uuid: string, exclude?: string) =>
    pushUserUpdate(
      env,
      uuid,
      PushType.SyncVault,
      { UserId: uuid, Date: '2026-01-01T00:00:00Z' },
      exclude,
    )

  it('encrypts one message per subscriber and skips the acting device', async () => {
    const { uuid, ua1, ua2 } = await setup()
    await fire(uuid, 'device-1')
    expect(sent.map((s) => s.url)).toEqual([ua2.endpoint])
    const { url, init } = sent[0] as Sent
    expect(init.method).toBe('POST')
    expect(init.redirect).toBe('manual')
    const h = init.headers as Record<string, string>
    expect(h['Content-Encoding']).toBe('aes128gcm')
    expect(h.TTL).toBe('300')
    expect(h.Authorization).toMatch(/^vapid t=[\w-]+\.[\w-]+\.[\w-]+, k=[\w-]{87}$/)
    const claims = JSON.parse(
      new TextDecoder().decode(
        fromB64u(h.Authorization?.split('t=')[1]?.split('.')[1] ?? '') as Uint8Array,
      ),
    )
    expect(claims.aud).toBe(new URL(url).origin)
    expect(claims.sub).toBe('https://vault.example.com')
    const plain = JSON.parse(await decrypt(init.body as Uint8Array, ua2))
    expect(plain).toEqual({
      data: {
        ContextId: 'device-1',
        Type: PushType.SyncVault,
        Payload: { UserId: uuid, Date: '2026-01-01T00:00:00Z' },
      },
    })
    // Another browser cannot read it.
    await expect(decrypt(init.body as Uint8Array, ua1)).rejects.toThrow()

    sent = []
    await fire(uuid)
    expect(sent.map((s) => s.url).sort()).toEqual([ua1.endpoint, ua2.endpoint].sort())
  })

  it('removes a subscription the push service reports gone (404 and 410), keeps it on other errors', async () => {
    const { email, uuid } = await setup()
    pushStatus = 500
    await fire(uuid)
    expect((await rowOf(email, 'device-1'))?.endpoint).not.toBeNull()
    pushStatus = 404
    await fire(uuid)
    expect((await rowOf(email, 'device-1'))?.endpoint).toBeNull()
    expect((await rowOf(email, 'device-1'))?.p256dh).toBeNull()
    expect((await rowOf(email, 'device-2'))?.endpoint).toBeNull()

    const again = await setup()
    pushStatus = 410
    await fire(again.uuid)
    expect((await rowOf(again.email, 'device-1'))?.endpoint).toBeNull()
  })

  it('drops a subscription whose stored key cannot be used', async () => {
    const { email, uuid } = await setup()
    await env.DB.prepare(
      "UPDATE devices SET web_push_p256dh = ?2 WHERE identifier = 'device-1' AND user_uuid = ?1",
    )
      .bind(uuid, toB64u(Uint8Array.of(4, ...new Uint8Array(64).fill(1))))
      .run()
    await fire(uuid)
    expect((await rowOf(email, 'device-1'))?.endpoint).toBeNull()
    expect((await rowOf(email, 'device-2'))?.endpoint).not.toBeNull()
  })

  it('never contacts an endpoint outside the allow-list, even one stored directly', async () => {
    const { email, uuid } = await setup()
    await env.DB.prepare(
      "UPDATE devices SET web_push_endpoint = 'https://internal.example.com/hook' WHERE identifier = 'device-1' AND user_uuid = ?1",
    )
      .bind(uuid)
      .run()
    await fire(uuid)
    expect(sent.map((s) => s.url).some((u) => u.includes('internal.example.com'))).toBe(false)
    expect((await rowOf(email, 'device-1'))?.endpoint).toBeNull()
  })

  it('sends nothing when the instance admin turned web push off', async () => {
    const { uuid } = await setup()
    await env.DB.prepare(
      "UPDATE instance_settings SET config = json_set(config, '$.enabled', json('false')) WHERE key = 'webpush'",
    ).run()
    invalidateWebPush()
    await fire(uuid)
    expect(sent).toEqual([])
  })

  it('does no push work for users without subscriptions and survives a fetch failure', async () => {
    const quiet = await userUuid((await actor(uemail('quiet'))).email)
    await fire(quiet)
    expect(sent).toEqual([])
    const { uuid } = await setup()
    globalThis.fetch = (async () => {
      throw new Error('network down')
    }) as typeof fetch
    await expect(fire(uuid)).resolves.toBeUndefined()
  })
})

// ----- Organisation public key and connections -----

describe('organisation public key', () => {
  it('serves confirmed members only', async () => {
    const owner = await actor(uemail('pkown'))
    const o = await createOrg(owner)
    const member = await actor(uemail('pkmem'))
    const outsider = await actor(uemail('pkout'))
    await addMember(owner, o.id, member)
    const mine = await owner.call(`/api/organizations/${o.id}/public-key`)
    expect(mine.status).toBe(200)
    expect(await mine.json()).toEqual({ object: 'organizationPublicKey', publicKey: 'orgPublic' })
    expect((await member.call(`/api/organizations/${o.id}/public-key`)).status).toBe(200)
    expect((await outsider.call(`/api/organizations/${o.id}/public-key`)).status).toBe(404)
    expect(
      (await outsider.call('/api/organizations/00000000-0000-4000-8000-000000000000/public-key'))
        .status,
    ).toBe(404)
    expect((await SELF.fetch(`${BASE}/api/organizations/${o.id}/public-key`)).status).toBe(401)
  })
})

describe('organisation connections', () => {
  it('answers like a self-hosted server with cloud communication disabled', async () => {
    const owner = await actor(uemail('cnown'))
    const o = await createOrg(owner)
    const member = await actor(uemail('cnmem'))
    await addMember(owner, o.id, member)
    const outsider = await actor(uemail('cnout'))

    expect(await (await owner.call('/api/organizations/connections/enabled')).json()).toBe(false)
    expect((await SELF.fetch(`${BASE}/api/organizations/connections/enabled`)).status).toBe(401)

    const create = (a: typeof owner, type = 1) =>
      a.call('/api/organizations/connections/', 'POST', {
        type,
        organizationId: o.id,
        enabled: true,
        config: { billingSyncKey: 'k' },
      })
    const refused = await create(owner)
    expect(refused.status).toBe(400)
    expect(((await refused.json()) as any).message).toBe('Cloud communication is disabled.')
    for (const a of [member, outsider]) {
      const res = await create(a)
      expect(res.status).toBe(400)
      expect(((await res.json()) as any).message).toBe(
        'Only the owner of an organization can create a connection.',
      )
    }
    // SCIM connections follow the manage SCIM permission, which owners hold.
    expect(((await (await create(owner, 2)).json()) as any).message).toBe(
      'Cloud communication is disabled.',
    )

    const id = '00000000-0000-4000-8000-000000000000'
    expect(
      (
        await owner.call(`/api/organizations/connections/${id}`, 'PUT', {
          type: 1,
          organizationId: o.id,
        })
      ).status,
    ).toBe(404)
    expect((await owner.call(`/api/organizations/connections/${id}`, 'DELETE')).status).toBe(404)
    expect((await owner.call(`/api/organizations/connections/${o.id}/1`)).status).toBe(204)
    expect((await member.call(`/api/organizations/connections/${o.id}/2`)).status).toBe(204)
    expect((await outsider.call(`/api/organizations/connections/${o.id}/1`)).status).toBe(400)
    expect(
      (await SELF.fetch(`${BASE}/api/organizations/connections/${id}`, { method: 'DELETE' }))
        .status,
    ).toBe(401)
  })
})

// ----- SSO cookie vendor -----

describe('GET /api/sso-cookie-vendor', () => {
  const get = (cookie: string | null, name?: string) =>
    withEnv(name ? { SSO_COOKIE_VENDOR_COOKIE_NAME: name } : {}, '/api/sso-cookie-vendor', {
      headers: cookie ? { Cookie: cookie } : {},
    })

  it('is absent unless a proxy cookie name is configured', async () => {
    expect((await get('AWSELBAuthSessionCookie-0=abc')).status).toBe(404)
  })

  it('confirms the proxy cookie, including sharded cookies, and never echoes it', async () => {
    const n = 'AWSELBAuthSessionCookie'
    expect((await get(null, n)).status).toBe(401)
    expect((await get('other=1', n)).status).toBe(401)
    expect((await get(`${n}x=1; ${n}-a=2`, n)).status).toBe(401)
    for (const cookie of [`${n}=secret-value`, `a=b; ${n}-0=s1; ${n}-1=s2`]) {
      const res = await get(cookie, n)
      expect(res.status).toBe(200)
      expect(res.headers.get('Cache-Control')).toBe('no-store')
      // A login in progress keeps its flow cookie.
      expect(res.headers.get('Set-Cookie')).toBeNull()
      expect(await res.text()).not.toContain('secret')
    }
  })
})

// ----- Key Connector enrolment and the upstream SSO paths -----

let idp: OidcIdp
beforeAll(async () => {
  idp = await startIdp()
})

async function ssoOrg(memberDecryptionType = 0) {
  const owner = await actor(uemail('ssoown'))
  const o = await createOrg(owner)
  const identifier = unique('sso')
  if (memberDecryptionType === 1) {
    for (const p of [3, 4]) {
      expect(
        (
          await owner.call(`/api/organizations/${o.id}/policies/${p}`, 'PUT', {
            enabled: true,
            data: null,
          })
        ).status,
      ).toBe(200)
    }
  }
  await configureOidc(owner, o.id, identifier, idp, {
    memberDecryptionType,
    keyConnectorUrl: 'https://kc.example.com',
  })
  return { owner, org: o, identifier }
}

describe('POST /api/accounts/key-connector/enroll', () => {
  const KEY = '2.aXZpdg==|ZGF0YQ==|bWFj'
  const enroll = (token: string, key: unknown = KEY) =>
    authedCall(token, '/api/accounts/key-connector/enroll', 'POST', {
      keyConnectorKeyWrappedUserKey: key,
    })
  const jit = async (identifier: string) => {
    const email = uemail('kcjit')
    const r = await oidcLogin(idp, identifier, { sub: unique('sub'), email })
    expect(r.token?.status).toBe(200)
    return { email, token: r.body.access_token as string }
  }
  const stamp = async (email: string) =>
    (
      await env.DB.prepare('SELECT security_stamp s FROM users WHERE email = ?1')
        .bind(email)
        .first<{ s: string }>()
    )?.s

  it('stores the key of a new SSO member, rotates the stamp and signs out other devices', async () => {
    const { identifier } = await ssoOrg(1)
    const u = await jit(identifier)
    const uuid = await userUuid(u.email)
    await env.DB.prepare(
      "INSERT INTO devices (uuid, identifier, user_uuid, name, type, refresh_token, created_at, updated_at) VALUES (?1, 'kc-other', ?2, 'x', 9, 'live-refresh', 1, 1)",
    )
      .bind(crypto.randomUUID(), uuid)
      .run()
    const before = await stamp(u.email)
    const first = await enroll(u.token)
    expect(first.status).toBe(200)
    const row = await env.DB.prepare(
      'SELECT akey, uses_key_connector k FROM users WHERE email = ?1',
    )
      .bind(u.email)
      .first<{ akey: string; k: number }>()
    expect(row).toEqual({ akey: KEY, k: 1 })
    expect(await stamp(u.email)).not.toBe(before)
    const devices = await env.DB.prepare(
      'SELECT identifier i, refresh_token r FROM devices WHERE user_uuid = ?1',
    )
      .bind(uuid)
      .all<{ i: string; r: string }>()
    expect(devices.results.find((d) => d.i === 'kc-other')?.r).toBe('')
    expect(devices.results.find((d) => d.i === 'sso-device-1')?.r).not.toBe('')
    // The old access token is dead; a second enrolment is refused.
    expect((await enroll(u.token)).status).toBe(401)
  })

  it('refuses members with a master password, anyone with keys, and malformed keys', async () => {
    const { owner, org: o, identifier } = await ssoOrg(1)
    const member = await actor(uemail('kcmem'))
    await addMember(owner, o.id, member)
    // Master password holders (owner included) use convert-to-key-connector instead.
    expect((await enroll(owner.token)).status).toBe(400)
    expect((await enroll(member.token)).status).toBe(400)
    expect((await enroll(member.token, '')).status).toBe(400)

    const u = await jit(identifier)
    for (const key of ['', '4.kcWrapped', '2.not base64|x|y', '2.aXZpdg==|ZGF0YQ==', 'plain', 5]) {
      expect((await enroll(u.token, key)).status, String(key)).toBe(400)
    }
    expect(
      (await authedCall(u.token, '/api/accounts/key-connector/enroll', 'POST', {})).status,
    ).toBe(400)
    // An account that already has keys is refused.
    await env.DB.prepare("UPDATE users SET akey = '2.a|b|c' WHERE email = ?1").bind(u.email).run()
    expect((await enroll(u.token)).status).toBe(400)
    expect(
      (
        await SELF.fetch(`${BASE}/api/accounts/key-connector/enroll`, {
          method: 'POST',
          body: '{}',
        })
      ).status,
    ).toBe(401)
  })

  it('refuses members of organisations that do not use Key Connector, and stand-in accounts', async () => {
    const { identifier } = await ssoOrg(0)
    const u = await jit(identifier)
    expect((await enroll(u.token)).status).toBe(400)
    const standIn = await actor(uemail('standin'))
    await env.DB.prepare("UPDATE users SET password_hash = '!federated.x' WHERE email = ?1")
      .bind(standIn.email)
      .run()
    // Stand-in accounts are refused (by the auth layer or the handler), never enrolled.
    expect([400, 401]).toContain((await enroll(standIn.token)).status)
  })
})

describe('upstream SSO paths', () => {
  async function authorizeUrl(identifier: string, extra: Record<string, string> = {}) {
    const pre = await inproc(
      `/identity/sso/prevalidate?domainHint=${encodeURIComponent(identifier)}`,
    )
    const { token } = (await pre.json()) as { token: string }
    const { verifier, challenge } = await pkce()
    const q = new URLSearchParams({
      client_id: 'web',
      redirect_uri: `${BASE}/sso-connector.html`,
      response_type: 'code',
      scope: 'api offline_access',
      state: `s123_identifier=${identifier}`,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      response_mode: 'query',
      domain_hint: identifier,
      ssoToken: token,
      ...extra,
    })
    return { path: `/identity/connect/authorize?${q}`, verifier, token }
  }
  const loc = (r: Response) => r.headers.get('Location') ?? ''

  it('runs a whole login through Login, ExternalChallenge and ExternalCallback', async () => {
    const { identifier } = await ssoOrg(0)
    const a = await authorizeUrl(identifier)

    const login1 = await inproc(`/identity/sso/Login?returnUrl=${encodeURIComponent(a.path)}`)
    expect(login1.status).toBe(302)
    const challenge = new URL(loc(login1), BASE)
    expect(challenge.pathname).toBe('/identity/sso/ExternalChallenge')
    expect(challenge.searchParams.get('domainHint')).toBe(identifier)
    expect(challenge.searchParams.get('ssoToken')).toBe(a.token)
    expect(challenge.searchParams.get('returnUrl')).toBe(a.path)

    const ch = await inproc(`${challenge.pathname}${challenge.search}`)
    expect(ch.status).toBe(302)
    const auth = new URL(loc(ch), BASE)
    expect(auth.pathname).toBe('/identity/connect/authorize')
    expect(auth.searchParams.get('code_challenge')).toBeTruthy()
    expect(auth.searchParams.get('domain_hint')).toBe(identifier)

    const toIdp = await inproc(`${auth.pathname}${auth.search}`)
    expect(toIdp.status).toBe(302)
    const cookie = (toIdp.headers.get('Set-Cookie') ?? '').split(';')[0] ?? ''
    expect(cookie).not.toBe('')
    const back = new URL(idp.authorize(loc(toIdp), { sub: unique('sub'), email: uemail('sso') }))
    const viaExternal = await callback(`/identity/sso/ExternalCallback${back.search}`, cookie)
    expect(viaExternal.status).toBe(302)
    const done = new URL(loc(viaExternal))
    expect(`${done.origin}${done.pathname}`).toBe(`${BASE}/sso-connector.html`)
    expect(done.searchParams.get('state')).toBe(`s123_identifier=${identifier}`)
    const token = await redeem(codeFrom(loc(viaExternal)), a.verifier)
    expect(token.status).toBe(200)
  })

  it('lets ExternalChallenge override the hint and tokens like the official controller', async () => {
    const { identifier } = await ssoOrg(0)
    const a = await authorizeUrl(identifier, { domain_hint: 'wrong' })
    const ch = await inproc(
      `/identity/sso/ExternalChallenge?domainHint=${identifier}&ssoToken=${a.token}&returnUrl=${encodeURIComponent(a.path)}`,
    )
    expect(new URL(loc(ch), BASE).searchParams.get('domain_hint')).toBe(identifier)
    const toIdp = await inproc(loc(ch))
    expect(toIdp.status).toBe(302)
    expect(loc(toIdp).startsWith(idp.issuer)).toBe(true)
  })

  it('refuses return URLs that are not this server authorize endpoint', async () => {
    const { identifier } = await ssoOrg(0)
    const a = await authorizeUrl(identifier)
    const good = a.path
    for (const bad of [
      `https://evil.example.com${good}`,
      `//evil.example.com${good}`,
      '/identity/connect/token?x=1',
      '/identity/sso/Login',
      'javascript:alert(1)',
      '',
    ]) {
      for (const route of ['Login', 'ExternalChallenge']) {
        const res = await inproc(
          `/identity/sso/${route}?domainHint=${identifier}&returnUrl=${encodeURIComponent(bad)}`,
        )
        expect(res.status, `${route} ${bad}`).toBe(400)
        expect(loc(res)).toBe('')
      }
    }
    expect((await inproc('/identity/sso/Login')).status).toBe(400)
    // No domain hint anywhere.
    const noHint = new URL(good, BASE)
    noHint.searchParams.delete('domain_hint')
    expect(
      (
        await inproc(
          `/identity/sso/Login?returnUrl=${encodeURIComponent(noHint.pathname + noHint.search)}`,
        )
      ).status,
    ).toBe(400)
  })

  it('keeps the authorize hardening: PKCE, redirect allow-list, prevalidation token, state', async () => {
    const { identifier } = await ssoOrg(0)
    const through = async (mutate: (q: URLSearchParams) => void) => {
      const a = await authorizeUrl(identifier)
      const u = new URL(a.path, BASE)
      mutate(u.searchParams)
      const ch = await inproc(
        `/identity/sso/ExternalChallenge?returnUrl=${encodeURIComponent(u.pathname + u.search)}`,
      )
      expect(ch.status).toBe(302)
      return inproc(loc(ch))
    }
    expect((await through(() => {})).status).toBe(302)
    expect((await through((q) => q.delete('code_challenge'))).status).toBe(400)
    expect((await through((q) => q.set('code_challenge_method', 'plain'))).status).toBe(400)
    expect(
      (await through((q) => q.set('redirect_uri', 'https://evil.example.com/cb'))).status,
    ).toBe(400)
    expect((await through((q) => q.delete('state'))).status).toBe(400)
    expect((await through((q) => q.set('ssoToken', 'forged'))).status).toBe(400)
    expect((await through((q) => q.set('domain_hint', 'nonexistent-org'))).status).toBe(400)
    // The identity provider return still needs the flow cookie and a known state.
    expect((await inproc('/identity/sso/ExternalCallback?code=x&state=unknown')).status).toBe(400)
    expect((await inproc('/identity/sso/ExternalCallback')).status).toBe(400)
  })

  it('still serves the existing oidc-signin path with a full login', async () => {
    const { identifier } = await ssoOrg(0)
    const r = await oidcLogin(idp, identifier, { sub: unique('sub'), email: uemail('legacy') })
    expect(r.token?.status).toBe(200)
    expect(authedCall).toBeDefined()
  })
})
