import { env } from 'cloudflare:workers'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { AdminEventType } from '../src/admin/service'
import {
  deriveUris,
  invalidatePushConfig,
  validateRelayUri,
} from '../src/notifications/push-config'
import { relayStatus, resolveRelay } from '../src/notifications/relay'
import { authed, createSession, freezeRateLimitWindow, withEnv } from './helpers'

const P = '/api/cloudwarden/admin/push-settings'
const KEY = 'super-secret-installation-key-0123456789'
const ID = '00000000-0000-4000-8000-000000000002'

let n = 0
async function person(admin: boolean, extra: Record<string, unknown> = {}) {
  const email = `push${++n}@example.com`
  const s = await createSession(email)
  const over = {
    ADMIN_ENABLED: 'true',
    ADMIN_EMAILS: admin ? email : 'nobody@example.com',
    ...extra,
  }
  const call = (path: string, method = 'GET', body?: unknown) =>
    withEnv(over, path, {
      method,
      headers: {
        Authorization: `Bearer ${s.access_token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
  return { email, token: s.access_token, over, call }
}

interface Seen {
  url: string
  body: any
}
let seen: Seen[] = []
let tokenStatus = 200
let realFetch: typeof fetch
beforeEach(async () => {
  invalidatePushConfig()
  await env.DB.prepare('DELETE FROM instance_settings').run()
  seen = []
  tokenStatus = 200
  realFetch = globalThis.fetch
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input)
    if (url.startsWith('https://vault.example.com')) return realFetch(input, init)
    const raw = init?.body
    seen.push({
      url,
      body:
        raw instanceof URLSearchParams
          ? Object.fromEntries(raw)
          : raw
            ? JSON.parse(String(raw))
            : null,
    })
    if (url.endsWith('/connect/token')) {
      return tokenStatus === 200
        ? Response.json({ access_token: 'relay-token', expires_in: 3600 })
        : new Response('no', { status: tokenStatus })
    }
    return new Response(null, { status: 200 })
  }) as typeof fetch
})
afterEach(() => {
  globalThis.fetch = realFetch
})

const save = (who: Awaited<ReturnType<typeof person>>, extra: Record<string, unknown> = {}) =>
  who.call(P, 'PUT', { installationId: ID, installationKey: KEY, region: 'us', ...extra })

describe('region URI derivation and validation', () => {
  it('derives the US and EU relay and identity URIs', () => {
    expect(deriveUris('us')).toEqual({
      relayUri: 'https://push.bitwarden.com',
      identityUri: 'https://identity.bitwarden.com',
    })
    expect(deriveUris('eu')).toEqual({
      relayUri: 'https://push.bitwarden.eu',
      identityUri: 'https://identity.bitwarden.eu',
    })
  })

  it('accepts custom https URIs and rejects unsafe ones', () => {
    expect(validateRelayUri('https://push.example.com/')).toBe('https://push.example.com')
    expect(validateRelayUri('https://push.example.com:443')).toBe('https://push.example.com')
    for (const bad of [
      'http://push.example.com',
      'https://user:pw@push.example.com',
      'https://push.example.com/?a=1',
      'https://localhost',
      'https://127.0.0.1',
      'https://[::1]',
      'https://push.example.com.',
      'https://push.example.com:8443',
      'https://push.example.com/x?',
      'https://relay.local',
      'https://relay.internal',
      'https://a.localhost',
      'https://nas.lan',
      'https://printer.home.arpa',
      'ftp://push.example.com',
      'not a url',
      42,
    ]) {
      expect(validateRelayUri(bad), String(bad)).toBeNull()
    }
    expect(deriveUris('custom', { relayUri: 'https://a.example.com' })).toBeNull()
    expect(
      deriveUris('custom', {
        relayUri: 'https://a.example.com',
        identityUri: 'https://b.example.com',
      }),
    ).toEqual({ relayUri: 'https://a.example.com', identityUri: 'https://b.example.com' })
  })
})

describe('relay hardening', () => {
  it('does not follow redirects and reports them as a rejected test', async () => {
    const admin = await person(true)
    await save(admin)
    const calls: RequestInit[] = []
    const inner = globalThis.fetch
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/connect/token')) {
        calls.push(init ?? {})
        return new Response(null, {
          status: 302,
          headers: { Location: 'https://evil.example.com' },
        })
      }
      return inner(input, init)
    }) as typeof fetch
    const res = await admin.call(`${P}/test`, 'POST')
    expect(await res.json()).toEqual({ ok: false, error: 'rejected' })
    expect(calls[0]?.redirect).toBe('manual')
    expect(calls[0]?.signal).toBeDefined()
  })

  it('reports an unreachable relay when the request fails', async () => {
    const admin = await person(true)
    await save(admin)
    const inner = globalThis.fetch
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('/connect/token')) throw new Error('timeout')
      return inner(input, init)
    }) as typeof fetch
    expect(await (await admin.call(`${P}/test`, 'POST')).json()).toEqual({
      ok: false,
      error: 'unreachable',
    })
  })

  it('shows an unreadable key state when the key cannot be opened', async () => {
    const admin = await person(true)
    await save(admin)
    await env.DB.prepare("UPDATE instance_settings SET sealed_secrets = 'v1.d.AAAA.AAAA'").run()
    invalidatePushConfig()
    const view = (await (await admin.call(P)).json()) as any
    expect(view).toMatchObject({ keySet: false, keyUnreadable: true })
    expect(view.status.state).toBe('key unreadable')
    // Saving without the key is refused; with it, the setting recovers.
    expect((await admin.call(P, 'PUT', { installationId: ID, region: 'us' })).status).toBe(400)
    const fixed = (await (await save(admin)).json()) as any
    expect(fixed).toMatchObject({ keySet: true, keyUnreadable: false })
  })

  it('rate limits saves per admin', async () => {
    const restore = freezeRateLimitWindow()
    try {
      const admin = await person(true)
      const codes: number[] = []
      for (let i = 0; i < 7; i++) codes.push((await save(admin)).status)
      expect(codes[4]).toBe(200)
      expect(codes[6]).toBe(429)
    } finally {
      restore()
    }
  })

  it('pages through every device and does not overlap runs', async () => {
    const owner = await person(true)
    await save(owner)
    const user = await createSession(`bulk${++n}@example.com`)
    const profile = (await (await authed('/api/accounts/profile', user.access_token)).json()) as {
      id: string
    }
    const stmts = Array.from({ length: 230 }, (_, i) =>
      env.DB.prepare(
        `INSERT INTO devices (uuid, user_uuid, name, type, identifier, push_token, refresh_token, created_at, updated_at)
         VALUES (?1, ?2, 'phone', 0, ?3, 'tok', 'r', 1, 1)`,
      ).bind(crypto.randomUUID(), profile.id, `bulk-${i}`),
    )
    await env.DB.batch(stmts)
    const { relayReregisterAll } = await import('../src/notifications/relay')
    seen = []
    const first = relayReregisterAll(env)
    const overlapped = await relayReregisterAll(env)
    expect(overlapped).toBe(0)
    expect(await first).toBeGreaterThanOrEqual(230)
    expect(seen.filter((s) => s.url.endsWith('/push/register')).length).toBeGreaterThanOrEqual(230)
    await env.DB.prepare("DELETE FROM devices WHERE identifier LIKE 'bulk-%'").run()
  })
})

describe('push settings API', () => {
  it('requires authentication and an admin (403 for others)', async () => {
    for (const [method, path] of [
      ['GET', P],
      ['PUT', P],
      ['DELETE', P],
      ['POST', `${P}/test`],
    ] as const) {
      const anon = await withEnv({ ADMIN_ENABLED: 'true' }, path, { method })
      expect(anon.status, `${method} ${path}`).toBe(401)
      const user = await person(false)
      const res = await user.call(path, method, method === 'PUT' ? {} : undefined)
      expect(res.status, `${method} ${path}`).toBe(403)
    }
  })

  it('never returns the key, seals it at rest and keeps it when left blank', async () => {
    const admin = await person(true)
    const put = await save(admin)
    expect(put.status).toBe(200)
    const body = await put.text()
    expect(body).not.toContain(KEY)
    const view = JSON.parse(body)
    expect(view).toMatchObject({
      installationId: ID,
      keySet: true,
      keyUnreadable: false,
      region: 'us',
      relayUri: 'https://push.bitwarden.com',
    })
    expect(await (await admin.call(P)).text()).not.toContain(KEY)

    const row = await env.DB.prepare('SELECT * FROM instance_settings').first<{
      config: string
      sealed_secrets: string
    }>()
    expect(JSON.stringify(row)).not.toContain(KEY)
    expect(row?.sealed_secrets.startsWith('v1.')).toBe(true)

    // Blank key keeps the stored one; the effective config still has it.
    const again = await admin.call(P, 'PUT', { installationId: ID, region: 'us' })
    expect(again.status).toBe(200)
    expect((await resolveRelay(env))?.cfg.installationKey).toBe(KEY)

    // Changing the destination needs the key again, so a stored key never goes to a new host.
    const moved = await admin.call(P, 'PUT', { installationId: ID, region: 'eu' })
    expect(moved.status).toBe(400)
    expect((await resolveRelay(env))?.cfg.relayUri).toBe('https://push.bitwarden.com')
    const ok = await save(admin, { region: 'eu' })
    expect(ok.status).toBe(200)
    expect(((await ok.json()) as any).relayUri).toBe('https://push.bitwarden.eu')
  })

  it('validates input', async () => {
    const admin = await person(true)
    expect((await admin.call(P, 'PUT', { installationId: ID, region: 'us' })).status).toBe(400)
    expect((await save(admin, { installationId: 'x' })).status).toBe(400)
    expect((await save(admin, { region: 'moon' })).status).toBe(400)
    expect((await save(admin, { region: 'custom', relayUri: 'http://a.example.com' })).status).toBe(
      400,
    )
    const ok = await save(admin, {
      region: 'custom',
      relayUri: 'https://push.example.com',
      identityUri: 'https://id.example.com/',
    })
    expect(ok.status).toBe(200)
    expect(((await ok.json()) as any).identityUri).toBe('https://id.example.com')
  })

  it('removes the settings and audits each change', async () => {
    const admin = await person(true)
    await save(admin)
    const del = await admin.call(P, 'DELETE')
    expect(del.status).toBe(200)
    expect(((await del.json()) as any).keySet).toBe(false)
    expect(await resolveRelay(env)).toBeNull()
    const count = async (t: number) =>
      (
        await env.DB.prepare('SELECT COUNT(*) AS c FROM events WHERE event_type = ?1')
          .bind(t)
          .first<{ c: number }>()
      )?.c ?? 0
    expect(await count(AdminEventType.PushSettingsUpdated)).toBeGreaterThan(0)
    expect(await count(AdminEventType.PushSettingsRemoved)).toBeGreaterThan(0)
  })

  it('lets Worker secrets override the stored settings', async () => {
    const admin = await person(true)
    await save(admin)
    const over = {
      PUSH_INSTALLATION_ID: 'env-installation-id',
      PUSH_INSTALLATION_KEY: 'env-key-value',
    }
    const r = await resolveRelay({ ...env, ...over })
    expect(r?.source).toBe('env')
    expect(r?.cfg.installationId).toBe('env-installation-id')
    expect(await relayStatus({ ...env, ...over })).toMatchObject({
      source: 'env',
      envOverride: true,
    })
    expect(await relayStatus(env)).toMatchObject({ source: 'settings', envOverride: false })
    const viaApi = (await (
      await withEnv({ ...admin.over, ...over }, P, {
        headers: { Authorization: `Bearer ${admin.token}` },
      })
    ).json()) as any
    expect(viaApi.status).toMatchObject({ source: 'env', envOverride: true })
  })

  it('tests the connection against a stand-in relay and returns a class only', async () => {
    const admin = await person(true)
    let res = await admin.call(`${P}/test`, 'POST')
    expect(await res.json()).toEqual({ ok: false, error: 'not_configured' })
    await save(admin)
    res = await admin.call(`${P}/test`, 'POST')
    expect(await res.json()).toEqual({ ok: true, error: null })
    const tokenCall = seen.find((s) => s.url === 'https://identity.bitwarden.com/connect/token')
    expect(tokenCall?.body).toMatchObject({
      client_id: `installation.${ID}`,
      client_secret: KEY,
      scope: 'api.push',
    })
    tokenStatus = 400
    res = await admin.call(`${P}/test`, 'POST')
    const text = await res.text()
    expect(JSON.parse(text)).toEqual({ ok: false, error: 'rejected' })
    expect(text).not.toContain(KEY)
  })

  it('rate limits the test endpoint', async () => {
    const restore = freezeRateLimitWindow()
    try {
      const admin = await person(true)
      const codes: number[] = []
      for (let i = 0; i < 7; i++) codes.push((await admin.call(`${P}/test`, 'POST')).status)
      expect(codes.slice(0, 5)).toEqual([200, 200, 200, 200, 200])
      expect(codes[6]).toBe(429)
    } finally {
      restore()
    }
  })

  it('registers existing mobile devices again when credentials change', async () => {
    const owner = await person(true)
    const phone = await createSession(`phone${++n}@example.com`, {
      deviceType: '0',
      deviceIdentifier: 'phone-1',
    })
    const tok = await authed('/api/devices/identifier/phone-1/token', phone.access_token, 'PUT', {
      pushToken: 'fcm-token-1',
    })
    expect(tok.status).toBe(204)
    seen = []
    await save(owner)
    for (let i = 0; i < 50 && !seen.some((s) => s.url.endsWith('/push/register')); i++) {
      await new Promise((r) => setTimeout(r, 20))
    }
    const reg = seen.find((s) => s.url === 'https://push.bitwarden.com/push/register')
    expect(reg?.body).toMatchObject({ pushToken: 'fcm-token-1', installationId: ID, type: 0 })

    // Saving identical values does not re-register.
    seen = []
    await save(owner)
    await new Promise((r) => setTimeout(r, 100))
    expect(seen.some((s) => s.url.endsWith('/push/register'))).toBe(false)
  })
})
