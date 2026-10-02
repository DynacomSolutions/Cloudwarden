import { env } from 'cloudflare:workers'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { PushType, pushLogOut, pushOrgUpdate, pushUserUpdate } from '../src/notifications/publish'
import { relayConfig, relayStatus } from '../src/notifications/relay'
import { BASE, createSession } from './helpers'

const cfg = {
  PUSH_INSTALLATION_ID: '00000000-0000-4000-8000-000000000001',
  PUSH_INSTALLATION_KEY: 'installation-key-for-tests',
}
const on = { ...env, ...cfg }

interface Seen {
  url: string
  method: string
  auth: string | null
  body: any
}
let seen: Seen[] = []
let respond: (url: string, n: number) => Response = (url) =>
  url.endsWith('/connect/token')
    ? Response.json({ access_token: 'relay-token', expires_in: 3600 })
    : new Response(null, { status: 200 })
let realFetch: typeof fetch

beforeEach(() => {
  seen = []
  realFetch = globalThis.fetch
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input)
    if (!url.includes('bitwarden.')) return realFetch(input, init)
    const raw = init?.body
    const body =
      raw instanceof URLSearchParams
        ? Object.fromEntries(raw)
        : typeof raw === 'string'
          ? JSON.parse(raw)
          : null
    seen.push({
      url,
      method: init?.method ?? 'GET',
      auth: new Headers(init?.headers).get('Authorization'),
      body,
    })
    return respond(url, seen.length)
  }) as typeof fetch
})
afterEach(() => {
  globalThis.fetch = realFetch
})

const sends = () => seen.filter((s) => s.url.endsWith('/push/send'))

it('is a silent no-op without credentials and reports why', async () => {
  expect(relayConfig(env)).toBeNull()
  await pushUserUpdate(env, crypto.randomUUID(), PushType.SyncVault, { UserId: 'u', Date: 'd' })
  await pushLogOut(env, crypto.randomUUID())
  expect(seen).toHaveLength(0)
  expect(relayStatus(env)).toMatchObject({
    configured: false,
    state: 'not configured',
    relayHost: null,
  })
  expect(relayStatus({ ...env, PUSH_INSTALLATION_ID: 'x' })).toMatchObject({ state: 'incomplete' })
})

it('defaults to the Bitwarden relay and never reports the key', () => {
  expect(relayConfig(on)).toMatchObject({
    relayUri: 'https://push.bitwarden.com',
    identityUri: 'https://identity.bitwarden.com',
  })
  const st = relayStatus({ ...on, PUSH_RELAY_URI: 'https://push.bitwarden.eu/' })
  expect(st).toMatchObject({ configured: true, relayHost: 'push.bitwarden.eu' })
  expect(JSON.stringify(st)).not.toContain(cfg.PUSH_INSTALLATION_KEY)
})

it('pushes a user event: token with installation credentials, then one send with exclusion', async () => {
  const user = crypto.randomUUID()
  await pushUserUpdate(on, user, PushType.SyncCipherUpdate, { Id: 'c1', UserId: user }, 'dev-x')
  expect(seen[0]).toMatchObject({
    url: 'https://identity.bitwarden.com/connect/token',
    method: 'POST',
    body: {
      grant_type: 'client_credentials',
      scope: 'api.push',
      client_id: `installation.${cfg.PUSH_INSTALLATION_ID}`,
      client_secret: cfg.PUSH_INSTALLATION_KEY,
    },
  })
  const [send] = sends()
  expect(send).toMatchObject({
    url: 'https://push.bitwarden.com/push/send',
    method: 'POST',
    auth: 'Bearer relay-token',
    body: {
      userId: user,
      organizationId: null,
      identifier: 'dev-x',
      type: PushType.SyncCipherUpdate,
      payload: { Id: 'c1', UserId: user },
      installationId: cfg.PUSH_INSTALLATION_ID,
    },
  })
})

it('reuses the token across pushes and renews it once after a 401', async () => {
  const user = crypto.randomUUID()
  let rejected = false
  respond = (url) => {
    if (url.endsWith('/connect/token'))
      return Response.json({ access_token: 'fresh', expires_in: 3600 })
    if (!rejected) {
      rejected = true
      return new Response(null, { status: 401 })
    }
    return new Response(null, { status: 200 })
  }
  await pushUserUpdate(on, user, PushType.SyncVault, { UserId: user, Date: 'd' })
  expect(sends()).toHaveLength(2)
  expect(sends()[1]?.auth).toBe('Bearer fresh')
  const tokenCalls = seen.filter((s) => s.url.endsWith('/connect/token')).length
  await pushUserUpdate(on, user, PushType.SyncVault, { UserId: user, Date: 'd' })
  expect(seen.filter((s) => s.url.endsWith('/connect/token')).length).toBe(tokenCalls)
  respond = (url) =>
    url.endsWith('/connect/token')
      ? Response.json({ access_token: 'relay-token', expires_in: 3600 })
      : new Response(null, { status: 200 })
})

it('sends LogOut and organisation pushes; organisation pushes reach members once on the relay', async () => {
  const user = crypto.randomUUID()
  await pushLogOut(on, user, 'dev-o')
  expect(sends().at(-1)?.body).toMatchObject({
    userId: user,
    identifier: 'dev-o',
    type: PushType.LogOut,
    payload: { UserId: user },
  })
  seen = []
  const org = crypto.randomUUID()
  const members = [crypto.randomUUID(), crypto.randomUUID(), crypto.randomUUID()]
  await pushOrgUpdate(
    on,
    org,
    members,
    PushType.SyncOrganizations,
    { UserId: null, Date: 'd' },
    'dev-a',
    members[0],
  )
  expect(sends()).toHaveLength(1)
  expect(sends()[0]?.body).toMatchObject({
    userId: null,
    organizationId: org,
    identifier: 'dev-a',
    type: PushType.SyncOrganizations,
  })
})

it('a failing relay never fails the caller', async () => {
  respond = () => new Response('nope', { status: 500 })
  await expect(
    pushUserUpdate(on, crypto.randomUUID(), PushType.SyncVault, { UserId: 'u', Date: 'd' }),
  ).resolves.toBeUndefined()
  respond = () => {
    throw new Error('network down')
  }
  await expect(pushLogOut(on, crypto.randomUUID())).resolves.toBeUndefined()
  respond = (url) =>
    url.endsWith('/connect/token')
      ? Response.json({ access_token: 'relay-token', expires_in: 3600 })
      : new Response(null, { status: 200 })
})

const putToken = async (token: string, id: string, pushToken: string | null) => {
  const { default: app } = await import('../src/index')
  return app.fetch(
    new Request(`${BASE}/api/devices/identifier/${id}/token`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ pushToken }),
    }),
    on,
  )
}

it('registers a mobile device token with the relay, clears it, and deregisters on removal', async () => {
  const s = await createSession('push-mobile@example.com', {
    deviceType: '1',
    deviceIdentifier: 'ios-1',
  })
  const reg = await putToken(s.access_token, 'ios-1', 'fcm-token-1')
  expect(reg.status).toBe(204)
  await vi.waitFor(() => expect(seen.some((x) => x.url.endsWith('/push/register'))).toBe(true))
  const register = seen.find((x) => x.url.endsWith('/push/register'))
  expect(register?.body).toMatchObject({
    pushToken: 'fcm-token-1',
    type: 1,
    identifier: 'ios-1',
    organizationIds: [],
    installationId: cfg.PUSH_INSTALLATION_ID,
  })
  const deviceId = register?.body.deviceId as string

  seen = []
  await putToken(s.access_token, 'ios-1', null)
  await vi.waitFor(() => expect(seen.some((x) => x.method === 'DELETE')).toBe(true))
  expect(seen.find((x) => x.method === 'DELETE')?.url).toBe(
    `https://push.bitwarden.com/push/${deviceId}`,
  )

  await putToken(s.access_token, 'ios-1', 'fcm-token-2')
  await vi.waitFor(() => expect(seen.some((x) => x.url.endsWith('/push/register'))).toBe(true))
  seen = []
  const { default: app } = await import('../src/index')
  const del = await app.fetch(
    new Request(`${BASE}/api/devices/${deviceId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${s.access_token}` },
    }),
    on,
  )
  expect(del.status).toBe(200)
  await vi.waitFor(() => expect(seen.some((x) => x.method === 'DELETE')).toBe(true))
})

it('does not register non-mobile devices or call the relay when unconfigured', async () => {
  const s = await createSession('push-web@example.com')
  await putToken(s.access_token, 'device-1', 'whatever')
  await new Promise((r) => setTimeout(r, 30))
  expect(seen).toHaveLength(0)
  const m = await createSession('push-off@example.com', {
    deviceType: '0',
    deviceIdentifier: 'and-1',
  })
  const { default: app } = await import('../src/index')
  const res = await app.fetch(
    new Request(`${BASE}/api/devices/identifier/and-1/token`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${m.access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ pushToken: 'tok' }),
    }),
    env,
  )
  expect(res.status).toBe(204)
  expect(seen).toHaveLength(0)
})
