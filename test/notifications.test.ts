import { runDurableObjectAlarm, runInDurableObject, SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { decode, encode, type MsgValue } from '../src/notifications/msgpack'
import { PushType, pushLogOut, pushUserUpdate } from '../src/notifications/publish'
import { frame, unframe } from '../src/notifications/signalr'
import { authed, BASE, createSession, json, login, registerUser } from './helpers'

const RS = '\x1e'

async function connect(url: string) {
  const res = await SELF.fetch(url, { headers: { Upgrade: 'websocket' } })
  if (res.status !== 101 || !res.webSocket)
    return { res, ws: null, inbox: [] as (string | ArrayBuffer)[] }
  const ws = res.webSocket
  ws.binaryType = 'arraybuffer'
  const inbox: (string | ArrayBuffer)[] = []
  ws.addEventListener('message', (e) => {
    inbox.push(e.data as string | ArrayBuffer)
  })
  ws.accept()
  return { res, ws, inbox }
}

async function waitFor<T>(fn: () => T | undefined, ms = 3000): Promise<T> {
  const end = Date.now() + ms
  for (;;) {
    const v = fn()
    if (v !== undefined) return v
    if (Date.now() > end) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 10))
  }
}

const hubUrl = (token: string) => `${BASE}/notifications/hub?access_token=${token}`

async function userUuid(token: string) {
  const p = (await (await authed('/api/accounts/profile', token)).json()) as { id: string }
  return p.id
}

it('rejects missing and invalid tokens', async () => {
  const none = await connect(`${BASE}/notifications/hub`)
  expect(none.res.status).toBe(401)
  const bad = await connect(hubUrl('not-a-token'))
  expect(bad.res.status).toBe(401)
  const plain = await SELF.fetch(hubUrl('x'))
  expect(plain.status).toBe(426)
})

it('rejects a token whose security stamp was rotated', async () => {
  const s = await createSession('ws-stamp@example.com')
  const r = await authed('/api/accounts/security-stamp', s.access_token, 'POST', {
    masterPasswordHash: 'client-derived-hash',
  })
  expect(r.status).toBe(200)
  expect((await connect(hubUrl(s.access_token))).res.status).toBe(401)
})

it('completes the JSON handshake and delivers pushes', async () => {
  const s = await createSession('ws-json@example.com')
  const { ws, inbox } = await connect(hubUrl(s.access_token))
  ws?.send(`{"protocol":"json","version":1}${RS}`)
  expect(await waitFor(() => inbox.shift())).toBe(`{}${RS}`)

  const id = await userUuid(s.access_token)
  await pushUserUpdate(
    env,
    id,
    PushType.SyncVault,
    { UserId: id, Date: '2026-01-01T00:00:00.000Z' },
    'other',
  )
  const raw = (await waitFor(() => inbox.shift())) as string
  expect(raw.endsWith(RS)).toBe(true)
  expect(JSON.parse(raw.slice(0, -1))).toEqual({
    type: 1,
    target: 'ReceiveMessage',
    arguments: [
      {
        ContextId: 'other',
        Type: 5,
        Payload: { UserId: id, Date: '2026-01-01T00:00:00.000Z' },
      },
    ],
  })
  ws?.close(1000)
})

it('completes the MessagePack handshake and delivers binary frames', async () => {
  const s = await createSession('ws-mp@example.com')
  const { ws, inbox } = await connect(hubUrl(s.access_token))
  ws?.send(`{"protocol":"messagepack","version":1}${RS}`)
  expect(await waitFor(() => inbox.shift())).toBe(`{}${RS}`)

  const id = await userUuid(s.access_token)
  await pushUserUpdate(env, id, PushType.SyncCipherUpdate, {
    Id: 'c1',
    UserId: id,
    OrganizationId: null,
    CollectionIds: null,
    RevisionDate: '2026-01-01T00:00:00.000Z',
  })
  const data = (await waitFor(() => inbox.shift())) as ArrayBuffer
  const [payload] = unframe(new Uint8Array(data))
  const msg = decode(payload as Uint8Array) as MsgValue[]
  expect(msg[0]).toBe(1)
  expect(msg[2]).toBeNull()
  expect(msg[3]).toBe('ReceiveMessage')
  expect(msg[4]).toEqual([
    {
      ContextId: null,
      Type: 0,
      Payload: {
        Id: 'c1',
        UserId: id,
        OrganizationId: null,
        CollectionIds: null,
        RevisionDate: '2026-01-01T00:00:00.000Z',
      },
    },
  ])
  // Client ping is accepted silently.
  ws?.send(frame(encode([6])))
  ws?.close(1000)
})

it('rejects an unsupported protocol and never sends before the handshake', async () => {
  const s = await createSession('ws-bad@example.com')
  const { ws, inbox } = await connect(hubUrl(s.access_token))
  const id = await userUuid(s.access_token)
  await pushLogOut(env, id)
  ws?.send(`{"protocol":"xml","version":1}${RS}`)
  const reply = (await waitFor(() => inbox.shift())) as string
  expect(JSON.parse(reply.slice(0, -1)).error).toContain('xml')
  expect(inbox).toHaveLength(0)
})

it('skips the excluded device and reaches the others', async () => {
  const s1 = await createSession('ws-ex@example.com', { deviceIdentifier: 'dev-a' })
  const s2 = (await (
    await login('ws-ex@example.com', 'client-derived-hash', { deviceIdentifier: 'dev-b' })
  ).json()) as { access_token: string }
  const a = await connect(hubUrl(s1.access_token))
  const b = await connect(hubUrl(s2.access_token))
  for (const c of [a, b]) {
    c.ws?.send(`{"protocol":"json","version":1}${RS}`)
    await waitFor(() => c.inbox.shift())
  }
  const id = await userUuid(s1.access_token)
  await pushUserUpdate(env, id, PushType.SyncVault, { UserId: id, Date: 'd' }, 'dev-a')
  await waitFor(() => b.inbox.shift())
  expect(a.inbox).toHaveLength(0)
  a.ws?.close(1000)
  b.ws?.close(1000)
})

it('does not leak between users', async () => {
  const s1 = await createSession('ws-iso1@example.com')
  const s2 = await createSession('ws-iso2@example.com')
  const a = await connect(hubUrl(s1.access_token))
  const b = await connect(hubUrl(s2.access_token))
  for (const c of [a, b]) {
    c.ws?.send(`{"protocol":"json","version":1}${RS}`)
    await waitFor(() => c.inbox.shift())
  }
  await pushLogOut(env, await userUuid(s1.access_token))
  const msg = (await waitFor(() => a.inbox.shift())) as string
  expect(JSON.parse(msg.slice(0, -1)).arguments[0].Type).toBe(PushType.LogOut)
  await new Promise((r) => setTimeout(r, 50))
  expect(b.inbox).toHaveLength(0)
  a.ws?.close(1000)
  b.ws?.close(1000)
})

it('pushes LogOut to connected devices on password change', async () => {
  const s = await createSession('ws-pw@example.com')
  const { ws, inbox } = await connect(hubUrl(s.access_token))
  ws?.send(`{"protocol":"json","version":1}${RS}`)
  await waitFor(() => inbox.shift())
  const r = await authed('/api/accounts/security-stamp', s.access_token, 'POST', {
    masterPasswordHash: 'client-derived-hash',
  })
  expect(r.status).toBe(200)
  const msg = (await waitFor(() => inbox.shift())) as string
  expect(JSON.parse(msg.slice(0, -1)).arguments[0].Type).toBe(PushType.LogOut)
  ws?.close(1000)
})

it('answers negotiate', async () => {
  const s = await createSession('ws-neg@example.com')
  const res = await SELF.fetch(`${BASE}/notifications/hub/negotiate?negotiateVersion=1`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${s.access_token}` },
  })
  expect(res.status).toBe(200)
  expect(await res.json()).toMatchObject({
    negotiateVersion: 1,
    availableTransports: [{ transport: 'WebSockets' }],
  })
  const anon = await SELF.fetch(`${BASE}/notifications/hub/negotiate`, { method: 'POST' })
  expect(anon.status).toBe(401)
})

it('registered users with no token get nothing from the anonymous hub', async () => {
  await registerUser('ws-anon0@example.com')
  expect((await connect(`${BASE}/notifications/anonymous-hub?Token=nope`)).res.status).toBe(404)
})

it('closes the sockets of other devices on logout, keeping the originating device', async () => {
  const s1 = await createSession('ws-close@example.com', { deviceIdentifier: 'dev-a' })
  const s2 = (await (
    await login('ws-close@example.com', 'client-derived-hash', { deviceIdentifier: 'dev-b' })
  ).json()) as { access_token: string }
  const a = await connect(hubUrl(s1.access_token))
  const b = await connect(hubUrl(s2.access_token))
  const closed = { a: false, b: false }
  a.ws?.addEventListener('close', () => {
    closed.a = true
  })
  b.ws?.addEventListener('close', () => {
    closed.b = true
  })
  for (const c of [a, b]) {
    c.ws?.send(`{"protocol":"json","version":1}${RS}`)
    await waitFor(() => c.inbox.shift())
  }
  const r = await authed('/api/accounts/security-stamp', s1.access_token, 'POST', {
    masterPasswordHash: 'client-derived-hash',
  })
  expect(r.status).toBe(200)
  await waitFor(() => (closed.b ? true : undefined))
  // Both were told to log out; only the other device was closed.
  expect(
    JSON.parse(((await waitFor(() => a.inbox.shift())) as string).slice(0, -1)).arguments[0].Type,
  ).toBe(11)
  expect(closed.a).toBe(false)
  a.ws?.close(1000)
})

it('ignores a client-supplied internal device header on the anonymous hub', async () => {
  const email = 'ws-hdr@example.com'
  await createSession(email)
  const created = (await (
    await json('/api/auth-requests/', {
      email,
      deviceIdentifier: 'nd',
      publicKey: 'p',
      type: 0,
      accessCode: 'c',
    })
  ).json()) as { id: string }
  const res = await SELF.fetch(`${BASE}/notifications/anonymous-hub?Token=${created.id}`, {
    headers: { Upgrade: 'websocket', 'X-Cw-Device': 'spoof', 'X-Cw-Expires-At': '99999999999999' },
  })
  expect(res.status).toBe(101)
  res.webSocket?.accept()
  const stub = env.NOTIFICATIONS.get(env.NOTIFICATIONS.idFromName(`anon:${created.id}`))
  const tags = await runInDurableObject(stub, (_i, state) =>
    state.getWebSockets().map((w) => state.getTags(w)),
  )
  expect(tags).toEqual([[]])
  const expiresAt = await runInDurableObject(stub, (_i, state) => state.storage.get('expiresAt'))
  expect(expiresAt as number).toBeLessThan(Date.now() + 16 * 60 * 1000)
  res.webSocket?.close(1000)
})

it('closes anonymous sockets once the request lifetime has passed', async () => {
  const email = 'ws-exp@example.com'
  await createSession(email)
  const created = (await (
    await json('/api/auth-requests/', {
      email,
      deviceIdentifier: 'nd',
      publicKey: 'p',
      type: 0,
      accessCode: 'c',
    })
  ).json()) as { id: string }
  const { ws } = await connect(`${BASE}/notifications/anonymous-hub?Token=${created.id}`)
  let closed = false
  ws?.addEventListener('close', () => {
    closed = true
  })
  const stub = env.NOTIFICATIONS.get(env.NOTIFICATIONS.idFromName(`anon:${created.id}`))
  await runInDurableObject(stub, (_i, state) => state.storage.put('expiresAt', Date.now() - 1))
  await runDurableObjectAlarm(stub)
  await waitFor(() => (closed ? true : undefined))
})

it('caps concurrent sockets per hub', async () => {
  const s = await createSession('ws-cap@example.com')
  const all = []
  for (let i = 0; i < 27; i++) all.push(await connect(hubUrl(s.access_token)))
  const id = await userUuid(s.access_token)
  const stub = env.NOTIFICATIONS.get(env.NOTIFICATIONS.idFromName(id))
  const open = await runInDurableObject(stub, (_i, state) => state.getWebSockets().length)
  expect(open).toBeLessThanOrEqual(25)
  for (const c of all) c.ws?.close(1000)
})
