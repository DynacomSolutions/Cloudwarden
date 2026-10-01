import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'
import { decode } from '../src/notifications/msgpack'
import { unframe } from '../src/notifications/signalr'
import { authed, BASE, createSession, form, json } from './helpers'

const RS = '\x1e'

const create = (email: string, deviceIdentifier: string, accessCode = 'code-1') =>
  json('/api/auth-requests/', {
    email,
    deviceIdentifier,
    publicKey: 'pub',
    type: 0,
    accessCode,
  })

async function waitFor<T>(fn: () => T | undefined, ms = 3000): Promise<T> {
  const end = Date.now() + ms
  for (;;) {
    const v = fn()
    if (v !== undefined) return v
    if (Date.now() > end) throw new Error('timed out')
    await new Promise((r) => setTimeout(r, 10))
  }
}

it('runs login with device end to end', async () => {
  const email = 'ar-flow@example.com'
  const s = await createSession(email)

  // The approving device listens on its user hub.
  const userRes = await SELF.fetch(`${BASE}/notifications/hub?access_token=${s.access_token}`, {
    headers: { Upgrade: 'websocket' },
  })
  const userWs = userRes.webSocket as WebSocket
  const userInbox: string[] = []
  userWs.addEventListener('message', (e) => {
    userInbox.push(e.data as string)
  })
  userWs.accept()
  userWs.send(`{"protocol":"json","version":1}${RS}`)
  await waitFor(() => userInbox.shift())

  // The new device creates a request.
  const createRes = await create(email, 'new-device')
  expect(createRes.status).toBe(200)
  const created = (await createRes.json()) as { id: string; requestApproved: unknown }
  expect(created.requestApproved).toBeNull()
  const ping = JSON.parse(((await waitFor(() => userInbox.shift())) as string).slice(0, -1))
  expect(ping.arguments[0]).toMatchObject({ Type: 15, Payload: { Id: created.id } })

  // The new device waits on the anonymous hub using the msgpack protocol.
  const anonRes = await SELF.fetch(`${BASE}/notifications/anonymous-hub?Token=${created.id}`, {
    headers: { Upgrade: 'websocket' },
  })
  expect(anonRes.status).toBe(101)
  const anonWs = anonRes.webSocket as WebSocket
  anonWs.binaryType = 'arraybuffer'
  const anonInbox: (string | ArrayBuffer)[] = []
  anonWs.addEventListener('message', (e) => {
    anonInbox.push(e.data as string | ArrayBuffer)
  })
  anonWs.accept()
  anonWs.send(`{"protocol":"messagepack","version":1}${RS}`)
  await waitFor(() => anonInbox.shift())

  // Pending list and detail for the approver.
  const pending = (await (await authed('/api/auth-requests/pending', s.access_token)).json()) as {
    data: { id: string }[]
  }
  expect(pending.data.map((r) => r.id)).toEqual([created.id])
  expect((await authed(`/api/auth-requests/${created.id}`, s.access_token)).status).toBe(200)

  // Not approved yet: the new device cannot log in with it.
  const early = await form('/identity/connect/token', {
    grant_type: 'password',
    username: email,
    password: 'code-1',
    authRequest: created.id,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceName: 'new',
    deviceIdentifier: 'new-device',
  })
  expect(early.status).toBe(400)

  // Approve.
  const put = await authed(`/api/auth-requests/${created.id}`, s.access_token, 'PUT', {
    key: 'encrypted-user-key',
    masterPasswordHash: 'h',
    deviceIdentifier: 'device-1',
    requestApproved: true,
  })
  expect(put.status).toBe(200)

  const frameData = (await waitFor(() => anonInbox.shift())) as ArrayBuffer
  const [payload] = unframe(new Uint8Array(frameData))
  const msg = decode(payload as Uint8Array) as unknown[]
  expect(msg[3]).toBe('AuthRequestResponseRecieved')
  expect(msg[4]).toMatchObject([{ Type: 16, Payload: { Id: created.id } }])

  // Poll with the access code.
  const poll = await SELF.fetch(`${BASE}/api/auth-requests/${created.id}/response?code=code-1`)
  expect(await poll.json()).toMatchObject({ requestApproved: true, key: 'encrypted-user-key' })
  const wrong = await SELF.fetch(`${BASE}/api/auth-requests/${created.id}/response?code=nope`)
  expect(wrong.status).toBe(404)

  // A second answer is refused.
  const again = await authed(`/api/auth-requests/${created.id}`, s.access_token, 'PUT', {
    key: 'k',
    deviceIdentifier: 'device-1',
    requestApproved: false,
  })
  expect(again.status).toBe(400)

  // Log in with the approved request: wrong device and wrong code fail, then success once.
  const grant = (over: Record<string, string>) =>
    form('/identity/connect/token', {
      grant_type: 'password',
      username: email,
      password: 'code-1',
      authRequest: created.id,
      scope: 'api offline_access',
      client_id: 'web',
      deviceType: '9',
      deviceName: 'new',
      deviceIdentifier: 'new-device',
      ...over,
    })
  expect((await grant({ deviceIdentifier: 'other' })).status).toBe(400)
  expect((await grant({ password: 'wrong' })).status).toBe(400)
  const ok = await grant({})
  expect(ok.status).toBe(200)
  expect(await ok.json()).toMatchObject({ token_type: 'Bearer' })
  expect((await grant({})).status).toBe(400)

  userWs.close(1000)
  anonWs.close(1000)
})

it('hides whether an email exists', async () => {
  await createSession('ar-real@example.com')
  const look = async (email: string) => {
    const res = await create(email, 'd', 'secret-code')
    expect(res.status).toBe(200)
    const body = (await res.json()) as { id: string }
    const poll = await SELF.fetch(`${BASE}/api/auth-requests/${body.id}/response?code=secret-code`)
    const bad = await SELF.fetch(`${BASE}/api/auth-requests/${body.id}/response?code=wrong`)
    const hub = await SELF.fetch(`${BASE}/notifications/anonymous-hub?Token=${body.id}`, {
      headers: { Upgrade: 'websocket' },
    })
    hub.webSocket?.accept()
    hub.webSocket?.close(1000)
    return [Object.keys(body).sort(), poll.status, bad.status, hub.status]
  }
  expect(await look('ar-nobody@example.com')).toEqual(await look('ar-real@example.com'))
})

it('stops serving the key once the request is redeemed', async () => {
  const email = 'ar-redact@example.com'
  const s = await createSession(email)
  const created = (await (await create(email, 'nd')).json()) as { id: string }
  await authed(`/api/auth-requests/${created.id}`, s.access_token, 'PUT', {
    key: 'wrapped',
    masterPasswordHash: 'h',
    deviceIdentifier: 'device-1',
    requestApproved: true,
  })
  const poll = () =>
    SELF.fetch(`${BASE}/api/auth-requests/${created.id}/response?code=code-1`).then((r) => r.json())
  expect(await poll()).toMatchObject({ key: 'wrapped' })
  const ok = await form('/identity/connect/token', {
    grant_type: 'password',
    username: email,
    password: 'code-1',
    authRequest: created.id,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceName: 'n',
    deviceIdentifier: 'nd',
  })
  expect(ok.status).toBe(200)
  expect(await poll()).toMatchObject({ key: null, masterPasswordHash: null })
})

it('refuses to redeem an unlock-only (type 1) request for tokens', async () => {
  const email = 'ar-type1@example.com'
  const s = await createSession(email)
  const res = await json('/api/auth-requests/', {
    email,
    deviceIdentifier: 'nd',
    publicKey: 'p',
    type: 1,
    accessCode: 'code-1',
  })
  const created = (await res.json()) as { id: string }
  await authed(`/api/auth-requests/${created.id}`, s.access_token, 'PUT', {
    key: 'wrapped',
    deviceIdentifier: 'device-1',
    requestApproved: true,
  })
  const grant = await form('/identity/connect/token', {
    grant_type: 'password',
    username: email,
    password: 'code-1',
    authRequest: created.id,
    scope: 'api offline_access',
    client_id: 'web',
    deviceType: '9',
    deviceName: 'n',
    deviceIdentifier: 'nd',
  })
  expect(grant.status).toBe(400)
})

it('rejects unsupported types and protects the authenticated endpoints', async () => {
  const s = await createSession('ar-guard@example.com')
  const admin = await json('/api/auth-requests/', {
    email: 'ar-guard@example.com',
    deviceIdentifier: 'd',
    publicKey: 'p',
    type: 2,
    accessCode: 'c',
  })
  expect(admin.status).toBe(400)
  expect((await SELF.fetch(`${BASE}/api/auth-requests/pending`)).status).toBe(401)
  const other = await createSession('ar-other@example.com')
  const created = (await (await create('ar-guard@example.com', 'x')).json()) as { id: string }
  expect((await authed(`/api/auth-requests/${created.id}`, other.access_token)).status).toBe(404)
  expect(
    (
      await authed(`/api/auth-requests/${created.id}`, other.access_token, 'PUT', {
        deviceIdentifier: 'd',
        requestApproved: false,
      })
    ).status,
  ).toBe(404)
  const denied = await authed(`/api/auth-requests/${created.id}`, s.access_token, 'PUT', {
    deviceIdentifier: 'device-1',
    requestApproved: false,
  })
  expect(await denied.json()).toMatchObject({ requestApproved: false, key: null })
})
