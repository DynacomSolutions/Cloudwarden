import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'
import { toB64u, utf8 } from '../src/auth/crypto'
import { authed, BASE, createSession, form, login, registerUser } from './helpers'

const known = (email: string, id: string) =>
  SELF.fetch(`${BASE}/api/devices/knowndevice`, {
    headers: { 'X-Request-Email': toB64u(utf8(email)), 'X-Device-Identifier': id },
  })

it('registers a device on login and lists it', async () => {
  const s = await createSession('dl@example.com')
  const res = await authed('/api/devices', s.access_token)
  const body = (await res.json()) as any
  expect(body).toMatchObject({ object: 'list', continuationToken: null })
  expect(body.data).toHaveLength(1)
  expect(body.data[0]).toMatchObject({
    name: 'chrome',
    type: 9,
    identifier: 'device-1',
    object: 'device',
    isTrusted: false,
  })
})

it('re-login from the same device updates it instead of duplicating', async () => {
  const s = await createSession('dup2@example.com')
  await login('dup2@example.com')
  const body = (await (await authed('/api/devices', s.access_token)).json()) as any
  expect(body.data).toHaveLength(1)
})

it('same device identifier can belong to two users', async () => {
  await createSession('u1@example.com')
  await createSession('u2@example.com')
  expect(await (await known('u1@example.com', 'device-1')).json()).toBe(true)
  expect(await (await known('u2@example.com', 'device-1')).json()).toBe(true)
})

it('knowndevice answers without authentication', async () => {
  await createSession('kd@example.com')
  expect(await (await known('kd@example.com', 'device-1')).json()).toBe(true)
  expect(await (await known('kd@example.com', 'other')).json()).toBe(false)
  expect(await (await known('nobody@example.com', 'device-1')).json()).toBe(false)
  const missing = await SELF.fetch(`${BASE}/api/devices/knowndevice`)
  expect(missing.status).toBe(400)
})

it('requires auth for the list', async () => {
  expect((await SELF.fetch(`${BASE}/api/devices`)).status).toBe(401)
})

it('gets a device and stores a push token', async () => {
  const s = await createSession('tok@example.com')
  expect((await authed('/api/devices/identifier/device-1', s.access_token)).status).toBe(200)
  expect((await authed('/api/devices/identifier/nope', s.access_token)).status).toBe(404)
  const put = await authed('/api/devices/identifier/device-1/token', s.access_token, 'PUT', {
    pushToken: 'abc',
  })
  expect(put.status).toBe(204)
})

it('deactivating a device revokes its refresh token', async () => {
  const s = await createSession('deact@example.com')
  const body = (await (await authed('/api/devices', s.access_token)).json()) as any
  const id = body.data[0].id
  expect((await authed(`/api/devices/${id}`, s.access_token, 'DELETE')).status).toBe(200)
  expect(((await (await authed('/api/devices', s.access_token)).json()) as any).data).toHaveLength(
    0,
  )
  const res = await form('/identity/connect/token', {
    grant_type: 'refresh_token',
    refresh_token: s.refresh_token,
  })
  expect(res.status).toBe(400)
  expect(
    (
      await authed(
        '/api/devices/00000000-0000-4000-8000-000000000000/deactivate',
        s.access_token,
        'POST',
      )
    ).status,
  ).toBe(404)
})

it("cannot touch another user's device", async () => {
  await createSession('own1@example.com', { deviceIdentifier: 'secret-dev' })
  const other = await createSession('own2@example.com', { deviceIdentifier: 'mine' })
  expect((await authed('/api/devices/identifier/secret-dev', other.access_token)).status).toBe(404)
  await registerUser('noop@example.com')
})
