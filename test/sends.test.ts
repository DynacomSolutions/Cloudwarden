import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { purgeExpired } from '../src/vault/purge'
import { authed, BASE, createSession, form, json } from './helpers'

const day = 86_400_000
const textSend = (extra: Record<string, unknown> = {}) => ({
  type: 0,
  name: '2.sendname',
  notes: '2.notes',
  key: '2.sendkey',
  text: { text: '2.secret', hidden: false },
  deletionDate: new Date(Date.now() + day).toISOString(),
  disabled: false,
  ...extra,
})

interface SendOut {
  id: string
  accessId: string
  accessCount: number
  password: string | null
  [k: string]: unknown
}

const create = async (token: string, body: unknown) => {
  const res = await authed('/api/sends', token, 'POST', body)
  expect(res.status).toBe(200)
  return (await res.json()) as SendOut
}

it('manages text Sends and includes them in sync', async () => {
  const s = await createSession('send1@example.com')
  const made = await create(s.access_token, textSend())
  expect(made).toMatchObject({ object: 'send', type: 0, authType: 2, text: { text: '2.secret' } })
  expect(made.accessId).toBeTruthy()

  const upd = await authed(
    `/api/sends/${made.id}`,
    s.access_token,
    'PUT',
    textSend({ name: '2.renamed' }),
  )
  expect(((await upd.json()) as { name: string }).name).toBe('2.renamed')
  const list = (await (await authed('/api/sends', s.access_token)).json()) as { data: unknown[] }
  expect(list.data).toHaveLength(1)
  const sync = (await (await authed('/api/sync', s.access_token)).json()) as {
    sends: { id: string }[]
  }
  expect(sync.sends.map((x) => x.id)).toEqual([made.id])

  expect((await authed(`/api/sends/${made.id}`, s.access_token, 'DELETE')).status).toBe(200)
  expect((await authed(`/api/sends/${made.id}`, s.access_token)).status).toBe(404)
  const far = await authed(
    '/api/sends',
    s.access_token,
    'POST',
    textSend({ deletionDate: new Date(Date.now() + 40 * day).toISOString() }),
  )
  expect(far.status).toBe(400)
})

it('enforces password and max access count on legacy access', async () => {
  const s = await createSession('send2@example.com')
  const made = await create(s.access_token, textSend({ password: 'aGFzaA==', maxAccessCount: 2 }))
  expect(made).toMatchObject({ authType: 1 })
  const access = (body?: unknown) => json(`/api/sends/access/${made.accessId}`, body ?? {})

  expect((await access()).status).toBe(401)
  expect((await access({ password: 'wrong' })).status).toBe(400)
  const ok = await access({ password: 'aGFzaA==' })
  expect(ok.status).toBe(200)
  expect(await ok.json()).toMatchObject({
    object: 'send-access',
    type: 0,
    text: { text: '2.secret' },
    creatorIdentifier: 'send2@example.com',
  })
  expect((await access({ password: 'aGFzaA==' })).status).toBe(200)
  expect((await access({ password: 'aGFzaA==' })).status).toBe(404)
  const owner = (await (await authed(`/api/sends/${made.id}`, s.access_token)).json()) as SendOut
  expect(owner.accessCount).toBe(2)

  const rm = await authed(`/api/sends/${made.id}/remove-password`, s.access_token, 'PUT')
  expect(((await rm.json()) as SendOut).password).toBeNull()
})

it('rejects disabled, expired and deleted Sends', async () => {
  const s = await createSession('send3@example.com')
  const disabled = await create(s.access_token, textSend({ disabled: true }))
  expect((await json(`/api/sends/access/${disabled.accessId}`, {})).status).toBe(404)
  const expired = await create(
    s.access_token,
    textSend({ expirationDate: new Date(Date.now() - 1000).toISOString() }),
  )
  expect((await json(`/api/sends/access/${expired.accessId}`, {})).status).toBe(404)
  expect((await json('/api/sends/access/not-a-send', {})).status).toBe(404)
})

it('supports the send_access token flow', async () => {
  const s = await createSession('send4@example.com')
  const made = await create(s.access_token, textSend({ password: 'aGFzaA==' }))
  const grant = (extra: Record<string, string>) =>
    form('/identity/connect/token', {
      grant_type: 'send_access',
      client_id: 'send',
      send_id: made.accessId,
      ...extra,
    })
  const missing = await grant({})
  expect(missing.status).toBe(400)
  expect(((await missing.json()) as { error_description: string }).error_description).toBe(
    'password_hash_b64_required',
  )
  expect((await grant({ password_hash_b64: 'nope' })).status).toBe(400)
  const ok = (await (await grant({ password_hash_b64: 'aGFzaA==' })).json()) as {
    access_token: string
  }
  const res = await SELF.fetch(`${BASE}/api/sends/access`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${ok.access_token}` },
  })
  expect(res.status).toBe(200)
  expect(((await res.json()) as { text: { text: string } }).text.text).toBe('2.secret')
  // A user access token is not a send token.
  const bad = await SELF.fetch(`${BASE}/api/sends/access`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${s.access_token}` },
  })
  expect(bad.status).toBe(401)
})

const fileSend = (size: number, extra: Record<string, unknown> = {}) => ({
  type: 1,
  name: '2.fname',
  key: '2.sendkey',
  file: { fileName: '2.file.txt' },
  fileLength: size,
  deletionDate: new Date(Date.now() + day).toISOString(),
  ...extra,
})

it('round-trips a file Send', async () => {
  const s = await createSession('send5@example.com')
  const res = await authed(
    '/api/sends/file/v2',
    s.access_token,
    'POST',
    fileSend(6, { maxAccessCount: 1 }),
  )
  const slot = (await res.json()) as {
    url: string
    fileUploadType: number
    object: string
    sendResponse: SendOut & { file: { id: string } }
  }
  expect(slot).toMatchObject({ fileUploadType: 0, object: 'send-fileUpload' })
  const fileId = slot.sendResponse.file.id
  expect(slot.url).toBe(`${BASE}/api/sends/${slot.sendResponse.id}/file/${fileId}`)

  // Not accessible before the upload completes.
  expect(
    (await json(`/api/sends/${slot.sendResponse.accessId}/access/file/${fileId}`, {})).status,
  ).toBe(404)

  const fd = new FormData()
  fd.append('data', new Blob([new Uint8Array([1, 2, 3, 4, 5, 6])]), '2.file.txt')
  const up = await SELF.fetch(slot.url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${s.access_token}` },
    body: fd,
  })
  expect(up.status).toBe(200)

  const dl = await json(`/api/sends/${slot.sendResponse.accessId}/access/file/${fileId}`, {})
  expect(dl.status).toBe(200)
  const { url } = (await dl.json()) as { url: string }
  const file = await SELF.fetch(url)
  expect(new Uint8Array(await file.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]))
  // maxAccessCount 1: the second download request is refused.
  expect(
    (await json(`/api/sends/${slot.sendResponse.accessId}/access/file/${fileId}`, {})).status,
  ).toBe(404)
  expect((await SELF.fetch(`${url}x`)).status).toBe(401)

  // Deleting the Send removes the blob.
  await authed(`/api/sends/${slot.sendResponse.id}`, s.access_token, 'DELETE')
  await new Promise((r) => setTimeout(r, 50))
  expect(await env.ATTACHMENTS.head(`sends/${slot.sendResponse.id}/${fileId}`)).toBeNull()
})

it('purges expired Sends, abandoned uploads and orphaned blobs', async () => {
  const s = await createSession('send6@example.com')
  const gone = await create(s.access_token, textSend())
  const keep = await create(s.access_token, textSend())
  const withFile = (await (
    await authed('/api/sends/file/v2', s.access_token, 'POST', fileSend(3))
  ).json()) as { url: string; sendResponse: SendOut & { file: { id: string } } }
  const fd = new FormData()
  fd.append('data', new Blob([new Uint8Array([1, 2, 3])]), 'f')
  await SELF.fetch(withFile.url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${s.access_token}` },
    body: fd,
  })
  const fileKey = `sends/${withFile.sendResponse.id}/${withFile.sendResponse.file.id}`
  await env.ATTACHMENTS.put('attachments/orphan/blob', new Uint8Array([1]))

  const future = Date.now() + 2 * day
  const r1 = await purgeExpired(env, future)
  expect(r1.sends).toBeGreaterThanOrEqual(3)
  expect(await env.ATTACHMENTS.head(fileKey)).toBeNull()
  expect(await env.ATTACHMENTS.head('attachments/orphan/blob')).toBeNull()
  const list = (await (await authed('/api/sends', s.access_token)).json()) as { data: unknown[] }
  expect(list.data).toHaveLength(0)
  expect(gone.id).not.toBe(keep.id)

  // Nothing is deleted when nothing is due.
  const fresh = await create(s.access_token, textSend())
  const r2 = await purgeExpired(env)
  expect(r2.sends).toBe(0)
  expect((await authed(`/api/sends/${fresh.id}`, s.access_token)).status).toBe(200)
})

it('removes Send and attachment blobs when the vault is purged', async () => {
  const s = await createSession('send7@example.com')
  const slot = (await (
    await authed('/api/sends/file/v2', s.access_token, 'POST', fileSend(3))
  ).json()) as {
    url: string
    sendResponse: SendOut & { file: { id: string } }
  }
  const fd = new FormData()
  fd.append('data', new Blob([new Uint8Array([1, 2, 3])]), 'f')
  await SELF.fetch(slot.url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${s.access_token}` },
    body: fd,
  })
  const key = `sends/${slot.sendResponse.id}/${slot.sendResponse.file.id}`
  expect(await env.ATTACHMENTS.head(key)).not.toBeNull()
  const res = await authed('/api/ciphers/purge', s.access_token, 'POST', {
    masterPasswordHash: 'client-derived-hash',
  })
  expect(res.status).toBe(200)
  await new Promise((r) => setTimeout(r, 50))
  expect(await env.ATTACHMENTS.head(key)).toBeNull()
})

it('revokes send_access tokens when the Send changes and re-checks download links', async () => {
  const s = await createSession('send8@example.com')
  const made = await create(s.access_token, textSend({ password: 'aGFzaA==' }))
  const grant = await form('/identity/connect/token', {
    grant_type: 'send_access',
    client_id: 'send',
    send_id: made.accessId,
    password_hash_b64: 'aGFzaA==',
  })
  const { access_token } = (await grant.json()) as { access_token: string }
  const call = () =>
    SELF.fetch(`${BASE}/api/sends/access`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${access_token}` },
    })
  await authed(`/api/sends/${made.id}/remove-password`, s.access_token, 'PUT')
  expect((await call()).status).toBe(401)

  const slot = (await (
    await authed('/api/sends/file/v2', s.access_token, 'POST', fileSend(3))
  ).json()) as {
    url: string
    sendResponse: SendOut & { file: { id: string } }
  }
  const fd = new FormData()
  fd.append('data', new Blob([new Uint8Array([1, 2, 3])]), 'f')
  await SELF.fetch(slot.url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${s.access_token}` },
    body: fd,
  })
  const dl = (await (
    await json(
      `/api/sends/${slot.sendResponse.accessId}/access/file/${slot.sendResponse.file.id}`,
      {},
    )
  ).json()) as { url: string }
  await authed(
    `/api/sends/${slot.sendResponse.id}`,
    s.access_token,
    'PUT',
    fileSend(3, { disabled: true, file: { fileName: '2.file.txt' } }),
  )
  expect((await SELF.fetch(dl.url)).status).toBe(404)
})

it('never lists or deletes keys outside attachments/ and sends/', async () => {
  await env.ATTACHMENTS.put('backups/db-1.sql', new Uint8Array([1]))
  await env.ATTACHMENTS.put('attachments/zz/orphan', new Uint8Array([1]))
  const future = Date.now() + 2 * day
  for (let i = 0; i < 4; i++) await purgeExpired(env, future)
  expect(await env.ATTACHMENTS.head('backups/db-1.sql')).not.toBeNull()
  expect(await env.ATTACHMENTS.head('attachments/zz/orphan')).toBeNull()
})
