import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { signBlobToken } from '../src/vault/blobs'
import { authed, BASE, createSession } from './helpers'

const cipher = { type: 2, name: '2.note', secureNote: { type: 0 } }

const upload = (url: string, token: string, bytes: Uint8Array, name = '2.enc-name') => {
  const fd = new FormData()
  fd.append('data', new Blob([bytes]), name)
  return SELF.fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: fd,
  })
}

const setup = async (email: string) => {
  const s = await createSession(email)
  const c = (await (await authed('/api/ciphers', s.access_token, 'POST', cipher)).json()) as {
    id: string
  }
  return { token: s.access_token, cipherId: c.id }
}

const slot = async (token: string, cipherId: string, size: number) =>
  (await (
    await authed(`/api/ciphers/${cipherId}/attachment/v2`, token, 'POST', {
      fileName: '2.fname',
      key: '2.fkey',
      fileSize: size,
    })
  ).json()) as { attachmentId: string; url: string; fileUploadType: number; object: string }

it('round-trips an attachment through v2 upload and signed download', async () => {
  const { token, cipherId } = await setup('att1@example.com')
  const bytes = new Uint8Array(200_000).map((_, i) => i % 251)
  const s = await slot(token, cipherId, bytes.length)
  expect(s.fileUploadType).toBe(0)
  expect(s.object).toBe('attachment-fileUpload')
  expect(s.url).toBe(`${BASE}/api/ciphers/${cipherId}/attachment/${s.attachmentId}`)

  expect((await upload(s.url, token, bytes)).status).toBe(200)
  expect((await upload(s.url, token, bytes)).status).toBe(400)

  const meta = (await (
    await authed(`/api/ciphers/${cipherId}/attachment/${s.attachmentId}`, token)
  ).json()) as { url: string; size: string; fileName: string; key: string }
  expect(meta.size).toBe('200000')
  expect(meta.fileName).toBe('2.fname')
  const dl = await SELF.fetch(meta.url)
  expect(dl.status).toBe(200)
  expect(new Uint8Array(await dl.arrayBuffer())).toEqual(bytes)

  // Cipher response and sync carry the attachment.
  const got = (await (await authed(`/api/ciphers/${cipherId}`, token)).json()) as {
    attachments: { id: string }[]
  }
  expect(got.attachments.map((a) => a.id)).toEqual([s.attachmentId])
  const sync = (await (await authed('/api/sync', token)).json()) as {
    ciphers: { attachments: { id: string }[] }[]
  }
  expect(sync.ciphers[0]?.attachments[0]?.id).toBe(s.attachmentId)

  // Renew returns the same upload target.
  const renew = (await (
    await authed(`/api/ciphers/${cipherId}/attachment/${s.attachmentId}/renew`, token)
  ).json()) as { url: string }
  expect(renew.url).toBe(s.url)
})

it('rejects a size mismatch and keeps nothing', async () => {
  const { token, cipherId } = await setup('att2@example.com')
  const s = await slot(token, cipherId, 1000)
  const res = await upload(s.url, token, new Uint8Array(999))
  expect(res.status).toBe(400)
  expect(await env.ATTACHMENTS.head(`attachments/${cipherId}/${s.attachmentId}`)).toBeNull()
  const big = await authed(`/api/ciphers/${cipherId}/attachment/v2`, token, 'POST', {
    fileName: '2.f',
    key: '2.k',
    fileSize: 101 * 1024 * 1024,
  })
  expect(big.status).toBe(413)
})

it('rejects tampered and expired download tokens', async () => {
  const { token, cipherId } = await setup('att3@example.com')
  const s = await slot(token, cipherId, 5)
  await upload(s.url, token, new Uint8Array([1, 2, 3, 4, 5]))
  const meta = (await (
    await authed(`/api/ciphers/${cipherId}/attachment/${s.attachmentId}`, token)
  ).json()) as { url: string }
  const url = new URL(meta.url)
  const tok = url.searchParams.get('token') ?? ''
  expect((await SELF.fetch(`${url.origin}${url.pathname}`)).status).toBe(401)
  expect((await SELF.fetch(`${url.origin}${url.pathname}?token=${tok}x`)).status).toBe(401)
  // A token for another blob does not work here.
  const other = await signBlobToken(env, 'attachment', `${cipherId}/other`)
  expect((await SELF.fetch(`${url.origin}${url.pathname}?token=${other}`)).status).toBe(401)
  // Expired: advance the clock past the five minute lifetime.
  const realNow = Date.now
  Date.now = () => realNow() + 6 * 60 * 1000
  try {
    expect((await SELF.fetch(meta.url)).status).toBe(401)
  } finally {
    Date.now = realNow
  }
})

it('deletes attachments and their blobs, including with the cipher', async () => {
  const { token, cipherId } = await setup('att4@example.com')
  const a = await slot(token, cipherId, 3)
  await upload(a.url, token, new Uint8Array([1, 2, 3]))
  const del = await authed(
    `/api/ciphers/${cipherId}/attachment/${a.attachmentId}/delete`,
    token,
    'POST',
  )
  expect(del.status).toBe(200)
  expect(((await del.json()) as { cipher: { attachments: unknown } }).cipher.attachments).toBeNull()
  expect(await env.ATTACHMENTS.head(`attachments/${cipherId}/${a.attachmentId}`)).toBeNull()

  const b = await slot(token, cipherId, 3)
  await upload(b.url, token, new Uint8Array([1, 2, 3]))
  expect(await env.ATTACHMENTS.head(`attachments/${cipherId}/${b.attachmentId}`)).not.toBeNull()
  expect((await authed(`/api/ciphers/${cipherId}`, token, 'DELETE')).status).toBe(200)
  await new Promise((r) => setTimeout(r, 50))
  expect(await env.ATTACHMENTS.head(`attachments/${cipherId}/${b.attachmentId}`)).toBeNull()
})

it('accepts the legacy single step upload and isolates users', async () => {
  const { token, cipherId } = await setup('att5@example.com')
  const fd = new FormData()
  fd.append('key', '2.legacykey')
  fd.append('data', new Blob([new Uint8Array([9, 9])]), '2.legacyname')
  const res = await SELF.fetch(`${BASE}/api/ciphers/${cipherId}/attachment`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: fd,
  })
  expect(res.status).toBe(200)
  const body = (await res.json()) as { attachments: { fileName: string; size: string }[] }
  expect(body.attachments[0]).toMatchObject({ fileName: '2.legacyname', size: '2' })

  const other = await createSession('att6@example.com')
  const miss = await authed(`/api/ciphers/${cipherId}/attachment/v2`, other.access_token, 'POST', {
    fileName: '2.f',
    key: '2.k',
    fileSize: 1,
  })
  expect(miss.status).toBe(404)
})

it('rejects an oversize legacy upload before parsing and caps pending slots', async () => {
  const { token, cipherId } = await setup('att7@example.com')
  const res = await SELF.fetch(`${BASE}/api/ciphers/${cipherId}/attachment`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'multipart/form-data; boundary=x',
      'Content-Length': String(200 * 1024 * 1024),
    },
    body: '--x--',
  })
  expect(res.status).toBe(413)
  for (let i = 0; i < 10; i++) await slot(token, cipherId, 5)
  const over = await authed(`/api/ciphers/${cipherId}/attachment/v2`, token, 'POST', {
    fileName: '2.f',
    key: '2.k',
    fileSize: 5,
  })
  expect(over.status).toBe(400)
})

it('keeps the first upload when a second one races it', async () => {
  const { token, cipherId } = await setup('att8@example.com')
  const s = await slot(token, cipherId, 3)
  const { createDb, schema } = await import('../src/db')
  const { eq } = await import('drizzle-orm')
  // Simulate an upload in progress holding the claim.
  await createDb(env.DB)
    .update(schema.attachments)
    .set({ uploadStartedAt: Date.now() })
    .where(eq(schema.attachments.id, s.attachmentId))
  await env.ATTACHMENTS.put(`attachments/${cipherId}/${s.attachmentId}`, new Uint8Array([7, 7, 7]))
  const res = await upload(s.url, token, new Uint8Array([1]))
  expect(res.status).toBe(409)
  expect(await env.ATTACHMENTS.head(`attachments/${cipherId}/${s.attachmentId}`)).not.toBeNull()
})
