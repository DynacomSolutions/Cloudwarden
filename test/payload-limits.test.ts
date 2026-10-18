// Size caps on cipher, folder, Send and import payloads (TASKS #408).

import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'
import { MAX_CIPHER_NOTES, MAX_ENC_NAME } from '../src/limits'
import { authed, BASE, createSession } from './helpers'

const cipher = (extra: Record<string, unknown> = {}) => ({
  type: 2,
  name: '2.name',
  notes: '2.notes',
  secureNote: { type: 0 },
  ...extra,
})
const send = (extra: Record<string, unknown> = {}) => ({
  type: 0,
  name: '2.sendname',
  key: '2.sendkey',
  text: { text: '2.secret', hidden: false },
  deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
  ...extra,
})

it('accepts normal payloads and refuses oversized ones with the usual error', async () => {
  const s = await createSession('limits@example.com')
  const post = (path: string, body: unknown) => authed(path, s.access_token, 'POST', body)

  expect((await post('/api/ciphers', cipher())).status).toBe(200)
  expect((await post('/api/ciphers', cipher({ notes: 'x'.repeat(MAX_CIPHER_NOTES) }))).status).toBe(
    200,
  )
  expect((await post('/api/folders', { name: '2.folder' })).status).toBe(200)
  expect((await post('/api/sends', send())).status).toBe(200)
  expect(
    (await post('/api/ciphers/import', { ciphers: [cipher()], folders: [{ name: '2.f' }] })).status,
  ).toBe(200)

  const refused = async (path: string, body: unknown) => {
    const res = await post(path, body)
    expect(res.status).toBe(400)
    const out = (await res.json()) as Record<string, unknown>
    expect(out).toMatchObject({ message: expect.any(String) })
    return out
  }
  const bigNotes = 'x'.repeat(MAX_CIPHER_NOTES + 1)
  expect(await refused('/api/ciphers', cipher({ notes: bigNotes }))).toMatchObject({
    message: 'The request is invalid.',
    validationErrors: { notes: expect.any(Array) },
  })
  await refused('/api/ciphers', cipher({ name: 'x'.repeat(MAX_ENC_NAME + 1) }))
  await refused('/api/ciphers', cipher({ secureNote: { blob: 'x'.repeat(300_000) } }))
  await refused('/api/folders', { name: 'x'.repeat(MAX_ENC_NAME + 1) })
  await refused('/api/sends', send({ notes: 'x'.repeat(1001) }))
  await refused('/api/sends', send({ text: { text: 'x'.repeat(10_001) } }))
  await refused('/api/ciphers/import', { ciphers: [cipher({ notes: bigNotes })] })
  // Many small valid ciphers that together pass the body cap: refused before parsing.
  const many = Array.from({ length: 2600 }, () => cipher({ notes: 'x'.repeat(MAX_CIPHER_NOTES) }))
  expect(await refused('/api/ciphers/import', { ciphers: many })).toMatchObject({
    message: 'You cannot import this much data at once.',
  })
  // Fields are capped per value, not per list: 25 fields of 5000 characters pass.
  const field = (value: string) => ({ name: '2.f', value, type: 0 })
  const fields = Array.from({ length: 25 }, () => field('x'.repeat(5000)))
  expect((await post('/api/ciphers', cipher({ fields }))).status).toBe(200)
  await refused('/api/ciphers', cipher({ fields: [field('x'.repeat(5001))] }))
  // Key rotation applies the same caps.
  const rotated = await post('/api/accounts/key', {
    masterPasswordHash: 'client-derived-hash',
    key: '2.newkey',
    privateKey: '2.newpk',
    folders: [],
    sends: [],
    ciphers: [{ id: crypto.randomUUID(), name: '2.n', notes: bigNotes }],
  })
  expect(rotated.status).toBe(400)
})

it('caps a chunked import body (no Content-Length) before reading it', async () => {
  const s = await createSession('limits-chunked@example.com')
  const streamed = (body: unknown) => {
    const bytes = new TextEncoder().encode(JSON.stringify(body))
    const stream = new ReadableStream({
      start(ctrl) {
        for (let i = 0; i < bytes.length; i += 65_536) ctrl.enqueue(bytes.slice(i, i + 65_536))
        ctrl.close()
      },
    })
    return SELF.fetch(`${BASE}/api/ciphers/import`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${s.access_token}`, 'Content-Type': 'application/json' },
      body: stream,
      duplex: 'half',
    } as RequestInit)
  }
  expect((await streamed({ ciphers: [cipher()] })).status).toBe(200)
  const many = Array.from({ length: 2600 }, () => cipher({ notes: 'x'.repeat(MAX_CIPHER_NOTES) }))
  const res = await streamed({ ciphers: many })
  expect(res.status).toBe(400)
  expect(await res.json()).toMatchObject({ message: 'You cannot import this much data at once.' })
})
