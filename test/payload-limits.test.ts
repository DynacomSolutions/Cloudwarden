// Size caps on cipher, folder, Send and import payloads (TASKS #408).
import { expect, it } from 'vitest'
import { MAX_CIPHER_NOTES, MAX_ENC_NAME, MAX_IMPORT_BODY } from '../src/limits'
import { authed, createSession } from './helpers'

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
  await refused('/api/ciphers', cipher({ secureNote: { blob: 'x'.repeat(200_000) } }))
  await refused('/api/folders', { name: 'x'.repeat(MAX_ENC_NAME + 1) })
  await refused('/api/sends', send({ notes: 'x'.repeat(1001) }))
  await refused('/api/sends', send({ text: { text: 'x'.repeat(10_001) } }))
  await refused('/api/ciphers/import', { ciphers: [cipher({ notes: bigNotes })] })
  await refused('/api/ciphers/import', {
    ciphers: [cipher({ notes: 'x'.repeat(MAX_IMPORT_BODY) })],
  })
})
