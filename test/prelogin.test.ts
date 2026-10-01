import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'
import { json, registerUser } from './helpers'

const post = (path: string, body: unknown) =>
  SELF.fetch(`https://vault.example.com${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

const DEFAULT = { kdf: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null }

it.each(['/api/accounts/prelogin', '/identity/accounts/prelogin'])(
  'POST %s returns default KDF for unknown emails',
  async (path) => {
    const res = await post(path, { email: 'nobody@example.com' })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual(DEFAULT)
  },
)

it('returns the stored PBKDF2 settings', async () => {
  await registerUser('pbkdf@example.com', { kdfIterations: 123456 })
  const res = await post('/identity/accounts/prelogin', { email: 'PBKDF@example.com' })
  expect(await res.json()).toEqual({
    kdf: 0,
    kdfIterations: 123456,
    kdfMemory: null,
    kdfParallelism: null,
  })
})

it('returns the stored Argon2id settings', async () => {
  const reg = await registerUser('argon@example.com', {
    kdf: 1,
    kdfIterations: 3,
    kdfMemory: 64,
    kdfParallelism: 4,
  })
  expect(reg.status).toBe(200)
  const res = await json('/api/accounts/prelogin', { email: 'argon@example.com' })
  expect(await res.json()).toEqual({ kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 })
})

it('rejects an invalid body', async () => {
  const res = await post('/api/accounts/prelogin', { email: 'nope' })
  expect(res.status).toBe(400)
  expect(await res.json()).toMatchObject({ object: 'error' })
})
