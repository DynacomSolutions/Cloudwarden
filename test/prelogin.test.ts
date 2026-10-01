import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'

const post = (path: string, body: unknown) =>
  SELF.fetch(`https://vault.example.com${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

it.each(['/api/accounts/prelogin', '/identity/accounts/prelogin'])(
  'POST %s returns default KDF',
  async (path) => {
    const res = await post(path, { email: 'user@example.com' })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ kdf: 0, kdfIterations: 600000 })
  },
)

it('rejects an invalid body', async () => {
  const res = await post('/api/accounts/prelogin', { email: 'nope' })
  expect(res.status).toBe(400)
  expect(await res.json()).toMatchObject({ object: 'error' })
})
