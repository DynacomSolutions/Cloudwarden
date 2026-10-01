import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'

it('GET /api/config derives environment URLs from DOMAIN', async () => {
  const res = await SELF.fetch('https://vault.example.com/api/config')
  expect(res.status).toBe(200)
  const body = await res.json<Record<string, unknown>>()
  expect(body.object).toBe('config')
  expect(body.featureStates).toEqual({})
  expect(body.environment).toMatchObject({
    vault: 'https://vault.example.com',
    api: 'https://vault.example.com/api',
    identity: 'https://vault.example.com/identity',
  })
  expect(res.headers.get('Cache-Control')).toBe('no-store')
})
