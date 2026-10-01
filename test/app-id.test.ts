import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'

it('GET /app-id.json lists only the configured origin', async () => {
  const res = await SELF.fetch('https://vault.example.com/app-id.json')
  expect(res.status).toBe(200)
  expect(await res.json()).toEqual({
    trustedFacets: [{ version: { major: 1, minor: 0 }, ids: ['https://vault.example.com'] }],
  })
})
