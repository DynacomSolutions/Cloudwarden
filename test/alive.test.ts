import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'

it('GET /alive returns an ISO timestamp string', async () => {
  const res = await SELF.fetch('https://vault.example.com/alive')
  expect(res.status).toBe(200)
  const body = await res.json<string>()
  expect(new Date(body).toISOString()).toBe(body)
  expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff')
})
