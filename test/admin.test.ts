import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'

it('returns 404 for /admin when ADMIN_ENABLED is not true', async () => {
  const res = await SELF.fetch('https://vault.example.com/admin')
  expect(res.status).toBe(404)
  const res2 = await SELF.fetch('https://vault.example.com/admin/users')
  expect(res2.status).toBe(404)
})
