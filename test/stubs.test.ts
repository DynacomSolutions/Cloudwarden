import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'

it('stubbed endpoints return 501', async () => {
  const res = await SELF.fetch('https://vault.example.com/api/sync')
  expect(res.status).toBe(501)
  expect(await res.json()).toEqual({ message: 'Not implemented' })
})
