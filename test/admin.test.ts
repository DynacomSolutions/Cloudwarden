import { SELF } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'
import { withEnv } from './helpers'

// The server-rendered admin was removed (TASKS #226): every /admin path is the standard 404 JSON,
// whether or not ADMIN_ENABLED is true, and never the vault's single-page fallback.
const PATHS = [
  '/admin',
  '/admin/',
  '/admin/users',
  '/admin/recovery',
  '/admin/recovery/magic?token=x',
]

const expectNotFound = async (res: Response) => {
  expect(res.status).toBe(404)
  expect(res.headers.get('content-type')).toContain('application/json')
  expect(await res.json()).toEqual({
    message: 'Not found',
    validationErrors: null,
    object: 'error',
  })
}

describe('removed /admin', () => {
  it.each(PATHS)('returns 404 JSON for GET %s when ADMIN_ENABLED is false', async (p) => {
    await expectNotFound(await SELF.fetch(`https://vault.example.com${p}`))
  })

  it.each(PATHS)('returns 404 JSON for GET %s when ADMIN_ENABLED is true', async (p) => {
    await expectNotFound(await withEnv({ ADMIN_ENABLED: 'true' }, p, {}))
  })

  it('returns 404 JSON for POST /admin/recovery/token', async () => {
    await expectNotFound(
      await withEnv({ ADMIN_ENABLED: 'true' }, '/admin/recovery/token', {
        method: 'POST',
        body: JSON.stringify({ token: 'x' }),
      }),
    )
  })
})
