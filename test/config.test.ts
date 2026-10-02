import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { app } from '../src/index'

it('GET /api/config returns the shape current clients expect', async () => {
  const res = await SELF.fetch('https://vault.example.com/api/config')
  expect(res.status).toBe(200)
  const body = await res.json<Record<string, unknown>>()
  expect(body.object).toBe('config')
  expect(body.version).toMatch(/^2026\.\d+\.\d+$/)
  expect(typeof body.gitHash).toBe('string')
  expect(body.server).toEqual({ name: 'Cloudwarden', url: 'https://vault.example.com' })
  expect(body.featureStates).toEqual({})
  expect(body.push).toEqual({ pushTechnology: 0 })
  expect(body.environment).toEqual({
    cloudRegion: null,
    vault: 'https://vault.example.com',
    api: 'https://vault.example.com/api',
    identity: 'https://vault.example.com/identity',
    notifications: 'https://vault.example.com/notifications',
    sso: 'https://vault.example.com/sso',
  })
  expect(res.headers.get('Cache-Control')).toBe('no-store')
})

it('reflects SIGNUPS_ALLOWED in settings.disableUserRegistration', async () => {
  const off = await app.request('/api/config', {}, { ...env, SIGNUPS_ALLOWED: 'false' })
  expect(
    (await off.json<{ settings: { disableUserRegistration: boolean } }>()).settings
      .disableUserRegistration,
  ).toBe(true)
  const on = await app.request('/api/config', {}, { ...env, SIGNUPS_ALLOWED: 'true' })
  expect(
    (await on.json<{ settings: { disableUserRegistration: boolean } }>()).settings
      .disableUserRegistration,
  ).toBe(false)
})

it('trims a trailing slash on DOMAIN', async () => {
  const res = await app.request('/api/config', {}, { ...env, DOMAIN: 'https://vault.example.com/' })
  const body = await res.json<{ environment: { api: string } }>()
  expect(body.environment.api).toBe('https://vault.example.com/api')
})
