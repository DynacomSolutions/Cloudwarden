import { expect, it } from 'vitest'
import { call } from './sso-helpers'

it.each(['/.well-known/openid-configuration', '/.well-known/jwks.json'])(
  'serves %s as JSON at the root',
  async (path) => {
    const res = await call(path)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/json')
  },
)

it('points the root discovery document at the identity endpoints', async () => {
  const disc = (await (await call('/.well-known/openid-configuration')).json()) as any
  expect(disc.token_endpoint).toMatch(/\/identity\/connect\/token$/)
})
