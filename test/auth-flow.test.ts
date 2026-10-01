import { expect, it } from 'vitest'
import { authed, form, json, login, registerUser } from './helpers'

it('register -> prelogin -> token -> refresh -> profile -> password change invalidates old token', async () => {
  const email = 'flow@example.com'
  expect((await registerUser(email)).status).toBe(200)

  const pre = await json('/identity/accounts/prelogin', { email })
  expect(await pre.json()).toMatchObject({ kdf: 0, kdfIterations: 600000 })

  const tokens = (await (await login(email)).json()) as any
  expect((await authed('/api/accounts/profile', tokens.access_token)).status).toBe(200)

  const refreshed = (await (
    await form('/identity/connect/token', {
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
    })
  ).json()) as any
  const profile = await authed('/api/accounts/profile', refreshed.access_token)
  expect(((await profile.json()) as any).email).toBe(email)

  const change = await authed('/api/accounts/password', refreshed.access_token, 'POST', {
    masterPasswordHash: 'client-derived-hash',
    newMasterPasswordHash: 'another-hash',
    key: '2.newKey',
  })
  expect(change.status).toBe(200)

  // Old access tokens, and the refresh token that produced them, no longer work.
  expect((await authed('/api/accounts/profile', tokens.access_token)).status).toBe(401)
  expect((await authed('/api/accounts/profile', refreshed.access_token)).status).toBe(401)
  const dead = await form('/identity/connect/token', {
    grant_type: 'refresh_token',
    refresh_token: refreshed.refresh_token,
  })
  expect(dead.status).toBe(400)

  const relog = (await (await login(email, 'another-hash')).json()) as any
  expect((await authed('/api/accounts/profile', relog.access_token)).status).toBe(200)
})
