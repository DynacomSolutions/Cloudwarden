import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { verifyJwt } from '../src/auth/jwt'
import { authed, createSession, form, login, registerUser } from './helpers'

it('password grant returns the client-expected shape', async () => {
  await registerUser('shape@example.com')
  const res = await login('Shape@Example.com')
  expect(res.status).toBe(200)
  const body = (await res.json()) as Record<string, any>
  expect(body).toMatchObject({
    expires_in: 3600,
    token_type: 'Bearer',
    scope: 'api offline_access',
    Key: '2.encryptedSymmetricKey',
    PrivateKey: '2.pk',
    Kdf: 0,
    KdfIterations: 600000,
    KdfMemory: null,
    KdfParallelism: null,
    ResetMasterPassword: false,
    ForcePasswordReset: false,
    UserDecryptionOptions: { HasMasterPassword: true, Object: 'userDecryptionOptions' },
    MasterPasswordPolicy: { Object: 'masterPasswordPolicy' },
  })
  expect(typeof body.refresh_token).toBe('string')
})

it('issues JWTs with the documented claims', async () => {
  const s = await createSession('claims@example.com')
  const claims = await verifyJwt<any>(s.access_token, [env.JWT_SECRET as string])
  expect(claims).toMatchObject({
    iss: 'https://vault.example.com',
    email: 'claims@example.com',
    name: 'Test User',
    premium: true,
    email_verified: true,
    device: 'device-1',
    scope: ['api', 'offline_access'],
    amr: ['Application'],
  })
  expect(claims.exp - claims.nbf).toBe(3600)
  expect(typeof claims.sstamp).toBe('string')
})

it('rejects a wrong password and an unknown user identically', async () => {
  await registerUser('wrong@example.com')
  const bad = await login('wrong@example.com', 'nope')
  const unknown = await login('ghost@example.com')
  expect(bad.status).toBe(400)
  expect(unknown.status).toBe(400)
  const a = (await bad.json()) as any
  expect(a).toMatchObject({ error: 'invalid_grant', ErrorModel: { Object: 'error' } })
  expect(a.ErrorModel.Message).toBeTruthy()
  expect(await unknown.json()).toEqual(a)
})

it('rejects disabled accounts', async () => {
  await registerUser('off@example.com')
  await env.DB.prepare('update users set enabled = 0 where email = ?').bind('off@example.com').run()
  const res = await login('off@example.com')
  expect(res.status).toBe(400)
  expect(((await res.json()) as any).error).toBe('invalid_grant')
})

it('requires device information and a known grant type', async () => {
  await registerUser('dev@example.com')
  const noDevice = await form('/identity/connect/token', {
    grant_type: 'password',
    username: 'dev@example.com',
    password: 'client-derived-hash',
  })
  expect(noDevice.status).toBe(400)
  const unknown = await form('/identity/connect/token', { grant_type: 'magic' })
  expect(unknown.status).toBe(400)
  expect(((await unknown.json()) as any).error).toBe('unsupported_grant_type')
})

it('refresh grant rotates the refresh token and rejects replays', async () => {
  const s = await createSession('refresh@example.com')
  const res = await form('/identity/connect/token', {
    grant_type: 'refresh_token',
    refresh_token: s.refresh_token,
    client_id: 'web',
  })
  expect(res.status).toBe(200)
  const next = (await res.json()) as any
  expect(next.refresh_token).not.toBe(s.refresh_token)
  expect(next.Key).toBe('2.encryptedSymmetricKey')
  expect((await authed('/api/accounts/profile', next.access_token)).status).toBe(200)

  const replay = await form('/identity/connect/token', {
    grant_type: 'refresh_token',
    refresh_token: s.refresh_token,
  })
  expect(replay.status).toBe(400)
  expect(((await replay.json()) as any).error).toBe('invalid_grant')
  const garbage = await form('/identity/connect/token', {
    grant_type: 'refresh_token',
    refresh_token: 'nonsense',
  })
  expect(garbage.status).toBe(400)
})

it('refresh grant rejects expired refresh tokens', async () => {
  const s = await createSession('stale@example.com')
  await env.DB.prepare('update devices set updated_at = ?')
    .bind(Date.now() - 31 * 24 * 3600 * 1000)
    .run()
  const res = await form('/identity/connect/token', {
    grant_type: 'refresh_token',
    refresh_token: s.refresh_token,
  })
  expect(res.status).toBe(400)
})

it('client_credentials logs in with the user API key', async () => {
  const s = await createSession('apikey@example.com')
  const key = (await (
    await authed('/api/accounts/api-key', s.access_token, 'POST', {
      masterPasswordHash: 'client-derived-hash',
    })
  ).json()) as any
  const row = await env.DB.prepare('select uuid from users where email = ?')
    .bind('apikey@example.com')
    .first<{ uuid: string }>()
  const res = await form('/identity/connect/token', {
    grant_type: 'client_credentials',
    client_id: `user.${row?.uuid}`,
    client_secret: key.apiKey,
    scope: 'api',
    deviceIdentifier: 'cli-1',
    deviceType: '25',
    deviceName: 'cli',
  })
  expect(res.status).toBe(200)
  const body = (await res.json()) as any
  expect(body.scope).toBe('api')
  expect(body.refresh_token).toBeUndefined()
  expect(body.Key).toBe('2.encryptedSymmetricKey')
  expect((await authed('/api/accounts/profile', body.access_token)).status).toBe(200)

  const bad = await form('/identity/connect/token', {
    grant_type: 'client_credentials',
    client_id: `user.${row?.uuid}`,
    client_secret: 'wrong',
    scope: 'api',
  })
  expect(bad.status).toBe(400)
  expect(((await bad.json()) as any).error).toBe('invalid_client')
})
