import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { authed, json, login } from './helpers'

const nested = (
  email: string,
  hash: string,
  key: string,
  kdf = { kdfType: 0, iterations: 600000 },
) => ({
  masterPasswordAuthentication: { salt: email, kdf, masterPasswordAuthenticationHash: hash },
  masterPasswordUnlock: { salt: email, kdf, masterKeyWrappedUserKey: key },
})

const registerNested = (email: string, extra: Record<string, unknown> = {}) =>
  json('/identity/accounts/register/finish', {
    email,
    masterPasswordHint: 'hint',
    userAsymmetricKeys: { publicKey: 'pub', encryptedPrivateKey: '2.pk' },
    ...nested(email, 'nested-hash', '2.wrapped'),
    ...extra,
  })

it('registers with the nested 2026.9 payload using the token name', async () => {
  const send = await json('/identity/accounts/register/send-verification-email', {
    email: 'nest@example.com',
    name: 'Nest',
  })
  const token = (await send.json()) as string
  const res = await registerNested('nest@example.com', { emailVerificationToken: token })
  expect(res.status).toBe(200)
  const row = await env.DB.prepare(
    'select name, akey, kdf_type, kdf_iterations from users where email = ?',
  )
    .bind('nest@example.com')
    .first<Record<string, unknown>>()
  expect(row).toMatchObject({
    name: 'Nest',
    akey: '2.wrapped',
    kdf_type: 0,
    kdf_iterations: 600000,
  })
  expect((await login('nest@example.com', 'nested-hash')).status).toBe(200)
})

it('registers with nested Argon2id settings', async () => {
  const kdf = { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 }
  const res = await json('/identity/accounts/register/finish', {
    email: 'argonn@example.com',
    userAsymmetricKeys: { publicKey: 'pub', encryptedPrivateKey: '2.pk' },
    ...nested('argonn@example.com', 'h', '2.k', kdf),
  })
  expect(res.status).toBe(200)
  const pre = await json('/identity/accounts/prelogin', { email: 'argonn@example.com' })
  expect(await pre.json()).toEqual({ kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 })
})

it('rejects inconsistent nested payloads', async () => {
  const base = { userAsymmetricKeys: { publicKey: 'p', encryptedPrivateKey: '2.pk' } }
  const wrongSalt = await json('/identity/accounts/register/finish', {
    email: 'salt@example.com',
    ...base,
    ...nested('someone-else@example.com', 'h', '2.k'),
  })
  expect(wrongSalt.status).toBe(400)
  const n = nested('diff@example.com', 'h', '2.k')
  n.masterPasswordUnlock.kdf = { kdfType: 0, iterations: 700000 }
  const differ = await json('/identity/accounts/register/finish', {
    email: 'diff@example.com',
    ...base,
    ...n,
  })
  expect(differ.status).toBe(400)
})

const session = async (email: string) => {
  expect((await registerNested(email)).status).toBe(200)
  return (await (await login(email, 'nested-hash')).json()) as { access_token: string }
}

it('changes password with authenticationData and unlockData', async () => {
  const s = await session('npw@example.com')
  const res = await authed('/api/accounts/password', s.access_token, 'POST', {
    masterPasswordHash: 'nested-hash',
    masterPasswordHint: 'new',
    authenticationData: nested('npw@example.com', 'next-hash', '2.next')
      .masterPasswordAuthentication,
    unlockData: nested('npw@example.com', 'next-hash', '2.next').masterPasswordUnlock,
  })
  expect(res.status).toBe(200)
  const again = (await (await login('npw@example.com', 'next-hash')).json()) as Record<
    string,
    unknown
  >
  expect(again.Key).toBe('2.next')
})

it('changes KDF with authenticationData and unlockData', async () => {
  const s = await session('nkdf@example.com')
  const kdf = { kdfType: 1, iterations: 3, memory: 64, parallelism: 4 }
  const n = nested('nkdf@example.com', 'kdf-hash', '2.kdfkey', kdf)
  const res = await authed('/api/accounts/kdf', s.access_token, 'POST', {
    masterPasswordHash: 'nested-hash',
    authenticationData: n.masterPasswordAuthentication,
    unlockData: n.masterPasswordUnlock,
  })
  expect(res.status).toBe(200)
  const pre = await json('/identity/accounts/prelogin', { email: 'nkdf@example.com' })
  expect(await pre.json()).toEqual({ kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 })
  expect((await login('nkdf@example.com', 'kdf-hash')).status).toBe(200)
})

it('rotates account keys with the key-management payload', async () => {
  const s = await session('nrot@example.com')
  const unlock = {
    kdfType: 0,
    kdfIterations: 600000,
    email: 'nrot@example.com',
    masterKeyAuthenticationHash: 'rot-hash',
    masterKeyEncryptedUserKey: '2.rotkey',
    masterPasswordHint: null,
  }
  const body = (old: string) => ({
    oldMasterKeyAuthenticationHash: old,
    accountUnlockData: { masterPasswordUnlockData: unlock },
    accountKeys: { userKeyEncryptedAccountPrivateKey: '2.rotpriv', accountPublicKey: 'pub' },
    accountData: { ciphers: [], folders: [], sends: [] },
  })
  const path = '/api/accounts/key-management/rotate-user-account-keys'
  expect((await authed(path, s.access_token, 'POST', body('wrong'))).status).toBe(400)
  expect((await authed(path, s.access_token, 'POST', body('nested-hash'))).status).toBe(200)
  const again = (await (await login('nrot@example.com', 'rot-hash')).json()) as Record<
    string,
    unknown
  >
  expect(again).toMatchObject({ Key: '2.rotkey', PrivateKey: '2.rotpriv' })
  expect((await authed('/api/accounts/profile', s.access_token)).status).toBe(401)
})

it('rejects a nested password change that alters the KDF', async () => {
  const s = await session('nlock@example.com')
  const n = nested('nlock@example.com', 'x', '2.x', { kdfType: 0, iterations: 700000 })
  const res = await authed('/api/accounts/password', s.access_token, 'POST', {
    masterPasswordHash: 'nested-hash',
    authenticationData: n.masterPasswordAuthentication,
    unlockData: n.masterPasswordUnlock,
  })
  expect(res.status).toBe(400)
  expect((await login('nlock@example.com', 'nested-hash')).status).toBe(200)
})

it('rotation rejects a changed public key and keeps the hint when omitted', async () => {
  const s = await session('nhint@example.com')
  const unlock: Record<string, unknown> = {
    kdfType: 0,
    kdfIterations: 600000,
    email: 'nhint@example.com',
    masterKeyAuthenticationHash: 'h2',
    masterKeyEncryptedUserKey: '2.k2',
  }
  const body = (pub: string) => ({
    oldMasterKeyAuthenticationHash: 'nested-hash',
    accountUnlockData: { masterPasswordUnlockData: unlock },
    accountKeys: { userKeyEncryptedAccountPrivateKey: '2.p2', accountPublicKey: pub },
    accountData: { ciphers: [], folders: [], sends: [] },
  })
  const path = '/api/accounts/key-management/rotate-user-account-keys'
  expect((await authed(path, s.access_token, 'POST', body('different'))).status).toBe(400)
  expect((await authed(path, s.access_token, 'POST', body('pub'))).status).toBe(200)
  const row = await env.DB.prepare('select password_hint h from users where email = ?')
    .bind('nhint@example.com')
    .first<{ h: string }>()
  expect(row?.h).toBe('hint')
})
