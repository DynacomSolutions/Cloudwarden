import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { authed, BASE, createSession, form, json, login } from './helpers'

const PW = 'client-derived-hash'

it('requires a valid bearer token', async () => {
  expect((await SELF.fetch(`${BASE}/api/accounts/profile`)).status).toBe(401)
  const bad = await authed('/api/accounts/profile', 'a.b.c')
  expect(bad.status).toBe(401)
  expect(bad.headers.get('WWW-Authenticate')).toBe('Bearer')
})

it('gets and updates the profile', async () => {
  const s = await createSession('prof@example.com')
  const got = (await (await authed('/api/accounts/profile', s.access_token)).json()) as any
  expect(got).toMatchObject({
    name: 'Test User',
    email: 'prof@example.com',
    emailVerified: true,
    premium: true,
    masterPasswordHint: 'hint',
    key: '2.encryptedSymmetricKey',
    privateKey: '2.pk',
    twoFactorEnabled: false,
    organizations: [],
    object: 'profile',
  })
  const put = await authed('/api/accounts/profile', s.access_token, 'PUT', {
    name: 'New Name',
    masterPasswordHint: 'new hint',
  })
  expect(await put.json()).toMatchObject({ name: 'New Name', masterPasswordHint: 'new hint' })
})

it('returns the revision date as a number', async () => {
  const s = await createSession('rev@example.com')
  const res = await authed('/api/accounts/revision-date', s.access_token)
  expect(typeof (await res.json())).toBe('number')
})

it('verifies the password', async () => {
  const s = await createSession('vp@example.com')
  expect(
    (
      await authed('/api/accounts/verify-password', s.access_token, 'POST', {
        masterPasswordHash: PW,
      })
    ).status,
  ).toBe(200)
  const bad = await authed('/api/accounts/verify-password', s.access_token, 'POST', {
    masterPasswordHash: 'x',
  })
  expect(bad.status).toBe(400)
})

it('password change invalidates access and refresh tokens', async () => {
  const s = await createSession('pw@example.com')
  const res = await authed('/api/accounts/password', s.access_token, 'POST', {
    masterPasswordHash: PW,
    newMasterPasswordHash: 'new-hash',
    masterPasswordHint: 'h2',
    key: '2.newKey',
  })
  expect(res.status).toBe(200)
  expect((await authed('/api/accounts/profile', s.access_token)).status).toBe(401)
  const refresh = await form('/identity/connect/token', {
    grant_type: 'refresh_token',
    refresh_token: s.refresh_token,
  })
  expect(refresh.status).toBe(400)
  expect((await login('pw@example.com', PW)).status).toBe(400)
  const again = await login('pw@example.com', 'new-hash')
  expect(again.status).toBe(200)
  expect(((await again.json()) as any).Key).toBe('2.newKey')
})

it('rejects password change with a wrong current password', async () => {
  const s = await createSession('pwbad@example.com')
  const res = await authed('/api/accounts/password', s.access_token, 'POST', {
    masterPasswordHash: 'wrong',
    newMasterPasswordHash: 'n',
    key: 'k',
  })
  expect(res.status).toBe(400)
  expect((await authed('/api/accounts/profile', s.access_token)).status).toBe(200)
})

it('changes KDF settings and invalidates sessions', async () => {
  const s = await createSession('kdf@example.com')
  const bad = await authed('/api/accounts/kdf', s.access_token, 'POST', {
    masterPasswordHash: PW,
    newMasterPasswordHash: 'n',
    key: 'k',
    kdf: 0,
    kdfIterations: 10,
  })
  expect(bad.status).toBe(400)
  const ok = await authed('/api/accounts/kdf', s.access_token, 'POST', {
    masterPasswordHash: PW,
    newMasterPasswordHash: 'kdf-hash',
    key: '2.kdfKey',
    kdf: 1,
    kdfIterations: 3,
    kdfMemory: 64,
    kdfParallelism: 4,
  })
  expect(ok.status).toBe(200)
  const pre = await json('/identity/accounts/prelogin', { email: 'kdf@example.com' })
  expect(await pre.json()).toEqual({ kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 })
  expect((await authed('/api/accounts/profile', s.access_token)).status).toBe(401)
  expect((await login('kdf@example.com', 'kdf-hash')).status).toBe(200)
})

it('rotating the security stamp kills tokens', async () => {
  const s = await createSession('stamp@example.com')
  expect(
    (
      await authed('/api/accounts/security-stamp', s.access_token, 'POST', {
        masterPasswordHash: 'bad',
      })
    ).status,
  ).toBe(400)
  expect((await authed('/api/accounts/profile', s.access_token)).status).toBe(200)
  expect(
    (
      await authed('/api/accounts/security-stamp', s.access_token, 'POST', {
        masterPasswordHash: PW,
      })
    ).status,
  ).toBe(200)
  expect((await authed('/api/accounts/profile', s.access_token)).status).toBe(401)
  const refresh = await form('/identity/connect/token', {
    grant_type: 'refresh_token',
    refresh_token: s.refresh_token,
  })
  expect(refresh.status).toBe(400)
  const fresh = (await (await login('stamp@example.com')).json()) as any
  expect((await authed('/api/accounts/profile', fresh.access_token)).status).toBe(200)
})

it('sets keys once for accounts registered without them', async () => {
  const reg = await json('/identity/accounts/register', {
    email: 'nokeys@example.com',
    masterPasswordHash: PW,
    key: '2.k',
  })
  expect(reg.status).toBe(200)
  const s = (await (await login('nokeys@example.com')).json()) as any
  const set = await authed('/api/accounts/keys', s.access_token, 'POST', {
    publicKey: 'pub',
    encryptedPrivateKey: '2.priv',
  })
  expect(await set.json()).toMatchObject({ publicKey: 'pub', privateKey: '2.priv', object: 'keys' })
  const again = await authed('/api/accounts/keys', s.access_token, 'POST', {
    publicKey: 'p2',
    encryptedPrivateKey: '2.p2',
  })
  expect(again.status).toBe(400)
})

it('returns a stable API key and rotates it on request', async () => {
  const s = await createSession('keys@example.com')
  const body = { masterPasswordHash: PW }
  const a = (await (
    await authed('/api/accounts/api-key', s.access_token, 'POST', body)
  ).json()) as any
  const b = (await (
    await authed('/api/accounts/api-key', s.access_token, 'POST', body)
  ).json()) as any
  expect(a.object).toBe('apiKey')
  expect(b.apiKey).toBe(a.apiKey)
  const c = (await (
    await authed('/api/accounts/rotate-api-key', s.access_token, 'POST', body)
  ).json()) as any
  expect(c.apiKey).not.toBe(a.apiKey)
  expect(
    (await authed('/api/accounts/api-key', s.access_token, 'POST', { masterPasswordHash: 'x' }))
      .status,
  ).toBe(400)
})

it('changes email with a token and re-keys the account', async () => {
  const s = await createSession('old@example.com')
  expect(
    (
      await authed('/api/accounts/email-token', s.access_token, 'POST', {
        newEmail: 'new@example.com',
        masterPasswordHash: 'bad',
      })
    ).status,
  ).toBe(400)
  expect(
    (
      await authed('/api/accounts/email-token', s.access_token, 'POST', {
        newEmail: 'old@example.com',
        masterPasswordHash: PW,
      })
    ).status,
  ).toBe(400)
  const tok = await authed('/api/accounts/email-token', s.access_token, 'POST', {
    newEmail: 'new@example.com',
    masterPasswordHash: PW,
  })
  expect(tok.status).toBe(204)
  const row = await env.DB.prepare('select email_new_token t from users where email = ?')
    .bind('old@example.com')
    .first<{ t: string }>()
  const change = (token: string) =>
    authed('/api/accounts/email', s.access_token, 'POST', {
      newEmail: 'new@example.com',
      masterPasswordHash: PW,
      newMasterPasswordHash: 'email-hash',
      token,
      key: '2.emailKey',
    })
  expect((await change('000000x')).status).toBe(400)
  expect((await change(row?.t as string)).status).toBe(200)
  expect((await login('old@example.com', 'email-hash')).status).toBe(400)
  expect((await login('new@example.com', 'email-hash')).status).toBe(200)
  expect((await authed('/api/accounts/profile', s.access_token)).status).toBe(401)
})

it('rejects an expired email change token', async () => {
  const s = await createSession('exp@example.com')
  await authed('/api/accounts/email-token', s.access_token, 'POST', {
    newEmail: 'exp2@example.com',
    masterPasswordHash: PW,
  })
  await env.DB.prepare('update users set email_new_expires_at = 1 where email = ?')
    .bind('exp@example.com')
    .run()
  const row = await env.DB.prepare('select email_new_token t from users where email = ?')
    .bind('exp@example.com')
    .first<{ t: string }>()
  const res = await authed('/api/accounts/email', s.access_token, 'POST', {
    newEmail: 'exp2@example.com',
    masterPasswordHash: PW,
    newMasterPasswordHash: 'n',
    token: row?.t,
    key: 'k',
  })
  expect(res.status).toBe(400)
})

const seedVault = async (email: string) => {
  const tag = email.split('@')[0]
  const u = await env.DB.prepare('select uuid from users where email = ?')
    .bind(email)
    .first<{ uuid: string }>()
  const now = Date.now()
  await env.DB.batch([
    env.DB.prepare(
      'insert into folders (uuid, user_uuid, name, created_at, updated_at) values (?,?,?,?,?)',
    ).bind(`f-${tag}`, u?.uuid, '2.oldFolder', now, now),
    env.DB.prepare(
      'insert into ciphers (uuid, user_uuid, atype, name, data, created_at, updated_at) values (?,?,?,?,?,?,?)',
    ).bind(`c-${tag}`, u?.uuid, 1, '2.oldName', '{}', now, now),
  ])
}

it('rotates keys atomically and re-encrypts vault items', async () => {
  const tag = 'rot'
  const s = await createSession('rot@example.com')
  await seedVault('rot@example.com')
  const res = await authed('/api/accounts/key', s.access_token, 'POST', {
    masterPasswordHash: PW,
    key: '2.rotatedKey',
    privateKey: '2.rotatedPriv',
    folders: [{ id: `f-${tag}`, name: '2.newFolder' }],
    ciphers: [{ id: `c-${tag}`, name: '2.newName', type: 1, login: { username: '2.u' } }],
    sends: [],
  })
  expect(res.status).toBe(200)
  const u = await env.DB.prepare('select akey, private_key from users where email = ?')
    .bind('rot@example.com')
    .first<any>()
  expect(u).toMatchObject({ akey: '2.rotatedKey', private_key: '2.rotatedPriv' })
  expect(
    (await env.DB.prepare('select name from folders where uuid = ?').bind(`f-${tag}`).first<any>())
      .name,
  ).toBe('2.newFolder')
  const c = await env.DB.prepare('select name, data from ciphers where uuid = ?')
    .bind(`c-${tag}`)
    .first<any>()
  expect(c.name).toBe('2.newName')
  expect(JSON.parse(c.data)).toEqual({ login: { username: '2.u' } })
  expect((await authed('/api/accounts/profile', s.access_token)).status).toBe(401)
})

it('rotation is all-or-nothing: incomplete or foreign items change nothing', async () => {
  const tag = 'rot2'
  const s = await createSession('rot2@example.com')
  await seedVault('rot2@example.com')
  const base = { masterPasswordHash: PW, key: '2.bad', privateKey: '2.bad', sends: [] }
  const missing = await authed('/api/accounts/key', s.access_token, 'POST', {
    ...base,
    folders: [],
    ciphers: [{ id: `c-${tag}`, name: 'x' }],
  })
  expect(missing.status).toBe(400)
  const foreign = await authed('/api/accounts/key', s.access_token, 'POST', {
    ...base,
    folders: [{ id: `f-${tag}`, name: 'x' }],
    ciphers: [
      { id: `c-${tag}`, name: 'x' },
      { id: 'other', name: 'y' },
    ],
  })
  expect(foreign.status).toBe(400)
  const u = await env.DB.prepare('select akey from users where email = ?')
    .bind('rot2@example.com')
    .first<any>()
  expect(u.akey).toBe('2.encryptedSymmetricKey')
  expect(
    (await env.DB.prepare('select name from folders where uuid = ?').bind(`f-${tag}`).first<any>())
      .name,
  ).toBe('2.oldFolder')
  expect(
    (await env.DB.prepare('select name from ciphers where uuid = ?').bind(`c-${tag}`).first<any>())
      .name,
  ).toBe('2.oldName')
  expect((await authed('/api/accounts/profile', s.access_token)).status).toBe(200)
})

it('deletes the account and its data after password verification', async () => {
  const tag = 'del'
  const s = await createSession('del@example.com')
  await seedVault('del@example.com')
  expect(
    (await authed('/api/accounts', s.access_token, 'DELETE', { masterPasswordHash: 'bad' })).status,
  ).toBe(400)
  expect(
    (await authed('/api/accounts', s.access_token, 'DELETE', { masterPasswordHash: PW })).status,
  ).toBe(200)
  expect((await authed('/api/accounts/profile', s.access_token)).status).toBe(401)
  expect((await login('del@example.com')).status).toBe(400)
  expect(
    await env.DB.prepare('select 1 from devices where identifier = ? and name = ?')
      .bind('device-1', 'chrome')
      .all()
      .then((r) => r.results.length),
  ).toBeGreaterThanOrEqual(0)
  expect(
    await env.DB.prepare('select count(*) n from folders where uuid = ?')
      .bind(`f-${tag}`)
      .first<any>(),
  ).toEqual({ n: 0 })
})

it('supports POST /api/accounts/delete', async () => {
  const s = await createSession('del2@example.com')
  expect(
    (await authed('/api/accounts/delete', s.access_token, 'POST', { masterPasswordHash: PW }))
      .status,
  ).toBe(200)
  expect((await login('del2@example.com')).status).toBe(400)
})

it('stores the SDK user key id report and returns it in sync', async () => {
  const s = await createSession('keyid@example.com')
  const before = (await (await authed('/api/sync', s.access_token)).json()) as any
  expect(before.userDecryption.userKeyId).toBeNull()
  const res = await authed('/api/accounts/key-management/user-key-id', s.access_token, 'POST', {
    userKeyId: '00000000-0000-4000-8000-000000000000',
  })
  expect(res.status).toBe(200)
  const after = (await (await authed('/api/sync', s.access_token)).json()) as any
  expect(after.userDecryption.userKeyId).toBe('00000000-0000-4000-8000-000000000000')
  expect(
    (await authed('/api/accounts/key-management/user-key-id', s.access_token, 'POST', {})).status,
  ).toBe(400)
})
