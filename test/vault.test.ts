import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { authed, createSession, login as loginRequest, withEnv } from './helpers'

const STALE = 'The client copy of this cipher is out of date. Resync the client and try again.'

const login = (name = '2.name') => ({
  type: 1,
  name,
  notes: '2.notes',
  favorite: false,
  reprompt: 0,
  key: '2.ckey',
  fields: [{ type: 0, name: '2.fn', value: '2.fv', linkedId: null }],
  passwordHistory: [{ password: '2.old', lastUsedDate: '2024-01-01T00:00:00.000Z' }],
  login: {
    username: '2.u',
    password: '2.p',
    totp: '2.totp',
    passwordRevisionDate: null,
    autofillOnPageLoad: true,
    uris: [{ uri: '2.uri', match: 3, uriChecksum: '2.sum' }],
    fido2Credentials: [{ credentialId: '2.cid', keyType: 'public-key', rpId: '2.rp' }],
  },
})
const card = () => ({
  type: 3,
  name: '2.card',
  card: {
    cardholderName: '2.c',
    number: '2.n',
    brand: '2.b',
    expMonth: '2.m',
    expYear: '2.y',
    code: '2.cv',
  },
})
const identity = () => ({
  type: 4,
  name: '2.id',
  identity: { title: '2.t', firstName: '2.f', lastName: '2.l', email: '2.e', ssn: '2.ssn' },
})
const note = () => ({ type: 2, name: '2.note', secureNote: { type: 0 } })
const ssh = () => ({
  type: 5,
  name: '2.ssh',
  sshKey: { privateKey: '2.pk', publicKey: '2.pub', keyFingerprint: '2.fp' },
})

const setup = async (email: string) => {
  const s = await createSession(email)
  const call = (path: string, method = 'GET', body?: unknown) =>
    authed(path, s.access_token, method, body)
  return { s, call }
}
const j = async (res: Response) => (await res.json()) as any

it('requires authentication on vault routes', async () => {
  const { SELF } = await import('cloudflare:test')
  for (const p of ['/api/sync', '/api/ciphers', '/api/folders', '/api/settings/domains']) {
    expect((await SELF.fetch(`https://vault.example.com${p}`)).status).toBe(401)
  }
})

it('syncs an empty vault with the full profile shape', async () => {
  const { call } = await setup('sync0@example.com')
  const res = await call('/api/sync')
  expect(res.status).toBe(200)
  const body = await j(res)
  expect(body).toMatchObject({
    object: 'sync',
    folders: [],
    collections: [],
    ciphers: [],
    policies: [],
    sends: [],
    profile: {
      object: 'profile',
      organizations: [],
      providers: [],
      providerOrganizations: [],
      premium: true,
      emailVerified: true,
      usesKeyConnector: false,
      forcePasswordReset: false,
      key: '2.encryptedSymmetricKey',
      privateKey: '2.pk',
    },
    domains: { object: 'domains', equivalentDomains: [] },
    userDecryption: {
      masterPasswordUnlock: {
        kdf: { kdfType: 0, iterations: 600000 },
        masterKeyEncryptedUserKey: '2.encryptedSymmetricKey',
        salt: 'sync0@example.com',
      },
    },
  })
  expect(typeof body.profile.creationDate).toBe('string')
  expect(body.domains.globalEquivalentDomains.length).toBeGreaterThan(0)
  const slim = await j(await call('/api/sync?excludeDomains=true'))
  expect(slim.domains).toBeNull()
})

it('round-trips every cipher type through sync', async () => {
  const { call } = await setup('rt@example.com')
  const inputs = [login(), card(), identity(), note(), ssh()]
  const created: any[] = []
  for (const i of inputs) {
    const res = await call('/api/ciphers', 'POST', i)
    expect(res.status).toBe(200)
    created.push(await j(res))
  }
  const sync = await j(await call('/api/sync'))
  expect(sync.ciphers).toHaveLength(5)
  for (const [n, input] of inputs.entries()) {
    const got = sync.ciphers.find((c: any) => c.id === created[n].id)
    expect(got).toMatchObject({
      object: 'cipherDetails',
      type: input.type,
      name: input.name,
      edit: true,
      viewPassword: true,
      organizationUseTotp: false,
      attachments: null,
      archivedDate: null,
      deletedDate: null,
      folderId: null,
      permissions: { delete: true, restore: true },
    })
    for (const k of ['login', 'card', 'identity', 'secureNote', 'sshKey'] as const) {
      expect(got[k]).toEqual((input as any)[k] ?? null)
    }
    expect(await j(await call(`/api/ciphers/${got.id}`))).toEqual(got)
  }
  const full = sync.ciphers.find((c: any) => c.id === created[0].id)
  expect(full).toMatchObject({
    notes: '2.notes',
    key: '2.ckey',
    fields: login().fields,
    passwordHistory: login().passwordHistory,
  })
  const list = await j(await call('/api/ciphers'))
  expect(list.object).toBe('list')
  expect(list.data).toHaveLength(5)
})

it('returns the legacy data field as a JSON string', async () => {
  const { call } = await setup('legacy-data@example.com')
  const body = await j(await call('/api/ciphers', 'POST', login()))
  expect(typeof body.data).toBe('string')
  expect(JSON.parse(body.data)).toMatchObject({ username: '2.u', password: '2.p' })
  const note2 = await j(await call('/api/ciphers', 'POST', { type: 2, name: '2.n' }))
  expect(note2.data).toBeNull()
})

it('validates cipher bodies and ownership', async () => {
  const { call } = await setup('val@example.com')
  expect((await call('/api/ciphers', 'POST', { type: 9, name: 'x' })).status).toBe(400)
  expect((await call('/api/ciphers', 'POST', { type: 1 })).status).toBe(400)
  expect(
    (await call('/api/ciphers', 'POST', { ...login(), folderId: crypto.randomUUID() })).status,
  ).toBe(400)
  expect(
    (await call('/api/ciphers', 'POST', { ...login(), organizationId: crypto.randomUUID() }))
      .status,
  ).toBe(404)
  expect((await call(`/api/ciphers/${crypto.randomUUID()}`)).status).toBe(404)

  const other = await setup('val2@example.com')
  const mine = await j(await call('/api/ciphers', 'POST', login()))
  expect((await other.call(`/api/ciphers/${mine.id}`)).status).toBe(404)
  expect((await other.call(`/api/ciphers/${mine.id}`, 'PUT', login())).status).toBe(404)
  expect((await other.call(`/api/ciphers/${mine.id}`, 'DELETE')).status).toBe(404)
  expect((await other.call('/api/ciphers/delete', 'POST', { ids: [mine.id] })).status).toBe(404)
  expect((await call(`/api/ciphers/${mine.id}`)).status).toBe(200)
})

it('creates through /create and rejects collections', async () => {
  const { call } = await setup('create@example.com')
  const ok = await call('/api/ciphers/create', 'POST', { cipher: login(), collectionIds: [] })
  expect(ok.status).toBe(200)
  expect((await j(ok)).name).toBe('2.name')
  const bad = await call('/api/ciphers/create', 'POST', {
    cipher: login(),
    collectionIds: [crypto.randomUUID()],
  })
  expect(bad.status).toBe(400)
})

it('updates ciphers with PUT and POST and changes type payloads', async () => {
  const { call } = await setup('upd@example.com')
  const c = await j(await call('/api/ciphers', 'POST', login()))
  const put = await call(`/api/ciphers/${c.id}`, 'PUT', { ...login('2.renamed'), favorite: true })
  expect(await j(put)).toMatchObject({
    name: '2.renamed',
    favorite: true,
    creationDate: c.creationDate,
  })
  const post = await call(`/api/ciphers/${c.id}`, 'POST', card())
  const body = await j(post)
  expect(body).toMatchObject({ type: 3, login: null, card: card().card })
})

it('updates favorite and folder with the partial endpoint', async () => {
  const { call } = await setup('part@example.com')
  const f = await j(await call('/api/folders', 'POST', { name: '2.folder' }))
  const c = await j(await call('/api/ciphers', 'POST', login()))
  const res = await call(`/api/ciphers/${c.id}/partial`, 'PUT', { folderId: f.id, favorite: true })
  expect(await j(res)).toMatchObject({ folderId: f.id, favorite: true, name: '2.name' })
  const clear = await call(`/api/ciphers/${c.id}/partial`, 'PUT', {
    folderId: null,
    favorite: false,
  })
  expect(await j(clear)).toMatchObject({ folderId: null, favorite: false })
  const bad = await call(`/api/ciphers/${c.id}/partial`, 'PUT', {
    folderId: crypto.randomUUID(),
    favorite: false,
  })
  expect(bad.status).toBe(400)
})

it('soft deletes, restores and hard deletes a cipher', async () => {
  const { call } = await setup('del@example.com')
  const c = await j(await call('/api/ciphers', 'POST', login()))
  expect((await call(`/api/ciphers/${c.id}/delete`, 'PUT')).status).toBe(200)
  const deleted = await j(await call(`/api/ciphers/${c.id}`))
  expect(typeof deleted.deletedDate).toBe('string')
  const sync = await j(await call('/api/sync'))
  expect(sync.ciphers[0].deletedDate).not.toBeNull()

  const restored = await j(await call(`/api/ciphers/${c.id}/restore`, 'PUT'))
  expect(restored.deletedDate).toBeNull()

  expect((await call(`/api/ciphers/${c.id}`, 'DELETE')).status).toBe(200)
  expect((await call(`/api/ciphers/${c.id}`)).status).toBe(404)
})

it('handles bulk move, soft delete, restore and hard delete', async () => {
  const { call } = await setup('bulk@example.com')
  const f = await j(await call('/api/folders', 'POST', { name: '2.f' }))
  const ids: string[] = []
  for (let n = 0; n < 3; n++)
    ids.push((await j(await call('/api/ciphers', 'POST', login(`2.n${n}`)))).id)

  expect((await call('/api/ciphers/move', 'PUT', { ids, folderId: f.id })).status).toBe(204)
  let list = (await j(await call('/api/ciphers'))).data
  expect(list.every((c: any) => c.folderId === f.id)).toBe(true)
  expect((await call('/api/ciphers/move', 'PUT', { ids: [ids[0]], folderId: null })).status).toBe(
    204,
  )
  list = (await j(await call('/api/ciphers'))).data
  expect(list.find((c: any) => c.id === ids[0]).folderId).toBeNull()
  expect(
    (await call('/api/ciphers/move', 'PUT', { ids, folderId: crypto.randomUUID() })).status,
  ).toBe(400)

  expect((await call('/api/ciphers/delete', 'PUT', { ids: [ids[0], ids[1]] })).status).toBe(200)
  list = (await j(await call('/api/ciphers'))).data
  expect(list.filter((c: any) => c.deletedDate !== null)).toHaveLength(2)

  const restored = await j(await call('/api/ciphers/restore', 'PUT', { ids: [ids[0], ids[1]] }))
  expect(restored.object).toBe('list')
  expect(restored.data).toHaveLength(2)
  expect(restored.data.every((c: any) => c.deletedDate === null)).toBe(true)

  expect((await call('/api/ciphers/delete', 'POST', { ids: [ids[0], ids[1]] })).status).toBe(200)
  expect((await j(await call('/api/ciphers'))).data).toHaveLength(1)
  const missing = await call('/api/ciphers/delete', 'POST', { ids: [ids[2], crypto.randomUUID()] })
  expect(missing.status).toBe(404)
  expect((await j(await call('/api/ciphers'))).data).toHaveLength(1)
})

it('bulk operations accept more ids than one SQL statement can bind', async () => {
  const { s, call } = await setup('many@example.com')
  const now = Date.now()
  const ids = Array.from({ length: 250 }, () => crypto.randomUUID())
  const user = await env.DB.prepare('select uuid from users where email = ?')
    .bind('many@example.com')
    .first<{ uuid: string }>()
  await env.DB.batch(
    ids.map((id) =>
      env.DB.prepare(
        'insert into ciphers (uuid, user_uuid, atype, name, data, created_at, updated_at) values (?,?,?,?,?,?,?)',
      ).bind(id, user?.uuid, 2, '2.n', '{"secureNote":{"type":0}}', now, now),
    ),
  )
  expect(s.access_token).toBeTruthy()
  expect((await call('/api/ciphers/delete', 'PUT', { ids })).status).toBe(200)
  const list = (await j(await call('/api/ciphers'))).data
  expect(list).toHaveLength(250)
  expect(list.every((c: any) => c.deletedDate !== null)).toBe(true)
  expect((await call('/api/ciphers/delete', 'POST', { ids })).status).toBe(200)
  expect((await j(await call('/api/ciphers'))).data).toHaveLength(0)
})

it('purges the vault only with the master password', async () => {
  const { call } = await setup('purge@example.com')
  await call('/api/ciphers', 'POST', login())
  await call('/api/folders', 'POST', { name: '2.f' })
  expect((await call('/api/ciphers/purge', 'POST', { masterPasswordHash: 'wrong' })).status).toBe(
    400,
  )
  expect((await j(await call('/api/ciphers'))).data).toHaveLength(1)
  expect(
    (await call('/api/ciphers/purge', 'POST', { masterPasswordHash: 'client-derived-hash' }))
      .status,
  ).toBe(200)
  const sync = await j(await call('/api/sync'))
  expect(sync.ciphers).toEqual([])
  expect(sync.folders).toEqual([])
})

it('rejects stale updates and accepts current ones', async () => {
  const { call } = await setup('stale@example.com')
  const c = await j(await call('/api/ciphers', 'POST', login()))
  await new Promise((r) => setTimeout(r, 1100))
  const fresh = await j(
    await call(`/api/ciphers/${c.id}`, 'PUT', {
      ...login('2.v2'),
      lastKnownRevisionDate: c.revisionDate,
    }),
  )
  expect(fresh.name).toBe('2.v2')
  expect(fresh.revisionDate).not.toBe(c.revisionDate)

  const stale = await call(`/api/ciphers/${c.id}`, 'PUT', {
    ...login('2.v3'),
    lastKnownRevisionDate: c.revisionDate,
  })
  expect(stale.status).toBe(400)
  expect((await j(stale)).message).toBe(STALE)
  expect((await j(await call(`/api/ciphers/${c.id}`))).name).toBe('2.v2')

  const ok = await call(`/api/ciphers/${c.id}`, 'PUT', {
    ...login('2.v4'),
    lastKnownRevisionDate: fresh.revisionDate,
  })
  expect(ok.status).toBe(200)
  const bad = await call(`/api/ciphers/${c.id}`, 'PUT', {
    ...login(),
    lastKnownRevisionDate: 'nope',
  })
  expect(bad.status).toBe(400)
})

it('bumps the account revision date on every vault write', async () => {
  const { call } = await setup('rev2@example.com')
  const rev = async () => (await j(await call('/api/accounts/revision-date'))) as number
  let last = await rev()
  const step = async (fn: () => Promise<Response>) => {
    await new Promise((r) => setTimeout(r, 5))
    expect((await fn()).status).toBeLessThan(300)
    const next = await rev()
    expect(next).toBeGreaterThan(last)
    last = next
  }
  let cid = ''
  let fid = ''
  await step(async () => {
    const r = await call('/api/ciphers', 'POST', login())
    cid = (await r.clone().json<any>()).id
    return r
  })
  await step(async () => {
    const r = await call('/api/folders', 'POST', { name: '2.f' })
    fid = (await r.clone().json<any>()).id
    return r
  })
  await step(() => call(`/api/ciphers/${cid}`, 'PUT', login('2.x')))
  await step(() => call(`/api/ciphers/${cid}/partial`, 'PUT', { folderId: fid, favorite: true }))
  await step(() => call(`/api/ciphers/${cid}/delete`, 'PUT'))
  await step(() => call(`/api/ciphers/${cid}/restore`, 'PUT'))
  await step(() => call('/api/ciphers/move', 'PUT', { ids: [cid], folderId: null }))
  await step(() => call(`/api/folders/${fid}`, 'PUT', { name: '2.g' }))
  await step(() =>
    call('/api/settings/domains', 'PUT', { equivalentDomains: [['a.com', 'b.com']] }),
  )
  await step(() => call(`/api/folders/${fid}`, 'DELETE'))
  await step(() => call(`/api/ciphers/${cid}`, 'DELETE'))
})

it('manages folders and unfiles ciphers when a folder is deleted', async () => {
  const { call } = await setup('folders@example.com')
  expect((await call('/api/folders', 'POST', {})).status).toBe(400)
  const f = await j(await call('/api/folders', 'POST', { name: '2.work' }))
  expect(f).toMatchObject({ name: '2.work', object: 'folder' })
  expect(typeof f.revisionDate).toBe('string')
  expect(await j(await call(`/api/folders/${f.id}`))).toMatchObject({ id: f.id, name: '2.work' })
  expect(await j(await call(`/api/folders/${f.id}`, 'PUT', { name: '2.play' }))).toMatchObject({
    name: '2.play',
  })
  expect(await j(await call(`/api/folders/${f.id}`, 'POST', { name: '2.again' }))).toMatchObject({
    name: '2.again',
  })
  expect((await j(await call('/api/folders'))).data).toHaveLength(1)

  const c = await j(await call('/api/ciphers', 'POST', { ...login(), folderId: f.id }))
  expect(c.folderId).toBe(f.id)
  expect((await j(await call('/api/sync'))).folders).toHaveLength(1)

  expect((await call(`/api/folders/${f.id}`, 'DELETE')).status).toBe(200)
  expect((await call(`/api/folders/${f.id}`)).status).toBe(404)
  const after = await j(await call(`/api/ciphers/${c.id}`))
  expect(after.folderId).toBeNull()
  expect(after.name).toBe('2.name')
  expect((await j(await call('/api/sync'))).folders).toEqual([])
})

it('keeps folders private to their owner', async () => {
  const a = await setup('fa@example.com')
  const b = await setup('fb@example.com')
  const f = await j(await a.call('/api/folders', 'POST', { name: '2.f' }))
  expect((await b.call(`/api/folders/${f.id}`)).status).toBe(404)
  expect((await b.call(`/api/folders/${f.id}`, 'PUT', { name: 'x' })).status).toBe(404)
  expect((await b.call(`/api/folders/${f.id}`, 'DELETE')).status).toBe(404)
  expect((await b.call('/api/ciphers', 'POST', { ...login(), folderId: f.id })).status).toBe(400)
  expect((await j(await b.call('/api/sync'))).folders).toEqual([])
})

it('reads and updates equivalent domains', async () => {
  const { call } = await setup('dom@example.com')
  const initial = await j(await call('/api/settings/domains'))
  expect(initial.equivalentDomains).toEqual([])
  const first = initial.globalEquivalentDomains[0]
  expect(first.excluded).toBe(false)

  const put = await j(
    await call('/api/settings/domains', 'PUT', {
      equivalentDomains: [['a.example.com', 'b.example.com']],
      excludedGlobalEquivalentDomains: [first.type],
    }),
  )
  expect(put.equivalentDomains).toEqual([['a.example.com', 'b.example.com']])
  expect(put.globalEquivalentDomains.find((g: any) => g.type === first.type).excluded).toBe(true)
  const post = await call('/api/settings/domains', 'POST', { equivalentDomains: [] })
  expect(post.status).toBe(200)
  const sync = await j(await call('/api/sync'))
  expect(sync.domains.equivalentDomains).toEqual([])
  expect(
    sync.domains.globalEquivalentDomains.find((g: any) => g.type === first.type).excluded,
  ).toBe(true)
})

it('imports folders, ciphers and relationships atomically', async () => {
  const { call } = await setup('imp@example.com')
  const payload = {
    folders: [{ name: '2.a' }, { name: '2.b' }],
    ciphers: [login('2.one'), card(), note()],
    folderRelationships: [
      { key: 0, value: 1 },
      { key: 2, value: 0 },
    ],
  }
  expect((await call('/api/ciphers/import', 'POST', payload)).status).toBe(200)
  const sync = await j(await call('/api/sync'))
  expect(sync.folders).toHaveLength(2)
  expect(sync.ciphers).toHaveLength(3)
  const byName = (n: string) => sync.ciphers.find((c: any) => c.name === n)
  const folderName = (id: string | null) => sync.folders.find((f: any) => f.id === id)?.name
  expect(folderName(byName('2.one').folderId)).toBe('2.b')
  expect(folderName(byName('2.note').folderId)).toBe('2.a')
  expect(byName('2.card').folderId).toBeNull()
  expect(byName('2.one').login).toEqual(login().login)

  // Out-of-range relationship: nothing is written.
  const bad = await call('/api/ciphers/import', 'POST', {
    folders: [{ name: '2.z' }],
    ciphers: [note()],
    folderRelationships: [{ key: 5, value: 0 }],
  })
  expect(bad.status).toBe(400)
  // An invalid cipher in the middle fails validation before any write.
  const bad2 = await call('/api/ciphers/import', 'POST', {
    folders: [{ name: '2.z' }],
    ciphers: [note(), { type: 7, name: 'x' }],
    folderRelationships: [],
  })
  expect(bad2.status).toBe(400)
  const after = await j(await call('/api/sync'))
  expect(after.folders).toHaveLength(2)
  expect(after.ciphers).toHaveLength(3)
})

it('key rotation keeps the stored cipher payload readable through sync', async () => {
  const { call } = await setup('rot@example.com')
  const c = await j(await call('/api/ciphers', 'POST', login()))
  const rot = await call('/api/accounts/key', 'POST', {
    masterPasswordHash: 'client-derived-hash',
    key: '2.newkey',
    privateKey: '2.newpk',
    folders: [],
    ciphers: [{ ...login('2.rotated'), id: c.id }],
    sends: [],
  })
  expect(rot.status).toBe(200)
  // The security stamp rotated, so the old token is dead: sign in again.
  const fresh = (await (await loginRequest('rot@example.com')).json()) as { access_token: string }
  const after = await j(await authed(`/api/ciphers/${c.id}`, fresh.access_token))
  expect(after).toMatchObject({ name: '2.rotated', login: login().login })
  expect(after.card).toBeNull()
})

it('key rotation keeps the stored payload even when the client type disagrees', async () => {
  const { call } = await setup('rot2@example.com')
  const c = await j(await call('/api/ciphers', 'POST', card()))
  const body = (extra: object) => ({
    masterPasswordHash: 'client-derived-hash',
    key: '2.newkey',
    privateKey: '2.newpk',
    folders: [],
    sends: [],
    ciphers: [{ id: c.id, name: '2.card2', card: card().card, ...extra }],
  })
  // A mismatching type is rejected and nothing changes.
  expect((await call('/api/accounts/key', 'POST', body({ type: 1 }))).status).toBe(400)
  expect((await j(await call(`/api/ciphers/${c.id}`))).name).toBe('2.card')
  // Without a type, the stored type decides what is kept.
  expect((await call('/api/accounts/key', 'POST', body({}))).status).toBe(200)
  const fresh = (await (await loginRequest('rot2@example.com')).json()) as { access_token: string }
  const after = await j(await authed(`/api/ciphers/${c.id}`, fresh.access_token))
  expect(after).toMatchObject({ type: 3, name: '2.card2', card: card().card })
})

it('applies concurrent updates once and rejects the loser as stale', async () => {
  const { call } = await setup('race@example.com')
  const f = await j(await call('/api/folders', 'POST', { name: '2.f' }))
  const c = await j(await call('/api/ciphers', 'POST', login()))
  const results = await Promise.all(
    [1, 2, 3].map((n) =>
      call(`/api/ciphers/${c.id}`, 'PUT', { ...login(`2.w${n}`), folderId: n === 1 ? f.id : null }),
    ),
  )
  const bodies = await Promise.all(results.map((r) => r.json<any>()))
  expect(results.some((r) => r.status === 200)).toBe(true)
  for (const [n, r] of results.entries()) {
    if (r.status !== 200) expect(bodies[n].message).toBe(STALE)
  }
  // Whatever won, the name and folder link belong to the same write.
  const final = await j(await call(`/api/ciphers/${c.id}`))
  const winner = final.name === '2.w1' ? f.id : null
  expect(final.folderId).toBe(winner)
})

it('keeps the revision date strictly increasing across back-to-back writes', async () => {
  const { call } = await setup('mono@example.com')
  const rev = async () => (await j(await call('/api/accounts/revision-date'))) as number
  const seen = [await rev()]
  for (let n = 0; n < 4; n++) {
    await call('/api/folders', 'POST', { name: `2.f${n}` })
    seen.push(await rev())
  }
  for (let n = 1; n < seen.length; n++) expect(seen[n]).toBeGreaterThan(seen[n - 1] as number)
})

it('keeps the original deletion time on repeated soft deletes', async () => {
  const { call } = await setup('deltime@example.com')
  const c = await j(await call('/api/ciphers', 'POST', login()))
  await call(`/api/ciphers/${c.id}/delete`, 'PUT')
  const first = (await j(await call(`/api/ciphers/${c.id}`))).deletedDate
  await new Promise((r) => setTimeout(r, 20))
  await call('/api/ciphers/delete', 'PUT', { ids: [c.id] })
  expect((await j(await call(`/api/ciphers/${c.id}`))).deletedDate).toBe(first)
})

it('rate limits purge and removes Sends with the vault', async () => {
  const { s, call } = await setup('purge2@example.com')
  const user = await env.DB.prepare('select uuid from users where email = ?')
    .bind('purge2@example.com')
    .first<{ uuid: string }>()
  const now = Date.now()
  await env.DB.prepare(
    'insert into sends (uuid, user_uuid, name, atype, data, akey, deletion_date, created_at, updated_at) values (?,?,?,?,?,?,?,?,?)',
  )
    .bind(crypto.randomUUID(), user?.uuid, '2.s', 0, '{}', '2.k', now + 1e9, now, now)
    .run()
  const blocked = await withEnv(
    { LOGIN_LIMITER: { limit: async () => ({ success: false }) } },
    '/api/ciphers/purge',
    {
      method: 'POST',
      headers: { Authorization: `Bearer ${s.access_token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ masterPasswordHash: 'client-derived-hash' }),
    },
  )
  expect(blocked.status).toBe(429)
  const left = () =>
    env.DB.prepare('select count(*) as n from sends where user_uuid = ?')
      .bind(user?.uuid)
      .first<{ n: number }>()
  expect((await left())?.n).toBe(1)
  expect(
    (await call('/api/ciphers/purge', 'POST', { masterPasswordHash: 'client-derived-hash' }))
      .status,
  ).toBe(200)
  expect((await left())?.n).toBe(0)
})

it('keeps omitted domain fields when updating', async () => {
  const { call } = await setup('dom2@example.com')
  const first = (await j(await call('/api/settings/domains'))).globalEquivalentDomains[0].type
  await call('/api/settings/domains', 'PUT', {
    equivalentDomains: [['a.example.com', 'b.example.com']],
    excludedGlobalEquivalentDomains: [first],
  })
  const onlyExcluded = await j(
    await call('/api/settings/domains', 'PUT', { excludedGlobalEquivalentDomains: [] }),
  )
  expect(onlyExcluded.equivalentDomains).toEqual([['a.example.com', 'b.example.com']])
  expect(onlyExcluded.globalEquivalentDomains.every((g: any) => !g.excluded)).toBe(true)
  const onlyDomains = await j(await call('/api/settings/domains', 'PUT', { equivalentDomains: [] }))
  expect(onlyDomains.equivalentDomains).toEqual([])
})

it('caps the size of an import', async () => {
  const { call } = await setup('cap@example.com')
  const many = Array.from({ length: 7001 }, () => note())
  expect((await call('/api/ciphers/import', 'POST', { folders: [], ciphers: many })).status).toBe(
    400,
  )
  const folders = Array.from({ length: 801 }, (_, n) => ({ name: `2.f${n}` }))
  expect((await call('/api/ciphers/import', 'POST', { folders, ciphers: [] })).status).toBe(400)
  const ok = Array.from({ length: 300 }, () => note())
  expect((await call('/api/ciphers/import', 'POST', { folders: [], ciphers: ok })).status).toBe(200)
  expect((await j(await call('/api/ciphers'))).data).toHaveLength(300)
})

it('imports several thousand items in sequential batches', async () => {
  const { call } = await setup('bigimport@example.com')
  const folders = [{ name: '2.f0' }, { name: '2.f1' }]
  const items = Array.from({ length: 1500 }, (_, i) => ({
    type: 2,
    name: `2.n${i}`,
    secureNote: { type: 0 },
  }))
  const folderRelationships = items.map((_, i) => ({ key: i, value: i % 2 }))
  const res = await call('/api/ciphers/import', 'POST', {
    folders,
    ciphers: items,
    folderRelationships,
  })
  expect(res.status).toBe(200)
  const sync = await j(await call('/api/sync'))
  expect(sync.ciphers).toHaveLength(1500)
  expect(sync.ciphers.filter((x: { folderId: string | null }) => x.folderId).length).toBe(1500)
})
