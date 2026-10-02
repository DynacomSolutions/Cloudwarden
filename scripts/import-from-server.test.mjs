import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { createServer } from 'node:http'
import { test } from 'node:test'
import { buildAccount, decType2, encType2 } from '../e2e/crypto.mjs'
import {
  authHash,
  buildImport,
  checkServerUrl,
  chunkImport,
  deriveMasterKey,
  loginAndUnlock,
  main,
  stretch,
  TwoFactorRequired,
} from './import-from-server.mjs'

const EMAIL = 'someone@example.com'
const PASSWORD = 'correct horse battery staple 1'
const ITERATIONS = 5000

/** A tiny server speaking the public client API endpoints the importer uses. */
async function fakeServer(state) {
  const server = createServer(async (req, res) => {
    const chunks = []
    for await (const c of req) chunks.push(c)
    const raw = Buffer.concat(chunks).toString()
    const url = new URL(req.url, 'http://x')
    const send = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(body))
    }
    state.log.push(`${req.method} ${url.pathname}`)
    if (url.pathname === '/identity/accounts/prelogin') {
      return send(200, { kdf: 0, kdfIterations: ITERATIONS })
    }
    if (url.pathname === '/identity/connect/token') {
      const form = new URLSearchParams(raw)
      if (state.twoFactor && form.get('twoFactorToken') !== state.twoFactor) {
        return send(400, { error: 'invalid_grant', TwoFactorProviders: ['0'] })
      }
      if (state.newDevice && form.get('newDeviceOtp') !== state.newDevice) {
        return send(400, {
          error: 'invalid_grant',
          error_description: 'new device verification required',
        })
      }
      const account = state.account
      if (!account || form.get('password') !== account.masterPasswordHash) {
        return send(400, { error: 'invalid_grant', error_description: 'bad credentials' })
      }
      return send(200, {
        access_token: 'tok',
        Key: account.body.key,
        PrivateKey: account.body.keys.encryptedPrivateKey,
      })
    }
    if (url.pathname === '/api/sync') return send(200, state.sync)
    if (url.pathname === '/identity/accounts/register') {
      state.registered = JSON.parse(raw)
      return send(200, { object: 'register' })
    }
    if (url.pathname === '/api/ciphers/import') {
      state.imports.push(JSON.parse(raw))
      return send(200, {})
    }
    return send(404, {})
  })
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok))
  state.url = `http://127.0.0.1:${server.address().port}`
  state.close = () => server.close()
  return state
}

async function vaultFor(userKey) {
  const enc = (s) => encType2(Buffer.from(s), userKey)
  const itemKey = randomBytes(64)
  const withKey = async (s) => encType2(Buffer.from(s), itemKey)
  return {
    profile: { name: 'Someone' },
    folders: [{ id: 'f1', name: await enc('Work') }],
    ciphers: [
      {
        id: 'c1',
        type: 1,
        folderId: 'f1',
        name: await enc('Example login'),
        notes: await enc('a note'),
        favorite: true,
        reprompt: 0,
        login: {
          username: await enc('me'),
          password: await enc('hunter2'),
          uris: [{ uri: await enc('https://example.com'), match: null }],
        },
        fields: [{ name: await enc('pin'), value: await enc('1234'), type: 1 }],
      },
      {
        id: 'c2',
        type: 2,
        folderId: null,
        key: await encType2(itemKey, userKey),
        name: await withKey('Keyed note'),
        secureNote: { type: 0 },
      },
      { id: 'c3', type: 1, organizationId: 'org', name: await enc('Org item') },
      { id: 'c4', type: 1, deletedDate: '2026-01-01T00:00:00Z', name: await enc('Trashed') },
    ],
  }
}

async function setup() {
  const account = await buildAccount(EMAIL, PASSWORD, ITERATIONS)
  const masterKey = await deriveMasterKey(EMAIL, PASSWORD, { kdf: 0, kdfIterations: ITERATIONS })
  const userKey = await decType2(account.body.key, stretch(masterKey))
  const source = await fakeServer({ account, log: [], imports: [] })
  source.sync = await vaultFor(userKey)
  return { account, userKey, source }
}

test('derives the master key and authentication hash as the clients do', async () => {
  const key = await deriveMasterKey(EMAIL, PASSWORD, { kdf: 0, kdfIterations: ITERATIONS })
  const account = await buildAccount(EMAIL, PASSWORD, ITERATIONS)
  assert.equal(await authHash(key, PASSWORD), account.masterPasswordHash)
  // Email is trimmed and lower-cased for the salt.
  const same = await deriveMasterKey(` ${EMAIL.toUpperCase()} `, PASSWORD, {
    kdf: 0,
    kdfIterations: ITERATIONS,
  })
  assert.ok(key.equals(same))
  const argon = await deriveMasterKey(EMAIL, PASSWORD, {
    kdf: 1,
    kdfIterations: 2,
    kdfMemory: 16,
    kdfParallelism: 1,
  })
  assert.equal(argon.length, 32)
  assert.ok(!argon.equals(key))
})

test('logs in, unlocks the vault and reports a wrong password or missing two-factor', async () => {
  const { source, userKey } = await setup()
  try {
    const session = await loginAndUnlock(source.url, EMAIL, PASSWORD)
    assert.ok(session.userKey.equals(userKey))
    await assert.rejects(loginAndUnlock(source.url, EMAIL, 'wrong'), /login failed/)
    source.twoFactor = '123456'
    await assert.rejects(loginAndUnlock(source.url, EMAIL, PASSWORD), TwoFactorRequired)
    const ok = await loginAndUnlock(source.url, EMAIL, PASSWORD, { provider: 0, token: '123456' })
    assert.ok(ok.userKey.equals(userKey))
  } finally {
    source.close()
  }
})

test('re-encrypts items for a different user key and keeps item keys intact', async () => {
  const { source, userKey } = await setup()
  try {
    const target = randomBytes(64)
    const built = await buildImport(source.sync, userKey, target)
    assert.equal(built.ciphers.length, 2)
    assert.equal(built.organisation, 1)
    assert.equal(built.trashed, 1)
    assert.deepEqual(built.folderRelationships, [{ key: 0, value: 0 }])
    const text = async (s, key) => (await decType2(s, key)).toString()
    assert.equal(await text(built.folders[0].name, target), 'Work')
    const [login, note] = built.ciphers
    assert.equal(await text(login.login.password, target), 'hunter2')
    assert.equal(await text(login.login.uris[0].uri, target), 'https://example.com')
    assert.equal(await text(login.fields[0].value, target), '1234')
    assert.equal(login.fields[0].type, 1)
    assert.equal(login.favorite, true)
    // The item key is re-wrapped; the field stays under the item key.
    const itemKey = await decType2(note.key, target)
    assert.equal(await text(note.name, itemKey), 'Keyed note')
    await assert.rejects(decType2(login.login.password, userKey))
  } finally {
    source.close()
  }
})

test('carries ciphertext over unchanged when both sides share the user key', async () => {
  const { source, userKey } = await setup()
  try {
    const built = await buildImport(source.sync, userKey, userKey)
    assert.equal(built.ciphers[0].login.password, source.sync.ciphers[0].login.password)
    assert.equal(built.folders[0].name, source.sync.folders[0].name)
  } finally {
    source.close()
  }
})

test('splits large imports and keeps each request self contained', () => {
  const ciphers = Array.from({ length: 6001 }, (_, i) => ({ name: String(i) }))
  const folders = [{ name: 'a' }, { name: 'b' }]
  const rel = [
    { key: 0, value: 1 },
    { key: 6000, value: 0 },
  ]
  const parts = chunkImport({ folders, ciphers, folderRelationships: rel })
  assert.equal(parts.length, 2)
  assert.deepEqual(parts[0].folders, [{ name: 'b' }])
  assert.deepEqual(parts[0].folderRelationships, [{ key: 0, value: 0 }])
  assert.deepEqual(parts[1].folders, [{ name: 'a' }])
  assert.deepEqual(parts[1].folderRelationships, [{ key: 0, value: 0 }])
})

test('end to end: registers the target with the same user key and imports the vault', async () => {
  const { source, userKey } = await setup()
  const target = await fakeServer({ log: [], imports: [] })
  const lines = []
  process.env.SOURCE_PASSWORD = PASSWORD
  try {
    // The target "becomes" the registered account for the login that follows registration.
    const realFetch = globalThis.fetch
    globalThis.fetch = async (url, init) => {
      const res = await realFetch(url, init)
      if (String(url).endsWith('/identity/accounts/register') && target.registered) {
        const r = target.registered
        target.account = {
          masterPasswordHash: r.masterPasswordHash,
          body: { key: r.key, keys: r.keys },
        }
      }
      return res
    }
    let code
    try {
      code = await main(
        [
          '--source',
          source.url,
          '--source-email',
          EMAIL,
          '--target',
          target.url,
          '--register',
          '--target-iterations',
          '5000',
        ],
        (l) => lines.push(l),
      )
    } finally {
      globalThis.fetch = realFetch
    }
    assert.equal(code, 0)
    const reg = target.registered
    assert.equal(reg.email, EMAIL)
    // The wrapped key opens with the new master key and is the source user key.
    const masterKey = await deriveMasterKey(EMAIL, PASSWORD, { kdf: 0, kdfIterations: 5000 })
    assert.equal(reg.masterPasswordHash, await authHash(masterKey, PASSWORD))
    assert.ok((await decType2(reg.key, stretch(masterKey))).equals(userKey))
    assert.equal(reg.keys.encryptedPrivateKey, source.account.body.keys.encryptedPrivateKey)
    assert.equal(reg.keys.publicKey, source.account.body.keys.publicKey)
    assert.equal(target.imports.length, 1)
    assert.equal(target.imports[0].ciphers.length, 2)
    assert.equal(target.imports[0].folders.length, 1)
    assert.ok(lines.some((l) => l.includes('Import finished')))
  } finally {
    delete process.env.SOURCE_PASSWORD
    source.close()
    target.close()
  }
})

test('a dry run never touches the target', async () => {
  const { source } = await setup()
  const lines = []
  process.env.SOURCE_PASSWORD = PASSWORD
  try {
    const code = await main(
      [
        '--source',
        source.url,
        '--source-email',
        EMAIL,
        '--target',
        'http://127.0.0.1:1',
        '--dry-run',
      ],
      (l) => lines.push(l),
    )
    assert.equal(code, 0)
    assert.ok(lines.some((l) => l.includes('2 items and 1 folders')))
  } finally {
    delete process.env.SOURCE_PASSWORD
    source.close()
  }
})

test('only https servers, or http on localhost, are accepted', () => {
  assert.equal(checkServerUrl('https://old.example.com/x', 'u'), 'https://old.example.com')
  assert.equal(checkServerUrl('http://127.0.0.1:8787', 'u'), 'http://127.0.0.1:8787')
  assert.equal(checkServerUrl('http://localhost:8787', 'u'), 'http://localhost:8787')
  for (const bad of ['http://old.example.com', 'ftp://127.0.0.1', 'not a url']) {
    assert.throws(() => checkServerUrl(bad, 'u'), bad)
  }
})

test('two-factor codes come from the environment, not arguments', async () => {
  const { source } = await setup()
  source.twoFactor = '654321'
  const lines = []
  process.env.SOURCE_PASSWORD = PASSWORD
  try {
    await assert.rejects(
      main(
        [
          '--source',
          source.url,
          '--source-email',
          EMAIL,
          '--target',
          'http://127.0.0.1:1',
          '--dry-run',
        ],
        (l) => lines.push(l),
      ),
      /SOURCE_2FA_TOKEN/,
    )
    process.env.SOURCE_2FA_TOKEN = '654321'
    const code = await main(
      [
        '--source',
        source.url,
        '--source-email',
        EMAIL,
        '--target',
        'http://127.0.0.1:1',
        '--dry-run',
      ],
      (l) => lines.push(l),
    )
    assert.equal(code, 0)
  } finally {
    delete process.env.SOURCE_PASSWORD
    delete process.env.SOURCE_2FA_TOKEN
    source.close()
  }
})

test('asks for the emailed new device code and sends a fixed device id', async () => {
  const { source } = await setup()
  source.newDevice = '777777'
  process.env.SOURCE_PASSWORD = PASSWORD
  const args = [
    '--source',
    source.url,
    '--source-email',
    EMAIL,
    '--target',
    'http://127.0.0.1:1',
    '--dry-run',
  ]
  try {
    await assert.rejects(
      main(args, () => {}),
      /SOURCE_NEW_DEVICE_CODE/,
    )
    process.env.SOURCE_NEW_DEVICE_CODE = '777777'
    assert.equal(await main([...args, '--device-id', 'fixed-device'], () => {}), 0)
  } finally {
    delete process.env.SOURCE_PASSWORD
    delete process.env.SOURCE_NEW_DEVICE_CODE
    source.close()
  }
})
