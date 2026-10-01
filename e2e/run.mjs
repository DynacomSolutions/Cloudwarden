// End-to-end run with the official Bitwarden CLI against a local dev server (TASKS #181).
// Usage: pnpm e2e
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { migrateLocal } from '../scripts/local-migrate.mjs'
import { buildAccount } from './crypto.mjs'
import { makeCert } from './tls-proxy.mjs'

const root = resolve(import.meta.dirname, '..')
const bin = (name) => join(root, 'node_modules', '.bin', name)
const PASSWORD = 'correct horse battery staple 1'
const EMAIL = `e2e-${Date.now()}@example.com`

function freePort() {
  return new Promise((ok, fail) => {
    const srv = createServer()
    srv.once('error', fail)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => ok(port))
    })
  })
}

let step = 0
const pass = (name) => console.log(`ok ${++step} - ${name}`)

function run(cmd, args, opts = {}) {
  const res = spawnSync(cmd, args, { encoding: 'utf8', cwd: root, ...opts })
  if (res.status !== 0 && !opts.allowFail) {
    throw new Error(`${cmd} ${args.join(' ')} exited ${res.status}\n${res.stdout}\n${res.stderr}`)
  }
  return res
}

async function main() {
  const port = await freePort()
  const tlsPort = await freePort()
  const base = `https://127.0.0.1:${tlsPort}` // what the CLI talks to
  const direct = `http://127.0.0.1:${port}` // what this script talks to
  const work = mkdtempSync(join(tmpdir(), 'cloudwarden-e2e-'))
  const tls = makeCert(work)
  // The Vite dev server persists local D1, R2 and DO state here, so migrate the same directory.
  const state = join(root, '.cloudflare', 'state')
  const env = {
    ...process.env,
    SIGNUPS_ALLOWED: 'true',
    LOCAL_DEV_SECRETS: 'true',
    JWT_SECRET: 'e2e-only-secret-e2e-only-secret-0123456789',
    DEPLOY_DOMAIN: `127.0.0.1:${tlsPort}`,
    NODE_EXTRA_CA_CERTS: tls.cert,
  }

  // Local D1 migrations through the cf CLI.
  await migrateLocal(root, env, state)
  pass('local D1 migrations applied with cf')

  const server = spawn(
    bin('vite'),
    ['dev', '--port', String(port), '--host', '127.0.0.1', '--strictPort'],
    {
      cwd: root,
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true, // own process group, so workerd children die with it
    },
  )
  let serverLog = ''
  server.stdout.on('data', (d) => {
    serverLog += d
  })
  server.stderr.on('data', (d) => {
    serverLog += d
  })
  const proxy = spawn(
    process.execPath,
    [join(root, 'e2e', 'tls-proxy.mjs'), work, String(tlsPort), String(port)],
    {
      stdio: 'inherit',
    },
  )
  const killGroup = (signal) => {
    try {
      process.kill(-server.pid, signal)
    } catch {}
  }
  const stop = () => {
    proxy.kill('SIGKILL')
    killGroup('SIGKILL')
  }
  // Ask Vite to shut down first: it stops workerd itself, which a plain kill leaves running.
  const stopGracefully = async () => {
    proxy.kill('SIGKILL')
    const exited = new Promise((ok) => server.once('exit', ok))
    server.kill('SIGINT')
    await Promise.race([exited, sleep(10000)])
    killGroup('SIGKILL')
  }
  process.on('exit', stop)

  try {
    for (let i = 0; ; i++) {
      try {
        if ((await fetch(`${direct}/alive`)).ok) break
      } catch {}
      if (i > 120) throw new Error(`dev server did not start\n${serverLog}`)
      await sleep(500)
    }
    pass(`dev server up behind a local TLS proxy on ${base}`)

    const bwEnv = {
      ...env,
      BITWARDENCLI_APPDATA_DIR: join(work, 'bw'),
      BW_NOINTERACTION: 'true',
      BW_PASSWORD: PASSWORD,
    }
    const bw = (args, opts = {}) => run(bin('bw'), args, { env: bwEnv, ...opts })
    const bwOut = (args, opts) => bw(args, opts).stdout.trim()
    const encode = (obj) => bwOut(['encode'], { input: JSON.stringify(obj) })

    bw(['config', 'server', base])
    pass('bw config server')

    // bw has no register command: register over HTTP with client-side key derivation.
    const acct = await buildAccount(EMAIL, PASSWORD)
    const reg = await fetch(`${direct}/identity/accounts/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(acct.body),
    })
    assert.equal(reg.status, 200, await reg.text())
    pass('register via HTTP')

    let session = bwOut(['login', EMAIL, '--passwordenv', 'BW_PASSWORD', '--raw'])
    assert.ok(session.length > 20)
    const status = () => JSON.parse(bwOut(['status', '--session', session]))
    assert.equal(status().status, 'unlocked')
    assert.equal(status().userEmail, EMAIL)
    pass('bw login (password grant)')

    const sync = bwOut(['sync', '--session', session])
    assert.match(sync, /Syncing complete/)
    pass('bw sync')

    const S = ['--session', session]
    const folder = JSON.parse(bwOut(['create', 'folder', encode({ name: 'e2e folder' }), ...S]))
    assert.ok(folder.id)
    assert.equal(folder.name, 'e2e folder')
    assert.ok(JSON.parse(bwOut(['list', 'folders', ...S])).some((f) => f.id === folder.id))
    pass('create + list folder')

    const item = {
      organizationId: null,
      collectionIds: null,
      folderId: folder.id,
      type: 1,
      name: 'e2e login',
      notes: 'secret note',
      favorite: false,
      fields: [{ name: 'field1', value: 'v1', type: 0 }],
      login: {
        uris: [{ match: null, uri: 'https://example.com' }],
        username: 'alice',
        password: 'p4ssw0rd!',
        totp: null,
      },
      reprompt: 0,
    }
    const created = JSON.parse(bwOut(['create', 'item', encode(item), ...S]))
    assert.ok(created.id)
    assert.equal(created.login.username, 'alice')
    assert.equal(created.login.password, 'p4ssw0rd!')
    assert.equal(created.folderId, folder.id)
    pass('create login item (decrypts back to what was sent)')

    const listed = JSON.parse(bwOut(['list', 'items', '--search', 'e2e login', ...S]))
    assert.equal(listed.length, 1)
    assert.equal(listed[0].id, created.id)
    assert.equal(bwOut(['get', 'password', created.id, ...S]), 'p4ssw0rd!')
    pass('list + get item')

    const edited = JSON.parse(
      bwOut([
        'edit',
        'item',
        created.id,
        encode({
          ...created,
          name: 'e2e login edited',
          login: { ...created.login, password: 'n3w-p4ss' },
        }),
        ...S,
      ]),
    )
    assert.equal(edited.name, 'e2e login edited')
    assert.equal(bwOut(['get', 'password', created.id, ...S]), 'n3w-p4ss')
    pass('edit item')

    // Attachment upload and download.
    const payload = join(work, 'payload.bin')
    const bytes = Buffer.from(Array.from({ length: 70000 }, (_, i) => (i * 7) % 256))
    writeFileSync(payload, bytes)
    const withAtt = JSON.parse(
      bwOut(['create', 'attachment', '--file', payload, '--itemid', created.id, ...S]),
    )
    assert.equal(withAtt.attachments.length, 1)
    const out = join(work, 'downloaded.bin')
    bw([
      'get',
      'attachment',
      withAtt.attachments[0].id,
      '--itemid',
      created.id,
      '--output',
      out,
      ...S,
    ])
    assert.ok(readFileSync(out).equals(bytes), 'downloaded attachment differs')
    pass('attachment upload + download (byte-identical)')
    bw(['delete', 'attachment', withAtt.attachments[0].id, '--itemid', created.id, ...S])
    pass('attachment delete')

    // Send (text).
    const send = JSON.parse(
      bwOut([
        'send',
        'create',
        encode({
          name: 'e2e send',
          notes: null,
          type: 0,
          text: { text: 'send body', hidden: false },
          deletionDate: new Date(Date.now() + 86400000).toISOString(),
          maxAccessCount: null,
          disabled: false,
          hideEmail: false,
        }),
        ...S,
      ]),
    )
    assert.ok(send.id && send.accessUrl)
    assert.ok(JSON.parse(bwOut(['send', 'list', ...S])).some((s) => s.id === send.id))
    const received = bwOut(['send', 'receive', send.accessUrl])
    assert.equal(received, 'send body')
    pass('send create + list + receive (text)')
    bw(['send', 'delete', send.id, ...S])
    pass('send delete')

    // Soft delete, trash listing, restore, then permanent delete.
    bw(['delete', 'item', created.id, ...S])
    assert.equal(
      JSON.parse(bwOut(['list', 'items', '--search', 'e2e login edited', ...S])).length,
      0,
    )
    assert.equal(JSON.parse(bwOut(['list', 'items', '--trash', ...S])).length, 1)
    pass('delete item (to trash)')
    bw(['restore', 'item', created.id, ...S])
    assert.equal(
      JSON.parse(bwOut(['list', 'items', '--search', 'e2e login edited', ...S])).length,
      1,
    )
    pass('restore item')
    bw(['delete', 'item', created.id, '--permanent', ...S])
    assert.equal(JSON.parse(bwOut(['list', 'items', '--trash', ...S])).length, 0)
    bw(['delete', 'folder', folder.id, ...S])
    assert.ok(!JSON.parse(bwOut(['list', 'folders', ...S])).some((f) => f.id === folder.id))
    pass('permanent delete item + delete folder')

    bw(['logout'])
    assert.equal(JSON.parse(bwOut(['status'])).status, 'unauthenticated')
    pass('bw logout')

    // API key re-login (client_credentials). The key is read with the account password hash.
    const tokenRes = await fetch(`${direct}/identity/connect/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        username: EMAIL,
        password: acct.masterPasswordHash,
        scope: 'api offline_access',
        client_id: 'cli',
        deviceType: '8',
        deviceName: 'e2e',
        deviceIdentifier: crypto.randomUUID(),
      }),
    })
    assert.equal(tokenRes.status, 200, await tokenRes.clone().text())
    const { access_token: access } = await tokenRes.json()
    const keyRes = await fetch(`${direct}/api/accounts/api-key`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${access}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ masterPasswordHash: acct.masterPasswordHash }),
    })
    assert.equal(keyRes.status, 200, await keyRes.clone().text())
    const { apiKey } = await keyRes.json()
    const profile = await (
      await fetch(`${direct}/api/accounts/profile`, {
        headers: { Authorization: `Bearer ${access}` },
      })
    ).json()
    const apiEnv = { ...bwEnv, BW_CLIENTID: `user.${profile.id}`, BW_CLIENTSECRET: apiKey }
    bw(['login', '--apikey'], { env: apiEnv })
    assert.equal(JSON.parse(bwOut(['status'])).status, 'locked')
    session = bwOut(['unlock', '--passwordenv', 'BW_PASSWORD', '--raw'])
    assert.match(bwOut(['sync', '--session', session]), /Syncing complete/)
    assert.equal(JSON.parse(bwOut(['status', '--session', session])).status, 'unlocked')
    pass('bw login --apikey (client_credentials), unlock, sync')
    bw(['logout'])

    // Registration the way web vault 2026.9 does it: verification email request, then the nested finish body.
    const email2 = `e2e-nested-${Date.now()}@example.com`
    const acct2 = await buildAccount(email2, PASSWORD)
    const sendRes = await fetch(`${direct}/identity/accounts/register/send-verification-email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: email2, name: 'Nested User', receiveMarketingEmails: false }),
    })
    // 200 carries the token (no mail transport); 204 means it was emailed, and signups are open anyway.
    assert.ok([200, 204].includes(sendRes.status), `send-verification-email ${sendRes.status}`)
    const verificationToken = sendRes.status === 200 ? await sendRes.json() : undefined
    const finish = await fetch(`${direct}/identity/accounts/register/finish`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...acct2.nestedBody, emailVerificationToken: verificationToken }),
    })
    assert.equal(finish.status, 200, await finish.text())
    session = bwOut(['login', email2, '--passwordenv', 'BW_PASSWORD', '--raw'])
    assert.match(bwOut(['sync', '--session', session]), /Syncing complete/)
    const nestedFolder = JSON.parse(
      bwOut(['create', 'folder', encode({ name: 'nested' }), '--session', session]),
    )
    assert.equal(nestedFolder.name, 'nested')
    pass('register via nested register/finish shape, then bw login, sync and create')
    bw(['logout'])
    console.log(`\n${step} steps passed`)
  } catch (err) {
    console.error(`--- dev server output ---\n${serverLog.slice(-4000)}`)
    throw err
  } finally {
    await stopGracefully()
    rmSync(work, { recursive: true, force: true })
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
