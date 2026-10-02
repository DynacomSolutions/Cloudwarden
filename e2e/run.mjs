// End-to-end run with the official Bitwarden CLI against a local dev server (TASKS #181).
// Usage: pnpm e2e
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { loginAndUnlock } from '../scripts/import-from-server.mjs'
import { migrateLocal } from '../scripts/local-migrate.mjs'
import { ensureBws } from './bws.mjs'
import { buildAccount, decType2, encType2, encType4 } from './crypto.mjs'
import { deriveAccessTokenKey } from './sm-client.mjs'
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
    NODE_EXTRA_CA_CERTS: tls.ca,
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

    // New device verification (TASKS #260): the dev server has a mail binding, so a second device
    // needs an emailed code. The simulated mailbox is unreadable here, so opt out with the master
    // password, as a user may, and check the client-visible answer on the way.
    const deviceLogin = (identifier) =>
      fetchRetry(`${direct}/identity/connect/token`, {
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
          deviceIdentifier: identifier,
        }),
      })
    const first = await deviceLogin(crypto.randomUUID())
    assert.equal(first.status, 200, await first.clone().text())
    const gated = await deviceLogin(crypto.randomUUID())
    assert.equal(gated.status, 400)
    assert.equal((await gated.json()).ErrorModel.Message, 'new device verification required')
    const optOut = await fetchRetry(`${direct}/api/accounts/verify-devices`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${(await first.json()).access_token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ masterPasswordHash: acct.masterPasswordHash, verifyDevices: false }),
    })
    assert.equal(optOut.status, 200, await optOut.clone().text())
    assert.equal((await deviceLogin(crypto.randomUUID())).status, 200)
    pass('new device verification gates a second device until the account opts out')

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

    // Password-protected Send: the CLI runs the send_access grant, so this covers the
    // password_hash_b64_required and _invalid error shapes the SDK reads.
    const guarded = JSON.parse(
      bwOut([
        'send',
        'create',
        encode({
          name: 'e2e guarded send',
          notes: null,
          type: 0,
          text: { text: 'guarded body', hidden: false },
          deletionDate: new Date(Date.now() + 400 * 86400000).toISOString(),
          maxAccessCount: null,
          disabled: false,
          hideEmail: false,
          authType: 1,
          password: 's3cret-pass',
        }),
        ...S,
      ]),
    )
    assert.ok(guarded.id && guarded.accessUrl)
    // Wrong password first: the CLI may reuse a send_access token it already holds for this Send,
    // so a refusal can only be judged before a right password has been accepted.
    const refused = bw(['send', 'receive', guarded.accessUrl, '--password', 'wrong'], {
      allowFail: true,
    })
    assert.ok(
      !`${refused.stdout}`.includes('guarded body'),
      `wrong password must not reveal the Send: ${refused.stdout} ${refused.stderr}`,
    )
    assert.equal(
      bwOut(['send', 'receive', guarded.accessUrl, '--password', 's3cret-pass']),
      'guarded body',
    )
    pass('password Send receive (right and wrong password, 400 day deletion date)')
    bw(['send', 'delete', guarded.id, ...S])

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
    const tokenRes = await fetchRetry(`${direct}/identity/connect/token`, {
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

    // Secrets Manager (TASKS #220). Admin setup over HTTP with client-side encryption, then a
    // machine client (e2e/sm-client.mjs, built from the GPL SDK contract) reads through TLS.
    const owner = await passwordLogin(direct, EMAIL, acct.masterPasswordHash)
    const api = async (path, method = 'GET', body) => {
      const res = await fetchRetry(`${direct}/api${path}`, {
        method,
        headers: { Authorization: `Bearer ${owner}`, 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
      })
      assert.ok(res.ok, `${method} ${path}: ${res.status} ${await res.clone().text()}`)
      const text = await res.text()
      return text ? JSON.parse(text) : null
    }
    const orgKey = randomBytes(64)
    const encOrg = (text) => encType2(Buffer.from(text), orgKey)
    const smOrg = await api('/organizations', 'POST', {
      name: 'E2E SM Org',
      billingEmail: 'billing@example.com',
      key: await encType4(orgKey, acct.body.keys.publicKey),
      keys: { publicKey: 'e2e-org-public', encryptedPrivateKey: await encOrg('org-private') },
      planType: 0,
    })
    assert.equal(smOrg.useSecretsManager, true)
    const project = await api(`/organizations/${smOrg.id}/projects`, 'POST', {
      name: await encOrg('deploy'),
    })
    const secret = await api(`/organizations/${smOrg.id}/secrets`, 'POST', {
      key: await encOrg('DATABASE_URL'),
      value: await encOrg('postgres://db.example.com/app'),
      note: await encOrg('rotated monthly'),
      projectIds: [project.id],
    })
    const hidden = await api(`/organizations/${smOrg.id}/secrets`, 'POST', {
      key: await encOrg('UNRELATED'),
      value: await encOrg('not for the machine'),
      note: '',
    })
    pass('Secrets Manager: organisation, project and secrets created via API')

    const sa = await api(`/organizations/${smOrg.id}/service-accounts`, 'POST', {
      name: await encOrg('ci machine'),
    })
    await api(`/projects/${project.id}/access-policies/service-accounts`, 'PUT', {
      serviceAccountAccessPolicyRequests: [{ granteeId: sa.id, read: true, write: false }],
    })
    const seed = randomBytes(16)
    const smToken = await api(`/service-accounts/${sa.id}/access-tokens`, 'POST', {
      name: await encOrg('ci token'),
      encryptedPayload: await encType2(
        Buffer.from(JSON.stringify({ encryptionKey: orgKey.toString('base64') })),
        deriveAccessTokenKey(seed),
      ),
      key: await encOrg(seed.toString('base64')),
      expireAt: null,
    })
    const accessToken = `0.${smToken.id}.${smToken.clientSecret}:${seed.toString('base64')}`
    pass('Secrets Manager: machine account, project grant and access token')

    const sm = (args, opts) =>
      run(process.execPath, [join(root, 'e2e', 'sm-client.mjs'), base, accessToken, ...args], {
        env,
        ...opts,
      })
    const listedSecrets = JSON.parse(sm(['list', smOrg.id]).stdout)
    assert.deepEqual(listedSecrets, [
      {
        id: secret.id,
        organizationId: smOrg.id,
        projectId: project.id,
        key: 'DATABASE_URL',
        value: 'postgres://db.example.com/app',
        note: 'rotated monthly',
      },
    ])
    assert.equal(JSON.parse(sm(['get', secret.id]).stdout).value, 'postgres://db.example.com/app')
    const denied = sm(['get', hidden.id], { allowFail: true })
    assert.notEqual(denied.status, 0)
    assert.match(denied.stderr, /404/)
    pass(
      'Secrets Manager: machine login over TLS, secret list and get decrypt; ungranted secret 404',
    )

    const synced = JSON.parse(sm(['sync', smOrg.id]).stdout)
    assert.equal(synced.hasChanges, true)
    assert.equal(synced.secrets.length, 1)
    const later = new Date(Date.now() + 60_000).toISOString()
    assert.deepEqual(JSON.parse(sm(['sync', smOrg.id, later]).stdout), {
      hasChanges: false,
      secrets: null,
    })
    pass('Secrets Manager: sync with and without lastSyncedDate')

    await api(`/service-accounts/${sa.id}/access-tokens/revoke`, 'POST', { ids: [smToken.id] })
    const revoked = sm(['list', smOrg.id], { allowFail: true })
    assert.notEqual(revoked.status, 0)
    assert.match(revoked.stderr, /login failed: 400/)
    pass('Secrets Manager: revoked token can no longer log in')

    // The official `bws` CLI (TASKS #225, pinned in e2e/bws.lock.json) with a machine token that may write.
    const bwsBin = await ensureBws()
    pass('bws: pinned release downloaded and sha256 verified')
    const writer = await api(`/organizations/${smOrg.id}/service-accounts`, 'POST', {
      name: await encOrg('bws machine'),
    })
    await api(`/projects/${project.id}/access-policies/service-accounts`, 'PUT', {
      serviceAccountAccessPolicyRequests: [{ granteeId: writer.id, read: true, write: true }],
    })
    const bwsSeed = randomBytes(16)
    const bwsTok = await api(`/service-accounts/${writer.id}/access-tokens`, 'POST', {
      name: await encOrg('bws token'),
      encryptedPayload: await encType2(
        Buffer.from(JSON.stringify({ encryptionKey: orgKey.toString('base64') })),
        deriveAccessTokenKey(bwsSeed),
      ),
      key: await encOrg(bwsSeed.toString('base64')),
      expireAt: null,
    })
    const bwsEnv = {
      PATH: process.env.PATH,
      HOME: work,
      BWS_CONFIG_FILE: join(work, 'bws-config'),
      BWS_ACCESS_TOKEN: `0.${bwsTok.id}.${bwsTok.clientSecret}:${bwsSeed.toString('base64')}`,
      BWS_SERVER_URL: base,
      SSL_CERT_FILE: tls.ca, // the proxy's throwaway CA
    }
    const bws = (args, opts) => run(bwsBin, args, { env: bwsEnv, ...opts })
    const bwsJson = (args) => JSON.parse(bws(args).stdout)

    const projects = bwsJson(['project', 'list'])
    assert.deepEqual(
      projects.map((p) => [p.id, p.name, p.organizationId]),
      [[project.id, 'deploy', smOrg.id]],
    )
    const bwsList = bwsJson(['secret', 'list'])
    assert.deepEqual(
      bwsList.map((s) => [s.id, s.key, s.value]),
      [[secret.id, 'DATABASE_URL', 'postgres://db.example.com/app']],
    )
    pass('bws: project list and secret list over TLS (decrypted)')

    const got = bwsJson(['secret', 'get', secret.id])
    assert.equal(got.value, 'postgres://db.example.com/app')
    assert.equal(got.note, 'rotated monthly')
    assert.equal(got.projectId, project.id)
    assert.notEqual(bws(['secret', 'get', hidden.id], { allowFail: true }).status, 0)
    pass('bws: secret get decrypts value and note; ungranted secret refused')

    const made = bwsJson(['secret', 'create', 'API_KEY', 'v1-value', project.id, '--note', 'n1'])
    assert.equal(made.key, 'API_KEY')
    assert.equal(made.value, 'v1-value')
    assert.equal(bwsJson(['secret', 'get', made.id]).note, 'n1')
    pass('bws: secret create')

    const edit = bwsJson(['secret', 'edit', made.id, '--value', 'v2-value', '--key', 'API_KEY_2'])
    assert.equal(edit.value, 'v2-value')
    const again = bwsJson(['secret', 'get', made.id])
    assert.equal(again.key, 'API_KEY_2')
    assert.equal(again.value, 'v2-value')
    assert.equal(again.note, 'n1')
    pass('bws: secret edit')

    bws(['secret', 'delete', made.id])
    assert.ok(!bwsJson(['secret', 'list']).some((s) => s.id === made.id))
    pass('bws: secret delete')

    // Importer (TASKS #163): copy the personal vault of the account above into a new account
    // on the same server, through the public API only, then check the copy decrypts identically.
    const copyEmail = `import-${Date.now()}@example.com`
    const copyEnv = { ...env, SOURCE_PASSWORD: PASSWORD }
    const importer = await loginAndUnlock(direct, EMAIL, PASSWORD, {
      deviceIdentifier: 'e2e-importer-device',
    })
    const sealed = async (text) => encType2(Buffer.from(text), importer.userKey)
    const post = async (path, body) =>
      fetchRetry(`${direct}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${importer.accessToken}`,
        },
        body: JSON.stringify(body),
      })
    const copyFolder = await (await post('/api/folders', { name: await sealed('Imported') })).json()
    for (const name of ['Import one', 'Import two']) {
      const made = await post('/api/ciphers', {
        type: 1,
        name: await sealed(name),
        folderId: copyFolder.id,
        login: { username: await sealed('user'), password: await sealed('pw'), uris: [] },
      })
      assert.equal(made.status, 200, await made.text())
    }
    const imported = run(
      process.execPath,
      [
        join(root, 'scripts', 'import-from-server.mjs'),
        '--source',
        direct,
        '--source-email',
        EMAIL,
        '--target',
        direct,
        '--target-email',
        copyEmail,
        '--register',
        '--device-id',
        'e2e-importer-device',
      ],
      { env: copyEnv },
    )
    assert.match(imported.stdout, /Import finished/)
    const device = { deviceIdentifier: 'e2e-importer-device' }
    const from = await loginAndUnlock(direct, EMAIL, PASSWORD, device)
    const to = await loginAndUnlock(direct, copyEmail, PASSWORD, device)
    const syncOf = async (session) =>
      await (
        await fetchRetry(`${direct}/api/sync`, {
          headers: { Authorization: `Bearer ${session.accessToken}` },
        })
      ).json()
    const [before, after] = [await syncOf(from), await syncOf(to)]
    const personal = (sync) => sync.ciphers.filter((c) => !c.organizationId && !c.deletedDate)
    assert.ok(personal(before).length > 0)
    assert.equal(personal(after).length, personal(before).length)
    const names = async (sync, key) =>
      (
        await Promise.all(personal(sync).map(async (c) => (await decType2(c.name, key)).toString()))
      ).sort()
    assert.deepEqual(await names(after, to.userKey), await names(before, from.userKey))
    pass('importer: personal vault copied to a new account and decrypts identically')

    console.log(`\n${step} steps passed`)
  } catch (err) {
    console.error(`--- dev server output ---\n${serverLog.slice(-4000)}`)
    throw err
  } finally {
    await stopGracefully()
    rmSync(work, { recursive: true, force: true })
  }
}

/**
 * `fetch` that retries once when the dev server closed an idle keep-alive socket just as it was
 * reused (undici reports `UND_ERR_SOCKET`).
 */
async function fetchRetry(url, init) {
  try {
    return await fetch(url, init)
  } catch (err) {
    if (err?.cause?.code !== 'UND_ERR_SOCKET') throw err
    return fetch(url, init)
  }
}

/** Password grant over HTTP; returns the access token. */
async function passwordLogin(server, email, masterPasswordHash) {
  const res = await fetchRetry(`${server}/identity/connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      username: email,
      password: masterPasswordHash,
      scope: 'api offline_access',
      client_id: 'cli',
      deviceType: '8',
      deviceName: 'e2e',
      deviceIdentifier: crypto.randomUUID(),
    }),
  })
  assert.equal(res.status, 200, await res.clone().text())
  return (await res.json()).access_token
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
