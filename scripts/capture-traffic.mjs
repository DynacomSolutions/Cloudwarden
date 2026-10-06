// Records official client traffic against a local dev server and writes sanitised fixtures to
// test/fixtures/traffic/ (TASKS #367). Usage: pnpm capture:traffic
//
// The official Bitwarden CLI (the version pinned in package.json) is driven through a local TLS
// proxy and a recording proxy in front of `vite dev`. Request and response bodies are sanitised
// in memory by scripts/traffic-sanitise.mjs before anything touches disk, and the written files
// are checked again with findIdentifying. See docs/traffic-fixtures.md.
import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createServer, request } from 'node:http'
import { createServer as netServer } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { buildAccount } from '../e2e/crypto.mjs'
import { makeCert, startProxy } from '../e2e/tls-proxy.mjs'
import { migrateLocal } from './local-migrate.mjs'
import { createSanitiser, findIdentifying } from './traffic-sanitise.mjs'

const root = resolve(import.meta.dirname, '..')
const outDir = join(root, 'test', 'fixtures', 'traffic')
const bin = (name) => join(root, 'node_modules', '.bin', name)
const PASSWORD = 'correct horse battery staple 1'
const CLI_VERSION = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).devDependencies[
  '@bitwarden/cli'
]

const freePort = () =>
  new Promise((ok, fail) => {
    const srv = netServer()
    srv.once('error', fail)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => ok(port))
    })
  })

// Request headers worth keeping; everything else (user agent, host, cookies) is dropped.
const KEEP_REQUEST_HEADERS = ['bitwarden-client-name', 'bitwarden-client-version', 'device-type']

let bucket = null // exchanges of the scenario being recorded, or null when not recording

/** Recording proxy: forwards to the dev server and notes every exchange of the open bucket. */
function startRecorder(port, target) {
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks)
      const up = request(
        {
          host: '127.0.0.1',
          port: target,
          method: req.method,
          path: req.url,
          headers: req.headers,
        },
        (upRes) => {
          const out = []
          upRes.on('data', (c) => out.push(c))
          upRes.on('end', () => {
            const resBody = Buffer.concat(out)
            res.writeHead(upRes.statusCode ?? 502, upRes.headers)
            res.end(resBody)
            if (bucket) bucket.push({ req, body, status: upRes.statusCode, upRes, resBody })
          })
        },
      )
      up.on('error', () => {
        res.writeHead(502)
        res.end()
      })
      up.end(body)
    })
  })
  return new Promise((ok) => server.listen(port, '127.0.0.1', () => ok(server)))
}

/** Turns raw recordings into sanitised, replayable exchanges. */
function toFixture(meta, raw) {
  const san = createSanitiser()
  const exchanges = []
  for (const { req, body, status, upRes, resBody } of raw) {
    const path = String(req.url)
    if (!/^\/(api|identity)\//.test(path)) continue
    const reqType = String(req.headers['content-type'] ?? '').split(';')[0]
    const resType = String(upRes.headers['content-type'] ?? '').split(';')[0]
    const headers = {}
    for (const h of KEEP_REQUEST_HEADERS)
      if (req.headers[h]) headers[h] = san.string(String(req.headers[h]), h)
    if (req.headers.authorization) {
      headers.authorization = `Bearer ${san.string(String(req.headers.authorization).replace(/^Bearer /i, ''), 'access_token')}`
    }
    const ex = { method: req.method, path: san.string(path), headers }
    if (body.length) {
      if (reqType === 'application/json')
        ex.requestBody = san.value(JSON.parse(body.toString('utf8')))
      else if (reqType === 'application/x-www-form-urlencoded') {
        ex.requestForm = san.value(Object.fromEntries(new URLSearchParams(body.toString('utf8'))))
      } else continue // multipart uploads are not recorded
    }
    ex.status = status
    if (resBody.length && resType === 'application/json') {
      ex.responseBody = san.value(JSON.parse(resBody.toString('utf8')))
    }
    exchanges.push(ex)
  }
  return { ...meta, exchanges }
}

const run = (cmd, args, env, input) =>
  new Promise((ok) => {
    const child = spawn(cmd, args, { cwd: root, env, stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => {
      stdout += d
    })
    child.stderr.on('data', (d) => {
      stderr += d
    })
    child.on('close', (code) => ok({ exitCode: code, stdout: stdout.trim(), stderr }))
    child.stdin.end(input ?? '')
  })

async function main() {
  const port = await freePort()
  const recPort = await freePort()
  const tlsPort = await freePort()
  const base = `https://127.0.0.1:${tlsPort}`
  const direct = `http://127.0.0.1:${port}`
  const work = mkdtempSync(join(tmpdir(), 'cloudwarden-capture-'))
  const tls = makeCert(work)
  const state = join(root, '.cloudflare', 'state')
  const env = {
    ...process.env,
    SIGNUPS_ALLOWED: 'true',
    LOCAL_DEV_SECRETS: 'true',
    JWT_SECRET: 'capture-only-secret-capture-only-secret-0123456789',
    DEPLOY_DOMAIN: `127.0.0.1:${tlsPort}`,
    NODE_EXTRA_CA_CERTS: tls.ca,
  }
  await migrateLocal(root, env, state)
  const server = spawn(
    bin('vite'),
    ['dev', '--port', String(port), '--host', '127.0.0.1', '--strictPort'],
    { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'], detached: true },
  )
  let log = ''
  for (const s of [server.stdout, server.stderr]) s.on('data', (d) => (log += d))
  const killGroup = (sig) => {
    try {
      process.kill(-server.pid, sig)
    } catch {}
  }
  process.on('exit', () => killGroup('SIGKILL'))
  const recorder = await startRecorder(recPort, port)
  const proxy = await startProxy(tls, tlsPort, recPort)

  try {
    for (let i = 0; ; i++) {
      try {
        if ((await fetch(`${direct}/alive`)).ok) break
      } catch {}
      if (i > 120) throw new Error(`dev server did not start\n${log}`)
      await sleep(500)
    }

    const bwEnv = {
      ...env,
      BITWARDENCLI_APPDATA_DIR: join(work, 'bw'),
      BW_NOINTERACTION: 'true',
      BW_PASSWORD: PASSWORD,
    }
    const bw = async (args, input) => {
      const r = await run(bin('bw'), args, bwEnv, input)
      return r
    }
    const bwOk = async (args, input) => {
      const r = await bw(args, input)
      if (r.exitCode !== 0) throw new Error(`bw ${args.slice(0, 2).join(' ')} failed: ${r.stderr}`)
      return r.stdout
    }
    const encode = (obj) => bwOk(['encode'], JSON.stringify(obj))

    // A fresh account per scenario, registered over HTTP (the CLI cannot register), with new
    // device verification switched off so the CLI's own device may log in. Not recorded.
    const freshAccount = async (tag) => {
      const email = `capture-${tag}-${Date.now()}@example.com`
      const acct = await buildAccount(email, PASSWORD)
      const reg = await fetch(`${direct}/identity/accounts/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(acct.body),
      })
      if (!reg.ok) throw new Error(`register ${reg.status}`)
      const login = (id) =>
        fetch(`${direct}/identity/connect/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'password',
            username: email,
            password: acct.masterPasswordHash,
            scope: 'api offline_access',
            client_id: 'cli',
            deviceType: '8',
            deviceName: 'capture',
            deviceIdentifier: id,
          }),
        })
      const first = await login(crypto.randomUUID())
      const { access_token } = await first.json()
      await fetch(`${direct}/api/accounts/verify-devices`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ masterPasswordHash: acct.masterPasswordHash, verifyDevices: false }),
      })
      return email
    }

    const fixtures = []
    const scenario = async (name, flows, fn) => {
      await bw(['logout'])
      const email = await freshAccount(name)
      bucket = []
      const login = await bwOk(['login', email, '--passwordenv', 'BW_PASSWORD', '--raw'])
      await fn({ S: ['--session', login], email, login })
      const raw = bucket
      bucket = null
      fixtures.push(
        toFixture({ client: 'cli', clientVersion: CLI_VERSION, scenario: name, flows }, raw),
      )
      console.log(`recorded ${name}: ${raw.length} exchanges`)
    }

    await bwOk(['config', 'server', base])

    await scenario('login-sync', ['login', 'sync'], async ({ S }) => {
      await bwOk(['sync', ...S])
      await bwOk(['sync', '--force', ...S])
      await bwOk(['list', 'items', ...S])
      await bwOk(['logout'])
    })

    await scenario('cipher-write', ['login', 'sync', 'cipher-write'], async ({ S }) => {
      await bwOk(['sync', ...S])
      const folder = JSON.parse(
        await bwOk(['create', 'folder', await encode({ name: 'capture folder' }), ...S]),
      )
      const item = {
        organizationId: null,
        collectionIds: null,
        folderId: folder.id,
        type: 1,
        name: 'capture login',
        notes: 'capture note',
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
      const created = JSON.parse(await bwOk(['create', 'item', await encode(item), ...S]))
      await bwOk([
        'edit',
        'item',
        created.id,
        await encode({ ...created, name: 'capture login edited' }),
        ...S,
      ])
      await bwOk(['edit', 'folder', folder.id, await encode({ name: 'capture folder 2' }), ...S])
      await bwOk(['delete', 'item', created.id, ...S])
      await bwOk(['restore', 'item', created.id, ...S])
      await bwOk(['delete', 'item', created.id, '--permanent', ...S])
      await bwOk(['delete', 'folder', folder.id, ...S])
      await bwOk(['sync', ...S])
    })

    await scenario('send', ['login', 'send'], async ({ S }) => {
      const mk = (extra) =>
        encode({
          name: 'capture send',
          notes: null,
          type: 0,
          text: { text: 'send body', hidden: false },
          deletionDate: new Date(Date.now() + 86400000).toISOString(),
          maxAccessCount: null,
          disabled: false,
          hideEmail: false,
          ...extra,
        })
      const send = JSON.parse(await bwOk(['send', 'create', await mk({}), ...S]))
      await bwOk(['send', 'list', ...S])
      await bwOk(['send', 'get', send.id, ...S])
      await bwOk([
        'send',
        'edit',
        await encode({ ...send, name: 'capture send edited' }),
        '--itemid',
        send.id,
        ...S,
      ])
      await bwOk(['send', 'receive', send.accessUrl])
      const guarded = JSON.parse(
        await bwOk(['send', 'create', await mk({ authType: 1, password: 's3cret-pass' }), ...S]),
      )
      await bw(['send', 'receive', guarded.accessUrl, '--password', 'wrong'])
      await bwOk(['send', 'receive', guarded.accessUrl, '--password', 's3cret-pass'])
      await bwOk(['send', 'delete', guarded.id, ...S])
      await bwOk(['send', 'delete', send.id, ...S])
    })

    mkdirSync(outDir, { recursive: true })
    for (const f of fixtures) {
      const bad = findIdentifying(f)
      if (bad.length) {
        throw new Error(
          `${f.scenario} still has identifying data:\n${JSON.stringify(bad.slice(0, 10), null, 2)}`,
        )
      }
      writeFileSync(
        join(outDir, `${f.client}-${f.scenario}.json`),
        `${JSON.stringify(f, null, 2)}\n`,
      )
    }
    console.log(`wrote ${fixtures.length} fixtures to test/fixtures/traffic/`)
  } catch (err) {
    console.error(`--- dev server output ---\n${log.slice(-3000)}`)
    throw err
  } finally {
    proxy.close()
    recorder.close()
    const exited = new Promise((ok) => server.once('exit', ok))
    server.kill('SIGINT')
    await Promise.race([exited, sleep(10000)])
    killGroup('SIGKILL')
    rmSync(work, { recursive: true, force: true })
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
