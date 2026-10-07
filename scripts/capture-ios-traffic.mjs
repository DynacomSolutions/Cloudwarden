// Records the official Bitwarden iOS app's API traffic against a local dev server and writes
// sanitised fixtures to test/fixtures/traffic/ios-*.json (TASKS #389).
// Usage: IOS_UDID=<booted simulator> IOS_APP=<Bitwarden.app> pnpm capture:ios-traffic
//
// The unmodified app, built from the bitwarden/ios release tag, runs in the iOS Simulator, which
// shares the host's network, so it reaches the TLS proxy at https://127.0.0.1:<port>. The proxy's
// throwaway CA goes into the simulator's trust store with `simctl keychain add-root-cert` (the app
// does not pin). The app is driven by Maestro flows in scripts/ios-flows/ that find elements by
// visible text or accessibility identifier. Only /api and /identity calls are kept. Bodies are
// sanitised in memory by scripts/traffic-sanitise.mjs before anything touches disk. See
// docs/traffic-fixtures.md.
//
// Environment: IOS_UDID (required, a booted simulator), IOS_APP (optional, the .app to install
// first), MAESTRO (the maestro binary, default `maestro`), CAPTURE_ONLY=register,send (record only
// those scenarios), CAPTURE_DEBUG_DIR=<dir> (keep Maestro's output, a screenshot and the view
// hierarchy of each failed scenario).
import { spawn, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { buildAccount } from '../e2e/crypto.mjs'
import { makeCert, startProxy } from '../e2e/tls-proxy.mjs'
import {
  descendants,
  formatFiles,
  freePort,
  killAll,
  killStrayWorkerd,
  startRecorder,
  toFixture,
} from './capture-lib.mjs'
import { migrateLocal } from './local-migrate.mjs'
import { findIdentifying } from './traffic-sanitise.mjs'

const root = resolve(import.meta.dirname, '..')
const outDir = join(root, 'test', 'fixtures', 'traffic')
const flowDir = join(root, 'scripts', 'ios-flows')
const bin = (name) => join(root, 'node_modules', '.bin', name)
const PASSWORD = 'correct horse battery staple 1'
const udid = process.env.IOS_UDID
const maestro = process.env.MAESTRO || 'maestro'
const debugDir = process.env.CAPTURE_DEBUG_DIR

if (!udid) {
  console.error('set IOS_UDID to a booted iOS Simulator (see docs/traffic-fixtures.md)')
  process.exit(1)
}
const simctl = (...args) =>
  spawnSync('xcrun', ['simctl', ...args], { encoding: 'utf8', maxBuffer: 1 << 26 })

async function main() {
  const port = await freePort()
  const recPort = await freePort()
  const tlsPort = await freePort()
  const direct = `http://127.0.0.1:${port}`
  const serverUrl = `https://127.0.0.1:${tlsPort}`
  const work = mkdtempSync(join(tmpdir(), 'cloudwarden-ios-capture-'))
  const tls = makeCert(work)
  const env = {
    ...process.env,
    SIGNUPS_ALLOWED: 'true',
    LOCAL_DEV_SECRETS: 'true',
    MAIL_DISABLED: 'true',
    JWT_SECRET: 'capture-only-secret-capture-only-secret-0123456789',
    DEPLOY_DOMAIN: `127.0.0.1:${tlsPort}`,
  }
  await migrateLocal(root, env, join(root, '.cloudflare', 'state'))
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
  process.on('exit', () => {
    const tree = descendants(server.pid)
    killGroup('SIGKILL')
    killAll(tree)
  })
  const recorder = await startRecorder(recPort, port)
  const proxy = await startProxy(tls, tlsPort, recPort)
  // Diagnostics for a client that does not trust the CA: TLS failures never reach the recorder.
  proxy.on('tlsClientError', (e) => console.error(`proxy TLS client error: ${e.message}`))
  proxy.on('secureConnection', () => console.error('proxy: TLS connection accepted'))
  proxy.on('request', (req) =>
    console.error(`proxy request: ${req.method} ${req.url.split('?')[0]}`),
  )
  let bundleId = ''

  try {
    for (let i = 0; ; i++) {
      try {
        if ((await fetch(`${direct}/alive`)).ok) break
      } catch {}
      if (i > 360) throw new Error(`dev server did not start\n${log}`)
      await sleep(500)
    }

    // Simulator set-up: trust the throwaway CA, install the app.
    const trust = simctl('keychain', udid, 'add-root-cert', tls.ca)
    console.log(
      spawnSync('openssl', ['x509', '-in', tls.ca, '-noout', '-text'], { encoding: 'utf8' })
        .stdout.split('\n')
        .filter((l) => /Version|CA:|Signature Algorithm|Not /.test(l))
        .join('\n'),
    )
    if (trust.status !== 0) throw new Error(`add-root-cert failed: ${trust.stderr}`)
    if (process.env.IOS_APP) {
      const res = simctl('install', udid, process.env.IOS_APP)
      if (res.status !== 0) throw new Error(`app install failed: ${res.stderr}`)
    }
    const app = simctl('get_app_container', udid, 'com.8bit.bitwarden', 'app')
    if (app.status !== 0) throw new Error(`com.8bit.bitwarden is not installed (set IOS_APP)`)
    bundleId = 'com.8bit.bitwarden'
    const plist = (key) =>
      spawnSync('plutil', ['-extract', key, 'raw', join(app.stdout.trim(), 'Info.plist')], {
        encoding: 'utf8',
      }).stdout.trim()
    const APP_VERSION = plist('CFBundleShortVersionString')
    if (!APP_VERSION) throw new Error('could not read the app version')
    console.log(`Bitwarden iOS ${APP_VERSION} (build ${plist('CFBundleVersion')})`)

    // A fresh account over HTTP (not recorded). New device verification is switched off so the
    // app's own device may log in without an emailed code.
    const freshAccount = async (tag) => {
      const email = `ios-${tag}-${Date.now()}@example.com`
      const acct = await buildAccount(email, PASSWORD)
      const reg = await fetch(`${direct}/identity/accounts/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(acct.body),
      })
      if (!reg.ok) throw new Error(`register ${reg.status}`)
      const first = await fetch(`${direct}/identity/connect/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'password',
          username: email,
          password: acct.masterPasswordHash,
          scope: 'api offline_access',
          client_id: 'web',
          deviceType: '9',
          deviceName: 'capture',
          deviceIdentifier: crypto.randomUUID(),
        }),
      })
      const { access_token } = await first.json()
      await fetch(`${direct}/api/accounts/verify-devices`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${access_token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ masterPasswordHash: acct.masterPasswordHash, verifyDevices: false }),
      })
      return email
    }

    // Async on purpose: the TLS proxy and recorder live in this process, so its event loop must
    // stay free while Maestro drives the app (a spawnSync here stalls every TLS handshake).
    const runFlow = async (name, email) => {
      const out = debugDir ? join(debugDir, name) : undefined
      if (out) mkdirSync(out, { recursive: true })
      const args = ['--device', udid, 'test']
      for (const [k, v] of Object.entries({ EMAIL: email, PASSWORD, SERVER_URL: serverUrl }))
        args.push('-e', `${k}=${v}`)
      if (out) args.push('--debug-output', out, '--flatten-debug-output')
      args.push(join(flowDir, `${name}.yaml`))
      const res = await new Promise((ok) => {
        const child = spawn(maestro, args, {
          env: {
            ...process.env,
            MAESTRO_DRIVER_STARTUP_TIMEOUT: '300000',
            MAESTRO_CLI_NO_ANALYTICS: '1',
          },
          stdio: ['ignore', 'inherit', 'inherit'],
        })
        const timer = setTimeout(() => child.kill('SIGKILL'), 900000)
        child.on('exit', (status) => {
          clearTimeout(timer)
          ok({ status })
        })
      })
      if (res.status !== 0) {
        if (out) {
          simctl('io', udid, 'screenshot', join(out, 'final.png'))
          const appLog = spawnSync(
            'xcrun',
            [
              'simctl',
              'spawn',
              udid,
              'log',
              'show',
              '--last',
              '10m',
              '--predicate',
              'process == "Bitwarden"',
              '--style',
              'compact',
            ],
            { encoding: 'utf8', maxBuffer: 1 << 28, timeout: 120000 },
          )
          writeFileSync(join(out, 'app.log'), appLog.stdout ?? '')
          writeFileSync(
            join(out, 'net.txt'),
            spawnSync('lsof', ['-nP', '-iTCP'], { encoding: 'utf8' }).stdout ?? '',
          )
          const h = spawnSync(maestro, ['--device', udid, 'hierarchy'], {
            encoding: 'utf8',
            maxBuffer: 1 << 26,
            timeout: 60000,
          })
          writeFileSync(join(out, 'hierarchy.json'), h.stdout ?? '')
        }
        throw new Error(`maestro flow ${name} failed (exit ${res.status})`)
      }
    }

    const fixtures = []
    const scenario = async (name, flows, { account = true } = {}) => {
      const email = account ? await freshAccount(name) : `ios-${name}-${Date.now()}@example.com`
      simctl('terminate', udid, bundleId)
      recorder.open()
      let raw = []
      try {
        await runFlow(name, email)
      } finally {
        raw = recorder.take()
      }
      fixtures.push(
        toFixture({ client: 'ios', clientVersion: APP_VERSION, scenario: name, flows }, raw),
      )
      console.log(`recorded ${name}: ${fixtures.at(-1).exchanges.length} API exchanges`)
    }

    const only = process.env.CAPTURE_ONLY
    const want = (name) => !only || only.split(',').includes(name)
    if (want('register'))
      await scenario('register', ['register', 'login', 'sync'], { account: false })
    if (want('login-sync')) await scenario('login-sync', ['login', 'sync'])
    if (want('cipher-write')) await scenario('cipher-write', ['login', 'sync', 'cipher-write'])
    if (want('send')) await scenario('send', ['login', 'send'])

    mkdirSync(outDir, { recursive: true })
    const written = []
    for (const f of fixtures) {
      const bad = findIdentifying(f)
      if (bad.length) {
        throw new Error(
          `${f.scenario} still has identifying data:\n${JSON.stringify(bad.slice(0, 10), null, 2)}`,
        )
      }
      const file = join(outDir, `${f.client}-${f.scenario}.json`)
      writeFileSync(file, `${JSON.stringify(f, null, 2)}\n`)
      written.push(file)
    }
    formatFiles(root, written)
    console.log(`wrote ${fixtures.length} fixtures to test/fixtures/traffic/`)
  } catch (err) {
    console.error(`--- dev server output ---\n${log.slice(-3000)}`)
    throw err
  } finally {
    if (bundleId) simctl('terminate', udid, bundleId)
    proxy.close()
    recorder.close()
    const tree = descendants(server.pid)
    const exited = new Promise((ok) => server.once('exit', ok))
    server.kill('SIGINT')
    await Promise.race([exited, sleep(10000)])
    killGroup('SIGKILL')
    killAll(tree)
    await sleep(500)
    killStrayWorkerd(root)
    rmSync(work, { recursive: true, force: true })
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
