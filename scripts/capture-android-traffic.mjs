// Records the official Bitwarden Android app's API traffic against a local dev server and writes
// sanitised fixtures to test/fixtures/traffic/android-*.json (TASKS #388).
// Usage: ANDROID_SERIAL=emulator-5554 pnpm capture:android-traffic
//
// The unmodified app from the bitwarden/android GitHub release runs on an Android emulator with a
// google_apis system image (not the Play Store image): the script restarts adbd as root, installs a
// throwaway CA into the user certificate store (the app's network security config trusts user
// CAs) and forwards a port into the host with `adb reverse`, so the app reaches the TLS proxy at
// https://127.0.0.1:<port>. Only /api and /identity calls are kept. Bodies are sanitised in memory
// by scripts/traffic-sanitise.mjs before anything touches disk. See docs/traffic-fixtures.md.
//
// Environment: ANDROID_SERIAL (required, a running emulator), ANDROID_HOME or ANDROID_SDK_ROOT
// (for adb), ANDROID_APK (optional, an APK to install first), CAPTURE_ONLY=register,send (record
// only those scenarios), CAPTURE_DEBUG_DIR=<dir> (keep the screen text of each failed step).
import { spawn, spawnSync } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { buildAccount } from '../e2e/crypto.mjs'
import { makeCert, startProxy } from '../e2e/tls-proxy.mjs'
import { createDevice } from './android-ui.mjs'
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
const bin = (name) => join(root, 'node_modules', '.bin', name)
const PASSWORD = 'correct horse battery staple 1'
const APP = 'com.x8bit.bitwarden'
const serial = process.env.ANDROID_SERIAL
const debugDir = process.env.CAPTURE_DEBUG_DIR

if (!serial) {
  console.error(
    'set ANDROID_SERIAL to a running google_apis emulator (see docs/traffic-fixtures.md)',
  )
  process.exit(1)
}
const dev = createDevice(serial)

async function main() {
  const port = await freePort()
  const recPort = await freePort()
  const tlsPort = await freePort()
  const direct = `http://127.0.0.1:${port}`
  const serverUrl = `https://127.0.0.1:${tlsPort}`
  const work = mkdtempSync(join(tmpdir(), 'cloudwarden-android-capture-'))
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
  let certOnDevice = ''

  try {
    for (let i = 0; ; i++) {
      try {
        if ((await fetch(`${direct}/alive`)).ok) break
      } catch {}
      if (i > 120) throw new Error(`dev server did not start\n${log}`)
      await sleep(500)
    }

    // Device set-up: root adbd, trust the throwaway CA as a user certificate, forward the port.
    if (process.env.ANDROID_APK) {
      const res = dev.adb('install', '-r', process.env.ANDROID_APK)
      if (!/Success/.test(res.stdout))
        throw new Error(`apk install failed: ${res.stdout}${res.stderr}`)
    }
    dev.adb('root')
    await sleep(3000)
    dev.adb('wait-for-device')
    const hash = spawnSync('openssl', ['x509', '-subject_hash_old', '-noout', '-in', tls.ca], {
      encoding: 'utf8',
    }).stdout.trim()
    certOnDevice = `/data/misc/user/0/cacerts-added/${hash}.0`
    copyFileSync(tls.ca, join(work, `${hash}.0`))
    dev.shell('mkdir -p /data/misc/user/0/cacerts-added')
    dev.adb('push', join(work, `${hash}.0`), certOnDevice)
    dev.shell(`chmod 644 ${certOnDevice}; chown system:system ${certOnDevice}`)
    dev.shell('restorecon -R /data/misc/user/0/cacerts-added')
    dev.adb('reverse', `tcp:${tlsPort}`, `tcp:${tlsPort}`)
    const APP_VERSION = /versionName=(\S+)/.exec(dev.shell(`dumpsys package ${APP}`))?.[1]
    if (!APP_VERSION) throw new Error(`${APP} is not installed (set ANDROID_APK)`)
    console.log(`Bitwarden Android ${APP_VERSION}`)

    // A fresh account over HTTP (not recorded). New device verification is switched off so the
    // app's own device may log in without an emailed code.
    const freshAccount = async (tag) => {
      const email = `android-${tag}-${Date.now()}@example.com`
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

    // --- UI helpers -----------------------------------------------------------------------
    const topBar = async (desc) => {
      const n = dev
        .nodes()
        .filter((x) => x.desc === desc && x.cy < 260)
        .sort((a, b) => b.cx - a.cx)[0]
      if (!n) throw new Error(`no top bar "${desc}"; on screen: ${JSON.stringify(dev.screen())}`)
      dev.tapXY(n.cx, n.cy)
      await sleep(700)
    }
    const launch = async () => {
      dev.shell(`pm clear ${APP}`)
      dev.shell(`monkey -p ${APP} -c android.intent.category.LAUNCHER 1`)
      await dev.wait('Accessibility Service Disclosure', { timeout: 60000 }).catch(() => {})
      if (await dev.appears('I understand', { timeout: 2000 })) await dev.tap('I understand')
      await dev.wait('Log in', { timeout: 60000, exact: true })
    }
    // Region drop-down on the create account and log in screens: self-hosted at the proxy.
    const useSelfHosted = async () => {
      const region = dev.nodes().find((n) => n.text === 'bitwarden.com')
      if (!region) throw new Error(`no region selector; on screen: ${JSON.stringify(dev.screen())}`)
      dev.tapXY(region.cx, region.cy)
      await dev.tap('Self-hosted', { exact: true })
      await dev.fill('Server URL', serverUrl)
      await dev.tap('Save', { exact: true })
      await dev.wait('Self-hosted', { exact: true })
    }
    // Skips the post-login set-up prompts and coach marks until the vault shows.
    const reachVault = async () => {
      for (let i = 0; i < 40; i++) {
        const text = dev.screen()
        const has = (s) => text.some((t) => t === s)
        if (has('Set up later')) {
          await dev.tap('Set up later', { exact: true })
          await dev.tap('Confirm', { exact: true })
        } else if (has('Turn on later')) {
          await dev.tap('Turn on later', { exact: true })
          await dev.tap('Confirm', { exact: true })
        } else if (has('Continue') && text.some((t) => t.startsWith('You’re all set'))) {
          await dev.tap('Continue', { exact: true })
        } else if (has('Get started') && has('Close')) {
          const close = dev.nodes().find((n) => n.desc === 'Close' && n.cx > 900)
          if (close) dev.tapXY(close.cx, close.cy)
          await sleep(700)
        } else if (has('Add item') && has('Settings')) return
        else await sleep(1000)
      }
      throw new Error(`vault not reached; on screen: ${JSON.stringify(dev.screen())}`)
    }
    // The vault shows coach marks the first time; closing them is part of reaching the vault.
    const dismissCoachMarks = async () => {
      for (let i = 0; i < 5; i++) {
        const close = dev.nodes().find((n) => n.desc === 'Close' && n.cx > 900 && n.cy < 500)
        if (!close) return
        dev.tapXY(close.cx, close.cy)
        await sleep(700)
      }
    }
    const logIn = async (email) => {
      await launch()
      await dev.tap('Log in', { exact: true })
      await useSelfHosted()
      await dev.fill('Email address', email)
      await dev.tap('Continue', { exact: true })
      await dev.fill('Master password', PASSWORD)
      await dev.tap('Log in with master password')
      await reachVault()
      await dismissCoachMarks()
    }
    const confirmDialog = async (button) => {
      await dev.wait(button, { exact: true })
      const btn = dev
        .nodes()
        .filter((n) => n.desc === button || n.text === button)
        .at(-1)
      dev.tapXY(btn.cx, btn.cy)
      await sleep(1500)
    }
    const openTrash = async () => {
      await dev.tap('Back', { exact: true })
      await dismissCoachMarks()
      await dev.tap('Trash', { exact: true })
    }
    const goTab = async (name) => {
      await dev.tap(name, { exact: true })
      await sleep(1000)
    }

    const fixtures = []
    const scenario = async (name, flows, fn, { account = true } = {}) => {
      const email = account ? await freshAccount(name) : `android-${name}-${Date.now()}@example.com`
      recorder.open()
      let raw = []
      try {
        await fn({ email })
      } catch (err) {
        if (debugDir) {
          mkdirSync(debugDir, { recursive: true })
          writeFileSync(join(debugDir, `${name}-failed.txt`), JSON.stringify(dev.screen(), null, 2))
        }
        throw err
      } finally {
        raw = recorder.take()
      }
      fixtures.push(
        toFixture({ client: 'android', clientVersion: APP_VERSION, scenario: name, flows }, raw),
      )
      console.log(`recorded ${name}: ${fixtures.at(-1).exchanges.length} API exchanges`)
    }

    const only = process.env.CAPTURE_ONLY
    const want = (name) => !only || only.split(',').includes(name)

    if (want('register'))
      await scenario(
        'register',
        ['register', 'login', 'sync'],
        async ({ email }) => {
          await launch()
          await dev.tap('Create account', { exact: true })
          await useSelfHosted()
          await dev.fill('Email address', email)
          await dev.fill('Name', 'Example User')
          await dev.tap('Continue', { exact: true })
          await dev.fill('Master password (required)', PASSWORD)
          await dev.fill('Re-type master password', PASSWORD)
          await dev.fill('Master password hint', 'example hint')
          // Do not send the password to a breach checking service outside the capture.
          const breach = await dev.wait('Check known data breaches')
          dev.tapXY(breach.cx, breach.cy)
          await sleep(700)
          await dev.tap('Next', { exact: true })
          await reachVault()
          await sleep(2000)
        },
        { account: false },
      )

    if (want('login-sync'))
      await scenario('login-sync', ['login', 'sync'], async ({ email }) => {
        await logIn(email)
        // A manual sync from the vault menu.
        await topBar('More options')
        await dev.tap('Sync', { exact: true })
        await sleep(2500)
      })

    if (want('cipher-write'))
      await scenario('cipher-write', ['login', 'sync', 'cipher-write'], async ({ email }) => {
        await logIn(email)

        // Folder, then a login in it.
        await dev.tap('Add item', { exact: true })
        await dev.tap('Folder', { exact: true })
        await dev.fill('Name', 'Example folder')
        await dev.tap('Save', { exact: true })
        await dev.wait('New folder created')
        await dev.tap('Add item', { exact: true })
        await dev.tap('Login', { exact: true })
        if (await dev.appears('Bitwarden Autofill Service')) await dev.tap('Okay', { exact: true })
        if (await dev.appears('Get started', { timeout: 2000 })) {
          const close = dev.nodes().find((n) => n.desc === 'Close' && n.cx > 900)
          dev.tapXY(close.cx, close.cy)
          await sleep(700)
        }
        await dev.fill('Item name', 'Example login')
        await dev.fill('Username', 'alice')
        await dev.fill('Password', 'p4ssw0rd!')
        await dev.fill('Website (URI)', 'https://example.com')
        await dev.tap('No Folder')
        await dev.tap('Example folder', { exact: true })
        await dev.tap('Save', { exact: true }) // the folder picker sheet has its own Save
        await dev.wait('ITEM DETAILS')
        await dev.tap('Save', { exact: true })
        await sleep(2000)
        await dismissCoachMarks()

        // Edit it.
        await dev.tap('Login', { exact: true })
        await dev.tap('Example login', { exact: true })
        await dev.tap('Edit item', { exact: true })
        await dev.fill('Item name', 'Example login edited')
        await dev.tap('Save', { exact: true })
        await dev.wait('View login')

        // Send to the trash, restore, trash again, delete for good.
        const trash = async () => {
          await topBar('More options')
          await dev.tap('Delete', { exact: true })
          await confirmDialog('Okay')
          await dev.wait('Item has been sent to trash')
        }
        await trash()
        await openTrash()
        await dev.tap('Example login edited', { exact: true })
        await dev.tap('Restore', { exact: true })
        await confirmDialog('Okay')
        await dev.wait('There are no items in the trash')
        await dev.tap('Back', { exact: true })
        await dismissCoachMarks()
        await dev.tap('Example folder', { exact: true })
        await dev.tap('Example login edited', { exact: true })
        await trash()
        await openTrash()
        await dev.tap('Example login edited', { exact: true })
        await topBar('More options')
        await dev.tap('Delete', { exact: true })
        await confirmDialog('Okay')
        await dev.wait('There are no items in the trash')
        await dev.tap('Back', { exact: true })

        // Rename and delete the folder from Settings, Vault, Folders.
        await goTab('Settings')
        await dev.tap('Vault', { exact: true })
        await dev.tap('Folders', { exact: true })
        await dev.tap('Example folder', { exact: true })
        await dev.fill('Name', 'Example folder renamed')
        await dev.tap('Save', { exact: true })
        await dev.wait('Folder saved')
        await dev.tap('Example folder renamed', { exact: true })
        await topBar('More options')
        await dev.tap('Delete', { exact: true })
        await confirmDialog('Delete')
        await sleep(2000)
      })

    if (want('send'))
      await scenario('send', ['login', 'send'], async ({ email }) => {
        await logIn(email)
        await goTab('Send')
        const leaveShareSheet = async () => {
          // Saving a Send opens the system share sheet.
          if (await dev.appears('Quick Share', { timeout: 6000 })) {
            dev.key(4)
            await sleep(1000)
          }
        }
        const rowMenu = async (entry) => {
          const more = dev
            .nodes()
            .filter((n) => n.desc === 'More options' && n.cy > 260)
            .at(0)
          dev.tapXY(more.cx, more.cy)
          await sleep(700)
          await dev.tap(entry, { exact: true })
        }
        await dev.tap('Add item', { exact: true })
        await dev.tap('Text', { exact: true })
        await dev.fill('Send name', 'Example send')
        await dev.fill('Text to share', 'Example text')
        await dev.tap('Save', { exact: true })
        await leaveShareSheet()
        await dev.wait('Example send')
        await rowMenu('Edit')
        await dev.fill('Send name', 'Example send edited')
        await dev.tap('Save', { exact: true })
        await leaveShareSheet()
        await dev.wait('Example send edited')
        await rowMenu('Delete')
        await confirmDialog('Yes')
        await sleep(2000)
      })

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
    dev.shell(`am force-stop ${APP}`)
    if (certOnDevice) dev.shell(`rm -f ${certOnDevice}`)
    dev.adb('reverse', '--remove', `tcp:${tlsPort}`)
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
