// Records the official web vault's API traffic against a local dev server and writes sanitised
// fixtures to test/fixtures/traffic/web-*.json (TASKS #387). Usage: pnpm capture:web-traffic
//
// The built, unmodified web client (`pnpm web:build`, served from web-vault/) is driven by headless
// Chromium (playwright-core) through a local TLS proxy and a recording proxy in front of `vite dev`.
// Only /api and /identity calls are kept; static assets are skipped. Bodies are sanitised in memory
// by scripts/traffic-sanitise.mjs before anything touches disk. See docs/traffic-fixtures.md.
//
// Chromium: set CHROMIUM_PATH to a Chromium or Chrome binary, or install one with
// `pnpm exec playwright-core install chromium`. CAPTURE_ONLY=login-sync,send records just those
// scenarios; CAPTURE_DEBUG_DIR=<dir> keeps screenshots of each step (never commit them).
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { chromium } from 'playwright-core'
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
const bin = (name) => join(root, 'node_modules', '.bin', name)
const PASSWORD = 'correct horse battery staple 1'
const debugDir = process.env.CAPTURE_DEBUG_DIR
const buildInfo = join(root, 'web-vault', 'cloudwarden-build.json')

if (!existsSync(buildInfo)) {
  console.error('web-vault/ is missing: run `pnpm web:build` first')
  process.exit(1)
}
const WEB_VERSION = JSON.parse(readFileSync(buildInfo, 'utf8')).upstream.replace(/^web-v/, '')

async function main() {
  const port = await freePort()
  const recPort = await freePort()
  const tlsPort = await freePort()
  const base = `https://127.0.0.1:${tlsPort}`
  const direct = `http://127.0.0.1:${port}`
  const work = mkdtempSync(join(tmpdir(), 'cloudwarden-web-capture-'))
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
  let browser

  try {
    for (let i = 0; ; i++) {
      try {
        if ((await fetch(`${direct}/alive`)).ok) break
      } catch {}
      if (i > 120) throw new Error(`dev server did not start\n${log}`)
      await sleep(500)
    }
    browser = await chromium.launch({
      executablePath: process.env.CHROMIUM_PATH || undefined,
      args: ['--no-sandbox'],
    })

    // A fresh account over HTTP (not recorded) for the scenarios that start at the login page.
    // New device verification is switched off so the browser's own device may log in.
    const freshAccount = async (tag) => {
      const email = `web-${tag}-${Date.now()}@example.com`
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

    const fixtures = []
    const scenario = async (name, flows, fn, { account = true } = {}) => {
      const context = await browser.newContext({
        viewport: { width: 1440, height: 1000 },
        ignoreHTTPSErrors: true,
        serviceWorkers: 'block',
      })
      const page = await context.newPage()
      page.setDefaultTimeout(30000)
      const email = account ? await freshAccount(name) : `web-${name}-${Date.now()}@example.com`
      recorder.open()
      let raw = []
      try {
        await fn({ page, context, email })
      } catch (err) {
        if (debugDir) {
          mkdirSync(debugDir, { recursive: true })
          await page.screenshot({ path: join(debugDir, `${name}-failed.png`) }).catch(() => {})
        }
        throw err
      } finally {
        raw = recorder.take()
        await context.close()
      }
      fixtures.push(
        toFixture({ client: 'web', clientVersion: WEB_VERSION, scenario: name, flows }, raw),
      )
      console.log(`recorded ${name}: ${fixtures.at(-1).exchanges.length} API exchanges`)
    }

    const snap = async (page, tag) => {
      if (!debugDir) return
      mkdirSync(debugDir, { recursive: true })
      await page.screenshot({ path: join(debugDir, `${tag}.png`) })
    }

    // After the first login the client may offer its browser extension; decline and wait for the vault.
    const reachVault = async (page) => {
      const later = page.getByRole('button', { name: 'Add it later' })
      const vault = page.locator('app-vault-items-v2, app-vault')
      await later.or(vault.first()).first().waitFor({ timeout: 60000 })
      if (await later.isVisible()) {
        await later.click()
        await page.getByText('Skip to web app').click()
      }
      await page.waitForURL(/#\/vault/)
      await page.waitForLoadState('networkidle')
      // New accounts get a welcome tour.
      const skip = page.getByRole('button', { name: 'Skip', exact: true })
      if (await skip.isVisible({ timeout: 3000 }).catch(() => false)) await skip.click()
    }

    const logIn = async (page, email) => {
      await page.goto(`${base}/#/login`)
      await page.getByLabel('Email address').fill(email)
      await page.getByRole('button', { name: 'Continue' }).click()
      await page.getByLabel('Master password').fill(PASSWORD)
      await page.getByRole('button', { name: 'Log in', exact: true }).click()
      await reachVault(page)
    }

    const only = process.env.CAPTURE_ONLY
    const want = (name) => !only || only.split(',').includes(name)

    if (want('register'))
      await scenario(
        'register',
        ['register', 'login', 'sync'],
        async ({ page, email }) => {
          await page.goto(`${base}/#/signup`)
          await page.getByLabel('Email address').fill(email)
          await page.getByLabel('Name').fill('Example User')
          await page.getByRole('button', { name: 'Continue' }).click()
          await page
            .getByLabel(/^Master password/)
            .first()
            .fill(PASSWORD)
          await page.getByLabel(/Confirm master password/).fill(PASSWORD)
          await page.getByLabel(/Master password hint/).fill('example hint')
          await page.getByRole('button', { name: 'Create account' }).click()
          await reachVault(page)
        },
        { account: false },
      )

    if (want('login-sync'))
      await scenario('login-sync', ['login', 'sync'], async ({ page, email }) => {
        await logIn(page, email)
        await snap(page, 'vault')
        await page.reload()
        await page.waitForLoadState('networkidle')
        await snap(page, 'vault-2')
      })

    if (want('cipher-write'))
      await scenario('cipher-write', ['login', 'sync', 'cipher-write'], async ({ page, email }) => {
        await logIn(page, email)
        await page.getByRole('button', { name: 'New', exact: true }).click()
        await snap(page, 'new-menu')
        await page.getByRole('menuitem', { name: 'Folder' }).click()
        const dialog = page.getByRole('dialog')
        await dialog.getByLabel(/Folder name/).fill('Example folder')
        await dialog.getByRole('button', { name: 'Save' }).click()
        await dialog.waitFor({ state: 'hidden' })

        // Create a login in that folder.
        await page.getByRole('button', { name: 'New', exact: true }).click()
        await page.getByRole('menuitem', { name: 'Login' }).click()
        await snap(page, 'item-dialog')
        await dialog.getByLabel(/Item name/).fill('Example login')
        await dialog.getByLabel('Folder', { exact: true }).click()
        await page.getByRole('option', { name: 'Example folder' }).click()
        await dialog.getByLabel('Username', { exact: true }).fill('alice')
        await dialog.getByLabel('Password', { exact: true }).fill('p4ssw0rd!')
        await dialog
          .getByLabel(/Website|URI/)
          .first()
          .fill('https://example.com')
        await dialog.getByLabel('Notes').fill('Example note')
        await snap(page, 'item-filled')
        await dialog.getByRole('button', { name: 'Save' }).click()
        // Saving a new item leaves its read-only view open.
        await dialog.getByText('View Login').waitFor()
        await dialog.getByRole('button', { name: 'Edit' }).click()
        await dialog.getByLabel(/Item name/).fill('Example login edited')
        await dialog.getByRole('button', { name: 'Save' }).click()
        // Saving returns to the read-only view of the item, which also offers the delete button.
        await dialog.getByText('View Login').waitFor()
        await snap(page, 'item-edited')

        // Move it to the bin, restore it, bin it again and delete it for good.
        const trash = async () => {
          await dialog.getByRole('button', { name: /Delete/ }).click()
          await page.getByRole('button', { name: 'Yes' }).click()
          await dialog.waitFor({ state: 'hidden' })
        }
        const openInBin = async () => {
          await page.getByText('Bin', { exact: true }).click()
          await page.getByRole('button', { name: 'Example login edited' }).first().click()
        }
        await trash()
        await openInBin()
        await snap(page, 'bin-view')
        await dialog.getByRole('button', { name: 'Restore' }).click()
        await dialog.waitFor({ state: 'hidden' })
        await page.getByText('All items', { exact: true }).click()
        await page.getByRole('button', { name: 'Example login edited' }).first().click()
        await trash()
        await openInBin()
        await dialog.getByRole('button', { name: /Delete/ }).click()
        await snap(page, 'perm-delete-confirm')
        await page.getByRole('button', { name: 'Yes' }).click()
        await dialog.waitFor({ state: 'hidden' })
        await snap(page, 'after-perm-delete')

        // Rename and delete the folder.
        const editFolder = async (name) => {
          // The pencil appears on the selected folder.
          await page.getByRole('button', { name: `Filter: ${name}` }).click()
          await page.getByRole('button', { name: `Edit Folder: ${name}` }).click()
          await dialog.waitFor()
        }
        await editFolder('Example folder')
        await dialog.getByLabel(/Folder name/).fill('Example folder renamed')
        await dialog.getByRole('button', { name: 'Save' }).click()
        await dialog.waitFor({ state: 'hidden' })
        await editFolder('Example folder renamed')
        await dialog.getByRole('button', { name: /Delete/ }).click()
        await page.getByRole('button', { name: 'Yes' }).click()
        await dialog.waitFor({ state: 'hidden' })
        await page.getByRole('button', { name: 'Filter: Example folder renamed' }).waitFor({
          state: 'detached',
        })
        await sleep(1000)
      })

    if (want('send'))
      await scenario('send', ['login', 'send'], async ({ page, email }) => {
        await logIn(page, email)
        await page.getByRole('link', { name: 'Send', exact: true }).click()
        await page.getByText('New', { exact: true }).first().click()
        await snap(page, 'send-menu')
        await page.getByRole('menuitem', { name: 'Text' }).click()
        const drawer = page
        const hidden = () => drawer.getByLabel(/Send name/).waitFor({ state: 'hidden' })
        await drawer.getByLabel(/Send name/).fill('Example send')
        await drawer.getByLabel(/Text to share/).fill('Example text')
        await drawer.getByRole('button', { name: 'Save' }).click()
        await drawer.getByText('Send created').first().waitFor()
        await drawer.getByRole('button', { name: 'Close', exact: true }).last().click()
        await page.getByRole('button', { name: 'Example send' }).first().click()
        await drawer.getByText('View text').waitFor()

        // Edit it.
        await drawer.getByRole('button', { name: 'Edit', exact: true }).click()
        await drawer.getByLabel(/Send name/).fill('Example send edited')
        await drawer.getByRole('button', { name: 'Save' }).click()
        await drawer.getByText('View text').waitFor()
        const link = (
          await drawer
            .getByText(/#\/send\//)
            .first()
            .textContent()
        ).trim()
        await snap(page, 'send-edited')

        // A recipient opens the link without an account.
        const guest = await browser.newContext({
          viewport: { width: 1440, height: 1000 },
          ignoreHTTPSErrors: true,
          serviceWorkers: 'block',
        })
        const guestPage = await guest.newPage()
        guestPage.setDefaultTimeout(30000)
        await guestPage.goto(link.replace(/^https:\/\/[^/]+/, base))
        await guestPage.getByRole('heading', { name: 'View Send' }).waitFor()
        await guestPage.getByText('Example send edited').waitFor()
        await guestPage.waitForLoadState('networkidle')
        await guest.close()

        // Delete it.
        await drawer.getByRole('button', { name: 'Delete' }).click()
        await page.getByRole('button', { name: 'Yes' }).click()
        await hidden()
        await snap(page, 'send-deleted')
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
    await browser?.close().catch(() => {})
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
