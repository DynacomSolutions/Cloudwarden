#!/usr/bin/env node

/**
 * Builds Cloudwarden's web client from the vendored source in web/ (TASKS #210) and publishes
 * the static files into web-vault/, which Vite copies into the Worker's asset bundle.
 *
 * Usage: node scripts/build-web.mjs [--skip-install] [--no-scope]
 *   --skip-install  do not run `npm ci` in web/ (node_modules must already exist)
 *   --no-scope      do not wrap the build in a memory-limited systemd scope
 *
 * The webpack build is memory hungry. Outside CI it runs inside a transient systemd scope
 * (MemoryHigh=8G, MemoryMax=12G, MemorySwapMax=512M) when `systemd-run` is available, and it
 * refuses to start when less than 12 GiB is available. Run one build at a time.
 */

import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { cp, readdir, rename, rm, stat, writeFile } from 'node:fs/promises'
import { freemem } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const WEB = join(ROOT, 'web')
const APP = join(WEB, 'apps', 'web')
const BUILD = join(APP, 'build')
const OUT_DIR = join(ROOT, 'web-vault')
export const UPSTREAM_TAG = 'web-v2026.9.1'
export const BUILD_MARKER = 'cloudwarden-build.json'
const MIN_FREE_BYTES = 12 * 1024 ** 3
const HEAP_MB = 6144

/**
 * Static asset headers (Workers `_headers` file). The client needs `wasm-unsafe-eval` for its
 * WebAssembly SDK and inline styles for Angular. Everything else is same-origin, including the
 * API, identity, notification and icon routes served by the Worker.
 */
/**
 * Email alias forwarders of the generator call their provider APIs from the browser, so those
 * hosts are allowed. Self-hosted SimpleLogin, addy.io or Fastmail instances can be added with
 * `CLOUDWARDEN_CONNECT_SRC` (space separated `https://host` origins) at build time.
 */
export const FORWARDER_HOSTS = [
  'https://app.simplelogin.io',
  'https://app.addy.io',
  'https://relay.firefox.com',
  'https://api.fastmail.com',
  'https://quack.duckduckgo.com',
  'https://api.forwardemail.net',
]

export function extraConnectSources(value = '') {
  return value
    .split(/\s+/)
    .filter(Boolean)
    .map((origin) => {
      const url = new URL(origin)
      if (url.protocol !== 'https:' || url.origin !== origin.replace(/\/$/, '')) {
        throw new Error(`CLOUDWARDEN_CONNECT_SRC entries must be https origins, got ${origin}`)
      }
      return url.origin
    })
}

export const cspFor = (extra = []) =>
  [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    // 'self' also covers same-origin ws: and wss: (the notifications hub) in current browsers.
    `connect-src 'self' https://api.pwnedpasswords.com ${[...FORWARDER_HOSTS, ...extra].join(' ')}`,
    "frame-src 'self' https://*.duosecurity.com https://*.duofederatedsecurity.com https://*.duofederal.com",
    "worker-src 'self' blob:",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'self'",
  ].join('; ')

const CSP = cspFor(extraConnectSources(process.env.CLOUDWARDEN_CONNECT_SRC))

export const HEADERS = `/*
  Content-Security-Policy: ${CSP}
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
  Referrer-Policy: same-origin
  Permissions-Policy: camera=(self), microphone=(), geolocation=()
/index.html
  Cache-Control: no-cache
`

const version = () => JSON.parse(readFileSync(join(APP, 'package.json'), 'utf8')).version

const gitCommit = () => {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf8' }).trim()
  } catch {
    return null
  }
}

export const notice = (v, commit) => `Cloudwarden web client ${v}
================================

This directory contains Cloudwarden's web client, built from a modified copy of the Bitwarden
clients source code (tag ${UPSTREAM_TAG}). It is licensed under the GNU General Public License,
version 3 (GPL-3.0). The complete corresponding source code, including Cloudwarden's
modifications, is the web/ directory of the Cloudwarden repository${commit ? ` at commit ${commit}` : ''}.
See web/NOTICE.md there for the list of modifications. The licence text is at
https://www.gnu.org/licenses/gpl-3.0.txt

Upstream: https://github.com/bitwarden/clients (Copyright Bitwarden Inc.)

Bitwarden is a trademark of Bitwarden Inc. Cloudwarden is not affiliated with or endorsed by
Bitwarden Inc.
`

const run = (cmd, args, opts) => {
  const r = spawnSync(cmd, args, { stdio: 'inherit', ...opts })
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} exited with ${r.status}`)
}

const hasSystemdRun = () =>
  spawnSync('systemd-run', ['--version'], { stdio: 'ignore' }).status === 0

async function removeMaps(dir) {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name)
    if (e.isDirectory()) await removeMaps(p)
    else if (e.name.endsWith('.map')) await rm(p)
  }
}

async function main() {
  const args = new Set(process.argv.slice(2))
  const ci = Boolean(process.env.CI)
  const scoped = !ci && !args.has('--no-scope') && hasSystemdRun()

  if (!ci && freemem() < MIN_FREE_BYTES) {
    // freemem() ignores reclaimable cache, so fall back to MemAvailable when present.
    const avail = /MemAvailable:\s+(\d+) kB/.exec(
      existsSync('/proc/meminfo') ? readFileSync('/proc/meminfo', 'utf8') : '',
    )
    if (!avail || Number(avail[1]) * 1024 < MIN_FREE_BYTES) {
      throw new Error('less than 12 GiB of memory available; not starting the web build')
    }
  }

  if (!args.has('--skip-install')) {
    run('npm', ['ci', '--no-audit', '--no-fund', '--loglevel=error'], { cwd: WEB })
  }

  const started = Date.now()
  const env = {
    ...process.env,
    ENV: 'selfhosted',
    NODE_ENV: 'production',
    NODE_OPTIONS: `--max-old-space-size=${HEAP_MB}`,
  }
  const webpack = join(WEB, 'node_modules', 'webpack', 'bin', 'webpack.js')
  if (scoped) {
    // Report the scope's peak memory from inside it, then exit with webpack's status.
    const inner = `"${process.execPath}" "${webpack}"; rc=$?; f=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)/memory.peak; [ -r "$f" ] && echo "web build peak memory: $(( $(cat "$f") / 1048576 )) MiB"; exit $rc`
    run(
      'systemd-run',
      [
        '--user',
        '--scope',
        '--quiet',
        '-p',
        'MemoryHigh=8G',
        '-p',
        'MemoryMax=12G',
        '-p',
        'MemorySwapMax=512M',
        'sh',
        '-c',
        inner,
      ],
      { cwd: APP, env },
    )
  } else {
    run(process.execPath, [webpack], { cwd: APP, env })
  }
  const seconds = Math.round((Date.now() - started) / 1000)

  if (!existsSync(join(BUILD, 'index.html'))) throw new Error('webpack produced no index.html')

  const staging = `${OUT_DIR}.tmp`
  await rm(staging, { recursive: true, force: true })
  await cp(BUILD, staging, { recursive: true })
  await removeMaps(staging)
  // The Worker serves /app-id.json from DOMAIN; the static copy lists upstream origins.
  await rm(join(staging, 'app-id.json'), { force: true })
  const v = version()
  const commit = gitCommit()
  await writeFile(join(staging, 'LICENSE-NOTICE.txt'), notice(v, commit))
  await writeFile(join(staging, '_headers'), HEADERS)
  await writeFile(
    join(staging, BUILD_MARKER),
    `${JSON.stringify({ product: 'Cloudwarden', version: v, upstream: UPSTREAM_TAG, commit }, null, 2)}\n`,
  )
  await rm(OUT_DIR, { recursive: true, force: true })
  await rename(staging, OUT_DIR)
  const size = (await stat(join(OUT_DIR, 'index.html'))).size
  console.log(`web-vault/ ready: Cloudwarden ${v} in ${seconds} s (index.html ${size} bytes)`)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(`build-web: ${e.message}`)
    process.exit(1)
  })
}
