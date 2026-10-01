#!/usr/bin/env node

/**
 * Fetches the official Bitwarden web vault (TASKS #143).
 *
 * The vault is published by Bitwarden as an OCI image. This script downloads a pinned image
 * (see web-vault.lock.json), checks the manifest digest and every layer sha256, extracts the web
 * root (`/app` in the image) into `web-vault/` and writes a licence notice next to it.
 * Source maps are dropped (they are large and not needed to run the vault). The Cloudwarden admin
 * link script (web-vault-overlay/admin-link.js) is then injected, see injectOverlay().
 *
 * Usage: node scripts/fetch-web-vault.mjs [--update] [--force]
 *   --update  resolve the newest stable tag, rewrite web-vault.lock.json, then fetch
 *   --force   fetch even when web-vault/ already matches the lock
 *
 * Only Bitwarden's own published image is used. Pure Node, no dependencies.
 */

import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { mkdir, readFile, rename, rm, writeFile } from 'node:fs/promises'
import { dirname, join, resolve, sep } from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import { createGunzip } from 'node:zlib'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const LOCK_PATH = join(ROOT, 'web-vault.lock.json')
const OUT_DIR = join(ROOT, 'web-vault')
const STAMP = '.fetched'
const OVERLAY_SRC = join(ROOT, 'web-vault-overlay', 'admin-link.js')
export const OVERLAY_PATH = 'cloudwarden/admin-link.js'
const REGISTRY = 'ghcr.io'
const REPO = 'bitwarden/web'
const WEB_ROOT = 'app/'
const PLATFORM = { os: 'linux', architecture: 'amd64' }
const STABLE_TAG = /^\d{4}\.\d+\.\d+$/
const ACCEPT = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.docker.distribution.manifest.v2+json',
].join(',')

const sha256 = (buf) => `sha256:${createHash('sha256').update(buf).digest('hex')}`

async function token() {
  const res = await fetch(`https://${REGISTRY}/token?scope=repository:${REPO}:pull`)
  if (!res.ok) throw new Error(`token request failed: ${res.status}`)
  return (await res.json()).token
}

async function registry(path, tok, accept = ACCEPT) {
  const res = await fetch(`https://${REGISTRY}/v2/${REPO}/${path}`, {
    headers: { Authorization: `Bearer ${tok}`, Accept: accept },
    redirect: 'follow',
  })
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`)
  return res
}

const compareVersions = (a, b) => {
  const x = a.split('.').map(Number)
  const y = b.split('.').map(Number)
  return x[0] - y[0] || x[1] - y[1] || x[2] - y[2]
}

async function newestStableTag(tok) {
  const tags = []
  let url = `https://${REGISTRY}/v2/${REPO}/tags/list?n=1000`
  while (url) {
    const res = await fetch(url, { headers: { Authorization: `Bearer ${tok}` } })
    if (!res.ok) throw new Error(`tag list failed: ${res.status}`)
    tags.push(...((await res.json()).tags ?? []))
    const next = /<([^>]+)>;\s*rel="next"/.exec(res.headers.get('link') ?? '')
    url = next ? new URL(next[1], `https://${REGISTRY}`).toString() : null
  }
  const stable = tags.filter((t) => STABLE_TAG.test(t)).sort(compareVersions)
  if (stable.length === 0) throw new Error('no stable tags found')
  return stable[stable.length - 1]
}

async function resolveLock(tag, tok) {
  const indexRes = await registry(`manifests/${tag}`, tok)
  const indexBytes = Buffer.from(await indexRes.arrayBuffer())
  const index = JSON.parse(indexBytes.toString('utf8'))
  const entry = index.manifests?.find(
    (m) => m.platform?.os === PLATFORM.os && m.platform?.architecture === PLATFORM.architecture,
  )
  if (!entry) throw new Error(`no ${PLATFORM.os}/${PLATFORM.architecture} manifest for ${tag}`)
  const manifestBytes = Buffer.from(
    await (await registry(`manifests/${entry.digest}`, tok)).arrayBuffer(),
  )
  if (sha256(manifestBytes) !== entry.digest) throw new Error('manifest digest mismatch')
  const manifest = JSON.parse(manifestBytes.toString('utf8'))
  return {
    image: `${REGISTRY}/${REPO}`,
    tag,
    indexDigest: sha256(indexBytes),
    platform: `${PLATFORM.os}/${PLATFORM.architecture}`,
    manifestDigest: entry.digest,
    layers: manifest.layers.map((l) => ({ digest: l.digest, size: l.size })),
  }
}

/** Minimal streaming tar reader: yields { name, type, data } for files and directories. */
async function* tarEntries(stream) {
  let buf = Buffer.alloc(0)
  let pax = {}
  let longName = null
  const it = stream[Symbol.asyncIterator]()
  const need = async (n) => {
    while (buf.length < n) {
      const { value, done } = await it.next()
      if (done) return false
      buf = Buffer.concat([buf, value])
    }
    return true
  }
  const str = (b, a, l) => b.toString('utf8', a, a + l).replace(/\0.*$/s, '')
  while (await need(512)) {
    const h = buf.subarray(0, 512)
    buf = buf.subarray(512)
    if (h.every((b) => b === 0)) continue
    const type = String.fromCharCode(h[156] || 48)
    let size
    if (h[124] & 0x80) {
      size = Number(h.readBigUInt64BE(120) & 0x7fffffffffffffffn)
    } else {
      size = Number.parseInt(str(h, 124, 12).trim() || '0', 8)
    }
    const prefix = str(h, 345, 155)
    let name = prefix ? `${prefix}/${str(h, 0, 100)}` : str(h, 0, 100)
    const padded = Math.ceil(size / 512) * 512
    const wanted = type === 'x' || type === 'L' || type === '0' || type === '5'
    let data = Buffer.alloc(0)
    if (wanted) {
      if (!(await need(padded))) throw new Error('truncated tar')
      data = buf.subarray(0, size)
      buf = buf.subarray(padded)
    } else {
      // Skip the body without buffering it all.
      let left = padded
      while (left > 0) {
        if (buf.length === 0 && !(await need(1))) throw new Error('truncated tar')
        const take = Math.min(left, buf.length)
        buf = buf.subarray(take)
        left -= take
      }
    }
    if (type === 'x') {
      pax = {}
      for (const m of data.toString('utf8').matchAll(/\d+ (\w+)=([^\n]*)\n/g)) pax[m[1]] = m[2]
      continue
    }
    if (type === 'L') {
      longName = data.toString('utf8').replace(/\0.*$/s, '')
      continue
    }
    name = pax.path ?? longName ?? name
    pax = {}
    longName = null
    if (wanted) yield { name, type, data }
  }
}

/** Downloads one layer, verifies its sha256 and extracts the web root into `dest`. */
async function extractLayer(layer, tok, dest) {
  const res = await registry(`blobs/${layer.digest}`, tok, '*/*')
  const hash = createHash('sha256')
  let size = 0
  const raw = Readable.fromWeb(res.body)
  raw.on('data', (c) => {
    hash.update(c)
    size += c.length
  })
  const tar = raw.pipe(createGunzip())
  raw.on('error', (e) => tar.destroy(e))
  let files = 0
  for await (const e of tarEntries(tar)) {
    const name = e.name.replace(/^\.\//, '')
    if (!name.startsWith(WEB_ROOT) || name.endsWith('.map')) continue
    const target = resolve(dest, name.slice(WEB_ROOT.length))
    if (target !== dest && !target.startsWith(dest + sep)) throw new Error(`unsafe path: ${name}`)
    if (e.type === '5') {
      await mkdir(target, { recursive: true })
    } else {
      await mkdir(dirname(target), { recursive: true })
      await writeFile(target, e.data)
      files++
    }
  }
  // Drain anything left (tar padding) so the digest covers the whole blob.
  for await (const _ of tar) void _
  if (`sha256:${hash.digest('hex')}` !== layer.digest) {
    throw new Error(`layer digest mismatch for ${layer.digest}`)
  }
  if (size !== layer.size) throw new Error(`layer size mismatch for ${layer.digest}`)
  return files
}

/**
 * Static asset headers (Workers `_headers` file). The vault needs `wasm-unsafe-eval` for its
 * WebAssembly SDK and inline styles for Angular. Everything else is same-origin, including the
 * API, identity, notification and icon routes served by the Worker.
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self' wss: https://api.pwnedpasswords.com",
  "frame-src 'self' https://*.duosecurity.com https://*.duofederatedsecurity.com",
  "worker-src 'self' blob:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'self'",
].join('; ')

const HEADERS = `/*
  Content-Security-Policy: ${CSP}
  X-Content-Type-Options: nosniff
  X-Frame-Options: SAMEORIGIN
  Referrer-Policy: same-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
/index.html
  Cache-Control: no-cache
`

/** Subresource Integrity value (sha384) for a script body. */
export const sri = (buf) => `sha384-${createHash('sha384').update(buf).digest('base64')}`

const TAG_RE = /[ \t]*<script src="cloudwarden\/admin-link\.js"[^>]*><\/script>\n?/g

/**
 * Copies the admin link script into `dir` and references it from index.html, once, with an
 * integrity attribute. Deterministic and idempotent: any previous tag is replaced, so rerunning
 * yields identical files.
 */
export async function injectOverlay(dir, source = OVERLAY_SRC) {
  const script = await readFile(source)
  await mkdir(join(dir, 'cloudwarden'), { recursive: true })
  await writeFile(join(dir, OVERLAY_PATH), script)
  const indexPath = join(dir, 'index.html')
  const index = (await readFile(indexPath, 'utf8')).replace(TAG_RE, '')
  if (!index.includes('</head>')) throw new Error('index.html has no </head>')
  const tag = `<script src="${OVERLAY_PATH}" integrity="${sri(script)}" defer></script>\n`
  await writeFile(indexPath, index.replace('</head>', `${tag}</head>`))
}

const notice = (lock) => `Bitwarden web vault ${lock.tag}
================================

This directory contains the official Bitwarden web vault, unmodified apart from the removal of
source maps and the app-id.json file (served dynamically by the Worker), and one added script tag in
index.html that loads cloudwarden/admin-link.js (Cloudwarden's own admin link, not Bitwarden code).

  Source:   ${lock.image}:${lock.tag}
  Digest:   ${lock.manifestDigest} (${lock.platform})
  Upstream: https://github.com/bitwarden/clients

The web vault is Copyright Bitwarden Inc. and licensed under the GNU General Public License,
version 3 (GPL-3.0). The complete corresponding source code for this exact version is available
from the upstream repository above (apps/web, tag web-v${lock.tag}). The licence text is at
https://www.gnu.org/licenses/gpl-3.0.txt

Bitwarden is a trademark of Bitwarden Inc. This deployment is not affiliated with or endorsed by
Bitwarden Inc.
`

async function main() {
  const args = new Set(process.argv.slice(2))
  const tok = await token()
  let lock
  if (args.has('--update') || !existsSync(LOCK_PATH)) {
    const tag = await newestStableTag(tok)
    lock = await resolveLock(tag, tok)
    await writeFile(LOCK_PATH, `${JSON.stringify(lock, null, 2)}\n`)
    console.log(`lock updated: ${lock.tag} ${lock.manifestDigest}`)
  } else {
    lock = JSON.parse(await readFile(LOCK_PATH, 'utf8'))
  }

  const stamp = join(OUT_DIR, STAMP)
  if (
    !args.has('--force') &&
    existsSync(stamp) &&
    readFileSync(stamp, 'utf8').trim() === lock.manifestDigest
  ) {
    await injectOverlay(OUT_DIR)
    console.log(`web-vault/ is up to date (${lock.tag})`)
    return
  }

  // Re-check the manifest against the pinned digest and the pinned layer list.
  const manifestBytes = Buffer.from(
    await (await registry(`manifests/${lock.manifestDigest}`, tok)).arrayBuffer(),
  )
  if (sha256(manifestBytes) !== lock.manifestDigest) throw new Error('manifest digest mismatch')
  const layers = JSON.parse(manifestBytes.toString('utf8')).layers.map((l) => l.digest)
  if (JSON.stringify(layers) !== JSON.stringify(lock.layers.map((l) => l.digest))) {
    throw new Error('manifest layers differ from the lock file')
  }

  const staging = `${OUT_DIR}.tmp`
  await rm(staging, { recursive: true, force: true })
  await mkdir(staging, { recursive: true })
  let total = 0
  for (const [i, layer] of lock.layers.entries()) {
    const n = await extractLayer(layer, await token(), staging)
    total += n
    console.log(`layer ${i + 1}/${lock.layers.length} verified (${n} files)`)
  }
  if (!existsSync(join(staging, 'index.html'))) throw new Error('index.html not found in image')
  // The Worker serves /app-id.json from DOMAIN; the upstream copy lists Bitwarden origins.
  await rm(join(staging, 'app-id.json'), { force: true })
  await writeFile(join(staging, 'LICENSE-NOTICE.txt'), notice(lock))
  await writeFile(join(staging, '_headers'), HEADERS)
  await injectOverlay(staging)
  await writeFile(join(staging, STAMP), `${lock.manifestDigest}\n`)
  await rm(OUT_DIR, { recursive: true, force: true })
  await rename(staging, OUT_DIR)
  console.log(`web-vault/ ready: ${lock.tag}, ${total} files`)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(`fetch-web-vault: ${e.message}`)
    process.exit(1)
  })
}
