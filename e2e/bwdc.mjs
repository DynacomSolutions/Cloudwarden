// Downloads the pinned official Directory Connector CLI, `bwdc` (GPL-3.0, TASKS #262), into
// e2e/.cache after checking its sha256 against e2e/bwdc.lock.json. Linux x64 only. The archive
// holds the `bwdc` binary and its native module, which must sit next to it.
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { extractEntry } from './bws.mjs'

const here = import.meta.dirname
const lock = JSON.parse(readFileSync(join(here, 'bwdc.lock.json'), 'utf8'))

/**
 * The binary links against `libatomic.so.1`, which slim runner images lack. When the loader cannot
 * find it, the pinned Debian package (e2e/bwdc.lock.json, sha256 checked) is unpacked next to the
 * binary without root, and the returned environment points `LD_LIBRARY_PATH` at it.
 */
async function libatomicEnv(dir) {
  if (spawnSync('sh', ['-c', 'ldconfig -p | grep -q libatomic.so.1']).status === 0) return {}
  const libs = join(dir, 'libatomic')
  const so = join(libs, 'usr', 'lib', 'x86_64-linux-gnu')
  if (!existsSync(join(so, 'libatomic.so.1'))) {
    const res = await fetch(lock.libatomic.url)
    if (!res.ok) throw new Error(`download ${lock.libatomic.url}: ${res.status}`)
    const deb = Buffer.from(await res.arrayBuffer())
    const digest = createHash('sha256').update(deb).digest('hex')
    if (digest !== lock.libatomic.sha256) throw new Error(`libatomic1 sha256 ${digest} mismatch`)
    // A .deb is an ar archive: 8 byte magic, then 60 byte member headers.
    let p = 8
    let data = null
    let name = ''
    while (p + 60 <= deb.length) {
      name = deb
        .toString('ascii', p, p + 16)
        .trim()
        .replace(/\/$/, '')
      const size = Number.parseInt(deb.toString('ascii', p + 48, p + 58).trim(), 10)
      if (name.startsWith('data.tar')) {
        data = deb.subarray(p + 60, p + 60 + size)
        break
      }
      p += 60 + size + (size % 2)
    }
    if (!data) throw new Error('libatomic1 package has no data archive')
    mkdirSync(libs, { recursive: true })
    const tarball = join(libs, name)
    writeFileSync(tarball, data)
    const x = spawnSync('tar', ['-xf', tarball, '-C', libs], { encoding: 'utf8' })
    if (x.status !== 0) throw new Error(`tar failed: ${x.stderr}`)
  }
  return { LD_LIBRARY_PATH: [so, process.env.LD_LIBRARY_PATH].filter(Boolean).join(':') }
}

/** The verified `bwdc` binary (downloaded on first use) and extra environment it needs. */
export async function ensureBwdc() {
  const dir = join(here, '.cache', `bwdc-${lock.version}`)
  const bin = join(dir, 'bwdc')
  if (existsSync(bin)) return { bin, env: await libatomicEnv(dir) }
  if (process.platform !== 'linux' || process.arch !== 'x64') {
    throw new Error('the bwdc e2e steps need Linux x64')
  }
  const res = await fetch(lock.url)
  if (!res.ok) throw new Error(`download ${lock.url}: ${res.status}`)
  const zip = Buffer.from(await res.arrayBuffer())
  const digest = createHash('sha256').update(zip).digest('hex')
  if (digest !== lock.sha256) {
    throw new Error(`bwdc archive sha256 ${digest} does not match the lock file ${lock.sha256}`)
  }
  mkdirSync(dir, { recursive: true })
  writeFileSync(
    join(dir, 'dc_native.linux-x64-gnu.node'),
    extractEntry(zip, 'dc_native.linux-x64-gnu.node'),
  )
  writeFileSync(bin, extractEntry(zip, 'bwdc'))
  chmodSync(bin, 0o755)
  return { bin, env: await libatomicEnv(dir) }
}
