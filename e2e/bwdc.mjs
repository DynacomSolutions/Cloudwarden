// Downloads the pinned official Directory Connector CLI, `bwdc` (GPL-3.0, TASKS #262), into
// e2e/.cache after checking its sha256 against e2e/bwdc.lock.json. Linux x64 only. The archive
// holds the `bwdc` binary and its native module, which must sit next to it.
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { extractEntry } from './bws.mjs'

const here = import.meta.dirname
const lock = JSON.parse(readFileSync(join(here, 'bwdc.lock.json'), 'utf8'))

/**
 * The binary links against `libatomic.so.1`, which slim runner images lack. When the loader cannot
 * find it, the Debian or Ubuntu package is fetched without root (`apt-get download`) and unpacked
 * next to the binary; the returned environment points `LD_LIBRARY_PATH` at it.
 */
function libatomicEnv(dir) {
  const has = spawnSync('sh', ['-c', 'ldconfig -p | grep -q libatomic.so.1'])
  if (has.status === 0) return {}
  const libs = join(dir, 'libatomic')
  if (!existsSync(libs)) {
    mkdirSync(libs, { recursive: true })
    const dl = spawnSync('apt-get', ['download', 'libatomic1'], { cwd: libs, encoding: 'utf8' })
    if (dl.status !== 0)
      throw new Error(`libatomic.so.1 missing and apt-get download failed: ${dl.stderr}`)
    const deb = readdirSync(libs).find((f) => f.endsWith('.deb'))
    const x = spawnSync('dpkg-deb', ['-x', join(libs, deb), libs], { encoding: 'utf8' })
    if (x.status !== 0) throw new Error(`dpkg-deb failed: ${x.stderr}`)
  }
  const found = spawnSync(
    'sh',
    ['-c', `dirname "$(find "${libs}" -name 'libatomic.so.1*' | head -n 1)"`],
    {
      encoding: 'utf8',
    },
  ).stdout.trim()
  return { LD_LIBRARY_PATH: [found, process.env.LD_LIBRARY_PATH].filter(Boolean).join(':') }
}

/** The verified `bwdc` binary (downloaded on first use) and extra environment it needs. */
export async function ensureBwdc() {
  const dir = join(here, '.cache', `bwdc-${lock.version}`)
  const bin = join(dir, 'bwdc')
  if (existsSync(bin)) return { bin, env: libatomicEnv(dir) }
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
  return { bin, env: libatomicEnv(dir) }
}
