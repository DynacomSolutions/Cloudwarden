// Downloads the pinned official Directory Connector CLI, `bwdc` (GPL-3.0, TASKS #262), into
// e2e/.cache after checking its sha256 against e2e/bwdc.lock.json. Linux x64 only. The archive
// holds the `bwdc` binary and its native module, which must sit next to it.
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { extractEntry } from './bws.mjs'

const here = import.meta.dirname
const lock = JSON.parse(readFileSync(join(here, 'bwdc.lock.json'), 'utf8'))

/** Path of the verified `bwdc` binary, downloading it on first use. */
export async function ensureBwdc() {
  const dir = join(here, '.cache', `bwdc-${lock.version}`)
  const bin = join(dir, 'bwdc')
  if (existsSync(bin)) return bin
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
  return bin
}
