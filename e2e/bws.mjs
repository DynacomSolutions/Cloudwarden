// Downloads the pinned official `bws` release (TASKS #225) into e2e/.cache, verifying its sha256
// against e2e/bws.lock.json before anything is extracted or run. Linux x64 only.
import { createHash } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { inflateRawSync } from 'node:zlib'

const here = import.meta.dirname
const lock = JSON.parse(readFileSync(join(here, 'bws.lock.json'), 'utf8'))
const cache = join(here, '.cache')

/** Extracts the `bws` entry from a zip archive held in memory (stored or deflate). */
export function extractBws(zip) {
  return extractEntry(zip, 'bws')
}

/** Extracts one named entry from a zip archive held in memory (stored or deflate). */
export function extractEntry(zip, wanted) {
  const eocd = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]))
  if (eocd < 0) throw new Error('not a zip archive')
  let p = zip.readUInt32LE(eocd + 16) // central directory offset
  for (let n = zip.readUInt16LE(eocd + 10); n > 0; n--) {
    const method = zip.readUInt16LE(p + 10)
    const size = zip.readUInt32LE(p + 20)
    const nameLen = zip.readUInt16LE(p + 28)
    const extraLen = zip.readUInt16LE(p + 30)
    const commentLen = zip.readUInt16LE(p + 32)
    const local = zip.readUInt32LE(p + 42)
    const name = zip.toString('utf8', p + 46, p + 46 + nameLen)
    if (name === wanted) {
      const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28)
      const data = zip.subarray(start, start + size)
      if (method === 0) return data
      if (method === 8) return inflateRawSync(data)
      throw new Error(`unsupported zip method ${method}`)
    }
    p += 46 + nameLen + extraLen + commentLen
  }
  throw new Error(`${wanted} not found in archive`)
}

/** Path of the verified `bws` binary, downloading it on first use. */
export async function ensureBws() {
  const bin = join(cache, `bws-${lock.version}`)
  if (existsSync(bin)) return bin
  if (process.platform !== 'linux' || process.arch !== 'x64') {
    throw new Error('the bws e2e steps need Linux x64')
  }
  const res = await fetch(lock.url)
  if (!res.ok) throw new Error(`download ${lock.url}: ${res.status}`)
  const zip = Buffer.from(await res.arrayBuffer())
  const digest = createHash('sha256').update(zip).digest('hex')
  if (digest !== lock.sha256) {
    throw new Error(`bws archive sha256 ${digest} does not match the lock file ${lock.sha256}`)
  }
  mkdirSync(cache, { recursive: true })
  writeFileSync(bin, extractBws(zip))
  chmodSync(bin, 0o755)
  return bin
}
