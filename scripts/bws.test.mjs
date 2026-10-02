// Archive handling and lock file of the pinned `bws` download (TASKS #225).
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { deflateRawSync } from 'node:zlib'
import { extractBws } from '../e2e/bws.mjs'

/** A one-entry zip with the given compression method (0 stored, 8 deflate). */
function zipOf(name, content, method) {
  const data = method === 8 ? deflateRawSync(content) : content
  const n = Buffer.from(name)
  const local = Buffer.alloc(30)
  local.writeUInt32LE(0x04034b50, 0)
  local.writeUInt16LE(method, 8)
  local.writeUInt32LE(data.length, 18)
  local.writeUInt32LE(content.length, 22)
  local.writeUInt16LE(n.length, 26)
  const central = Buffer.alloc(46)
  central.writeUInt32LE(0x02014b50, 0)
  central.writeUInt16LE(method, 10)
  central.writeUInt32LE(data.length, 20)
  central.writeUInt32LE(content.length, 24)
  central.writeUInt16LE(n.length, 28)
  const head = Buffer.concat([local, n, data])
  const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0)
  eocd.writeUInt16LE(1, 8)
  eocd.writeUInt16LE(1, 10)
  eocd.writeUInt32LE(central.length + n.length, 12)
  eocd.writeUInt32LE(head.length, 16)
  return Buffer.concat([head, central, n, eocd])
}

test('extracts bws from stored and deflated archives', () => {
  const body = Buffer.from('#!binary'.repeat(50))
  assert.ok(extractBws(zipOf('bws', body, 0)).equals(body))
  assert.ok(extractBws(zipOf('bws', body, 8)).equals(body))
})

test('rejects archives without bws and non-archives', () => {
  assert.throws(() => extractBws(zipOf('other', Buffer.from('x'), 0)), /not found/)
  assert.throws(() => extractBws(Buffer.from('nope')), /not a zip/)
})

test('lock file pins an official sdk-sm release with a sha256', () => {
  const lock = JSON.parse(readFileSync(new URL('../e2e/bws.lock.json', import.meta.url), 'utf8'))
  assert.match(lock.sha256, /^[0-9a-f]{64}$/)
  assert.ok(lock.url.startsWith('https://github.com/bitwarden/sdk-sm/releases/download/'))
  assert.ok(lock.url.includes(lock.version))
})
