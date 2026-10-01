import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { buildStatements, chunk, insertStatement } from './restore-backup.mjs'

function makeBackup(files) {
  const dir = mkdtempSync(join(tmpdir(), 'cw-backup-'))
  const tables = []
  for (const [name, text] of Object.entries(files)) {
    writeFileSync(join(dir, `${name}.jsonl`), text)
    tables.push({
      name,
      rows: text.split('\n').filter(Boolean).length,
      bytes: text.length,
      sha256: createHash('sha256').update(text).digest('hex'),
      key: `backups/2026-10-01/${name}.jsonl`,
    })
  }
  writeFileSync(
    join(dir, 'manifest.json'),
    JSON.stringify({ version: 1, createdAt: '2026-10-01T00:00:00.000Z', tables }),
  )
  return dir
}

test('escapes quotes, nulls, numbers and blobs', () => {
  const sql = insertStatement('users', { uuid: "o'brien", n: 5, x: null, b: { $blob: 'AQID' } })
  assert.equal(
    sql,
    `INSERT INTO "users" ("uuid", "n", "x", "b") VALUES ('o''brien', 5, NULL, X'010203');`,
  )
})

test('rejects hostile identifiers', () => {
  assert.throws(() => insertStatement('users"; DROP TABLE x;--', { a: 1 }))
  assert.throws(() => insertStatement('users', { 'a"b': 1 }))
})

test('builds ordered statements and verifies checksums', () => {
  const dir = makeBackup({
    users: '{"uuid":"a"}\n{"uuid":"b"}\n',
    folders: '{"uuid":"f","user_uuid":"a"}\n',
  })
  const stmts = buildStatements(dir)
  assert.equal(stmts[0], 'PRAGMA defer_foreign_keys = on;')
  assert.equal(stmts.length, 4)
})

test('detects a tampered file', () => {
  const dir = makeBackup({ users: '{"uuid":"a"}\n' })
  writeFileSync(join(dir, 'users.jsonl'), '{"uuid":"evil"}\n')
  assert.throws(() => buildStatements(dir), /checksum mismatch/)
})

test('chunks by size', () => {
  const parts = chunk(['aaaa', 'bbbb', 'cccc'], 9)
  assert.equal(parts.length, 2)
})
