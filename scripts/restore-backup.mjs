#!/usr/bin/env node

/**
 * Turn a Cloudwarden backup (see docs/backup.md) into SQL INSERT statements.
 *
 * Usage: node scripts/restore-backup.mjs <backup-dir> [--out-dir <dir>] [--chunk-bytes <n>]
 *
 * <backup-dir> holds manifest.json and the <table>.NNNN.jsonl part files downloaded from R2. Files are verified
 * against the manifest SHA-256 first. Without --out-dir the SQL goes to stdout; with it, numbered
 * part files are written so each stays small enough for one `cf d1 query --sql` call. Run the parts
 * in order against an empty database that already has the schema migrations applied.
 */

import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { basename, join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/

export function sqlValue(v) {
  if (v === null || v === undefined) return 'NULL'
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('non-finite number in backup')
    return String(v)
  }
  if (typeof v === 'boolean') return v ? '1' : '0'
  if (typeof v === 'string') return `'${v.replaceAll("'", "''")}'`
  if (typeof v === 'object' && typeof v.$blob === 'string') {
    return `X'${Buffer.from(v.$blob, 'base64').toString('hex')}'`
  }
  throw new Error('unsupported value in backup')
}

export function insertStatement(table, row) {
  if (!IDENT.test(table)) throw new Error('invalid table name in backup')
  const cols = Object.keys(row)
  for (const c of cols) if (!IDENT.test(c)) throw new Error('invalid column name in backup')
  return `INSERT INTO "${table}" (${cols.map((c) => `"${c}"`).join(', ')}) VALUES (${cols.map((c) => sqlValue(row[c])).join(', ')});`
}

export function tableStatements(table, jsonl) {
  return jsonl
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => insertStatement(table, JSON.parse(l)))
}

/** Read and verify a backup directory; returns an ordered list of SQL statements. */
export function buildStatements(dir) {
  const manifest = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8'))
  if (manifest.version !== 2) throw new Error(`unsupported manifest version ${manifest.version}`)
  const statements = ['PRAGMA defer_foreign_keys = on;']
  for (const t of manifest.tables) {
    if (!IDENT.test(t.name)) throw new Error('invalid table name in manifest')
    let rows = 0
    for (const part of t.parts) {
      // Parts are looked up by file name, so a directory of downloaded objects works as is.
      const data = readFileSync(join(dir, basename(part.key)))
      const digest = createHash('sha256').update(data).digest('hex')
      if (digest !== part.sha256) throw new Error(`checksum mismatch for ${basename(part.key)}`)
      const stmts = tableStatements(t.name, data.toString('utf8'))
      if (stmts.length !== part.rows)
        throw new Error(`row count mismatch for ${basename(part.key)}`)
      rows += stmts.length
      statements.push(...stmts)
    }
    if (rows !== t.rows) throw new Error(`row count mismatch for ${t.name}`)
  }
  return statements
}

export function chunk(statements, maxBytes) {
  const parts = []
  let cur = []
  let size = 0
  for (const s of statements) {
    if (cur.length && size + s.length > maxBytes) {
      parts.push(cur)
      cur = []
      size = 0
    }
    cur.push(s)
    size += s.length + 1
  }
  if (cur.length) parts.push(cur)
  return parts
}

function main(argv) {
  const args = argv.slice(2)
  const dir = args.find(
    (a) =>
      !a.startsWith('--') &&
      args[args.indexOf(a) - 1] !== '--out-dir' &&
      args[args.indexOf(a) - 1] !== '--chunk-bytes',
  )
  const opt = (name) => {
    const i = args.indexOf(name)
    return i >= 0 ? args[i + 1] : undefined
  }
  if (!dir) {
    console.error('usage: restore-backup.mjs <backup-dir> [--out-dir <dir>] [--chunk-bytes <n>]')
    process.exit(2)
  }
  const statements = buildStatements(resolve(dir))
  const outDir = opt('--out-dir')
  if (!outDir) {
    process.stdout.write(`${statements.join('\n')}\n`)
    return
  }
  const maxBytes = Number(opt('--chunk-bytes') ?? 500_000)
  mkdirSync(outDir, { recursive: true })
  chunk(statements, maxBytes).forEach((part, i) => {
    writeFileSync(
      join(outDir, `part-${String(i + 1).padStart(3, '0')}.sql`),
      `${part.join('\n')}\n`,
    )
  })
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) main(process.argv)
