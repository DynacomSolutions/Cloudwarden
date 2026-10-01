import { errorKind, log } from './log'

/**
 * Scheduled D1 export to R2 (TASKS #162). Each run writes one JSONL file per table plus a manifest
 * under `backups/<YYYY-MM-DD>/`. The manifest is written last, so a prefix without one is an
 * incomplete run. Backups hold encrypted vault data and password hashes: keep the bucket private.
 */

export const BACKUP_PREFIX = 'backups/'
export const RETENTION_DAYS = 14
/** Cron expression (see cloudflare.config.ts) that triggers the export; other crons skip it. */
export const BACKUP_CRON = '17 3 * * *'
export const PAGE_SIZE = 500

/** Short-lived auth state that is useless after a restore and sensitive to keep. */
export const EXCLUDED_TABLES = new Set([
  'admin_login_tokens',
  'admin_rate_limits',
  'admin_sessions',
])

export interface ManifestTable {
  name: string
  rows: number
  bytes: number
  sha256: string
  key: string
}

export interface Manifest {
  version: 1
  createdAt: string
  tables: ManifestTable[]
}

export interface BackupResult {
  prefix: string
  tables: number
  rows: number
  deleted: number
}

const quote = (name: string) => `"${name.replace(/"/g, '""')}"`

function toBase64(bytes: number[]): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

/** JSON replacer: D1 returns BLOB columns as number arrays; tag them so restore can rebuild them. */
function encodeRow(row: Record<string, unknown>): string {
  const out: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(row))
    out[k] = Array.isArray(v) ? { $blob: toBase64(v as number[]) } : v
  return JSON.stringify(out)
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  return Array.from(d, (b) => b.toString(16).padStart(2, '0')).join('')
}

export async function listTables(db: D1Database): Promise<string[]> {
  const { results } = await db
    .prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' AND name != 'd1_migrations' ORDER BY name",
    )
    .all<{ name: string }>()
  return results.map((r) => r.name).filter((n) => !EXCLUDED_TABLES.has(n))
}

/** Page through a table by rowid so memory use per query stays bounded and ordering is stable. */
export async function* readTable(
  db: D1Database,
  table: string,
  pageSize = PAGE_SIZE,
): AsyncGenerator<Record<string, unknown>[]> {
  let after = -1
  for (;;) {
    const { results } = await db
      .prepare(
        `SELECT rowid AS __rowid, * FROM ${quote(table)} WHERE rowid > ? ORDER BY rowid LIMIT ?`,
      )
      .bind(after, pageSize)
      .all<Record<string, unknown>>()
    if (results.length === 0) return
    after = results[results.length - 1]?.__rowid as number
    yield results.map(({ __rowid, ...row }) => row)
    if (results.length < pageSize) return
  }
}

export function backupDate(now: Date): string {
  return now.toISOString().slice(0, 10)
}

export async function exportDatabase(
  db: D1Database,
  bucket: R2Bucket,
  now: Date,
  pageSize = PAGE_SIZE,
): Promise<{ prefix: string; manifest: Manifest }> {
  const prefix = `${BACKUP_PREFIX}${backupDate(now)}/`
  const encoder = new TextEncoder()
  const tables: ManifestTable[] = []

  for (const name of await listTables(db)) {
    const lines: string[] = []
    let rows = 0
    for await (const page of readTable(db, name, pageSize)) {
      for (const row of page) lines.push(encodeRow(row))
      rows += page.length
    }
    const bytes = encoder.encode(lines.length ? `${lines.join('\n')}\n` : '')
    const key = `${prefix}${name}.jsonl`
    await bucket.put(key, bytes, { httpMetadata: { contentType: 'application/x-ndjson' } })
    tables.push({ name, rows, bytes: bytes.length, sha256: await sha256Hex(bytes), key })
  }

  const manifest: Manifest = { version: 1, createdAt: now.toISOString(), tables }
  await bucket.put(`${prefix}manifest.json`, JSON.stringify(manifest, null, 2), {
    httpMetadata: { contentType: 'application/json' },
  })
  return { prefix, manifest }
}

/** Delete backup prefixes older than the retention window. Returns the number of objects removed. */
export async function pruneBackups(
  bucket: R2Bucket,
  now: Date,
  keepDays = RETENTION_DAYS,
): Promise<number> {
  const today = Date.parse(backupDate(now))
  let deleted = 0
  let cursor: string | undefined
  for (;;) {
    const page = await bucket.list({ prefix: BACKUP_PREFIX, cursor })
    const stale = page.objects
      .map((o) => o.key)
      .filter((key) => {
        const date = /^backups\/(\d{4}-\d{2}-\d{2})\//.exec(key)?.[1]
        if (!date) return false
        const ageDays = (today - Date.parse(date)) / 86_400_000
        return ageDays >= keepDays
      })
    for (let i = 0; i < stale.length; i += 1000) await bucket.delete(stale.slice(i, i + 1000))
    deleted += stale.length
    if (!page.truncated) break
    cursor = page.cursor
  }
  return deleted
}

export async function runBackup(
  env: { DB: D1Database; ATTACHMENTS: R2Bucket },
  now: Date,
): Promise<BackupResult> {
  try {
    const { prefix, manifest } = await exportDatabase(env.DB, env.ATTACHMENTS, now)
    const deleted = await pruneBackups(env.ATTACHMENTS, now)
    const rows = manifest.tables.reduce((n, t) => n + t.rows, 0)
    log('info', 'backup.done', { prefix, tables: manifest.tables.length, rows, deleted })
    return { prefix, tables: manifest.tables.length, rows, deleted }
  } catch (err) {
    log('error', 'backup.failed', { errorKind: errorKind(err) })
    throw err
  }
}
