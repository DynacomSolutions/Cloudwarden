import { env } from 'cloudflare:workers'
import { scheduled } from '../src/scheduled'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { EXCLUDED_TABLES, exportDatabase, listTables, pruneBackups, runBackup } from '../src/backup'

const NOW = new Date('2026-10-01T03:17:00Z')

async function readJsonl(key: string) {
  const text = await (await env.ATTACHMENTS.get(key))?.text()
  return (text ?? '')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Record<string, unknown>)
}

describe('D1 export to R2', () => {
  beforeAll(async () => {
    await env.DB.exec(
      'CREATE TABLE zz_backup_test (id INTEGER PRIMARY KEY, label TEXT, n REAL, b BLOB)',
    )
    const stmts = Array.from({ length: 1203 }, (_, i) =>
      env.DB.prepare('INSERT INTO zz_backup_test (id, label, n, b) VALUES (?, ?, ?, ?)').bind(
        i + 1,
        i === 0 ? "it's" : `row ${i}`,
        i / 2,
        i === 1 ? new Uint8Array([1, 2, 3]) : null,
      ),
    )
    for (let i = 0; i < stmts.length; i += 100) await env.DB.batch(stmts.slice(i, i + 100))
  })
  afterAll(async () => {
    await env.DB.exec('DROP TABLE zz_backup_test')
  })

  it('lists every table except migrations bookkeeping and ephemeral auth state', async () => {
    const tables = await listTables(env.DB)
    expect(tables).toContain('users')
    expect(tables).toContain('zz_backup_test')
    expect(tables).not.toContain('d1_migrations')
    for (const t of EXCLUDED_TABLES) expect(tables).not.toContain(t)
  })

  it('exports all rows across pages with a manifest', async () => {
    const { prefix, manifest } = await exportDatabase(env.DB, env.ATTACHMENTS, NOW, 100)
    expect(prefix).toBe('backups/2026-10-01/')
    const t = manifest.tables.find((x) => x.name === 'zz_backup_test')
    expect(t?.rows).toBe(1203)
    const rows = await readJsonl(`${prefix}zz_backup_test.jsonl`)
    expect(rows.length).toBe(1203)
    expect(rows[0]).toEqual({ id: 1, label: "it's", n: 0, b: null })
    expect(rows[1]?.b).toEqual({ $blob: 'AQID' })
    expect(rows.at(-1)?.id).toBe(1203)
    expect('__rowid' in (rows[0] ?? {})).toBe(false)

    const stored = JSON.parse(
      (await (await env.ATTACHMENTS.get(`${prefix}manifest.json`))?.text()) ?? '{}',
    )
    expect(stored.version).toBe(1)
    expect(stored.tables.length).toBe(manifest.tables.length)
    const bytes = new Uint8Array(
      (await (await env.ATTACHMENTS.get(t?.key ?? ''))?.arrayBuffer()) ?? new ArrayBuffer(0),
    )
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
    expect(Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')).toBe(t?.sha256)
  })

  it('writes empty tables as empty files', async () => {
    const { prefix } = await exportDatabase(env.DB, env.ATTACHMENTS, NOW)
    expect((await env.ATTACHMENTS.get(`${prefix}folders.jsonl`))?.size).toBe(0)
  })

  it('prunes backups older than 14 days and keeps the rest', async () => {
    for (const d of ['2026-09-10', '2026-09-17', '2026-09-18', '2026-09-30']) {
      await env.ATTACHMENTS.put(`backups/${d}/manifest.json`, '{}')
      await env.ATTACHMENTS.put(`backups/${d}/users.jsonl`, '')
    }
    await env.ATTACHMENTS.put('attachments/keep-me', 'x')
    const deleted = await pruneBackups(env.ATTACHMENTS, NOW)
    expect(deleted).toBe(4)
    const keys = (await env.ATTACHMENTS.list({ prefix: 'backups/' })).objects.map((o) => o.key)
    expect(keys).toContain('backups/2026-09-18/manifest.json')
    expect(keys).toContain('backups/2026-09-30/users.jsonl')
    expect(
      keys.some((k) => k.startsWith('backups/2026-09-10/') || k.startsWith('backups/2026-09-17/')),
    ).toBe(false)
    expect(await env.ATTACHMENTS.get('attachments/keep-me')).not.toBeNull()
  })

  it('runBackup reports totals', async () => {
    const res = await runBackup(env, NOW)
    expect(res.prefix).toBe('backups/2026-10-01/')
    expect(res.rows).toBeGreaterThanOrEqual(1203)
  })
})
