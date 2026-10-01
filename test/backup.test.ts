import { env } from 'cloudflare:workers'
import { scheduled } from '../src/scheduled'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  EXCLUDED_TABLES,
  exportDatabase,
  listTables,
  pruneBackups,
  runBackup,
  scheduled,
} from '../src/backup'

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

  it('exports all rows across pages and part files with a manifest', async () => {
    // Tiny part size forces many parts, proving no whole-table buffering.
    const { prefix, manifest } = await exportDatabase(env.DB, env.ATTACHMENTS, NOW, 100, 4096)
    expect(prefix).toBe('backups/2026-10-01/run-1790824620/')
    const t = manifest.tables.find((x) => x.name === 'zz_backup_test')
    expect(t?.rows).toBe(1203)
    expect(t?.parts.length ?? 0).toBeGreaterThan(3)
    for (const p of t?.parts ?? []) expect(p.bytes).toBeLessThan(4096 + 200)
    const rows: Record<string, unknown>[] = []
    for (const p of t?.parts ?? []) {
      const bytes = new Uint8Array(
        (await (await env.ATTACHMENTS.get(p.key))?.arrayBuffer()) ?? new ArrayBuffer(0),
      )
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
      expect(Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('')).toBe(p.sha256)
      rows.push(...(await readJsonl(p.key)))
    }
    expect(rows.length).toBe(1203)
    expect(rows[0]).toEqual({ id: 1, label: "it's", n: 0, b: null })
    expect(rows[1]?.b).toEqual({ $blob: 'AQID' })
    expect(rows.at(-1)?.id).toBe(1203)
    expect('__rowid' in (rows[0] ?? {})).toBe(false)
    expect(t?.parts.reduce((n, p) => n + p.rows, 0)).toBe(1203)

    const stored = JSON.parse(
      (await (await env.ATTACHMENTS.get(`${prefix}manifest.json`))?.text()) ?? '{}',
    )
    expect(stored.version).toBe(2)
    expect(stored.tables.length).toBe(manifest.tables.length)
  })

  it('writes no parts for empty tables', async () => {
    const { manifest } = await exportDatabase(env.DB, env.ATTACHMENTS, NOW)
    expect(manifest.tables.find((t) => t.name === 'folders')?.parts).toEqual([])
  })

  it('redacts device credentials', async () => {
    const now = Date.now()
    await env.DB.prepare(
      "INSERT INTO users (uuid, email, name, password_hash, salt, password_iterations, akey, security_stamp, created_at, updated_at) VALUES ('u-bk', 'bk@example.com', 'n', 'h', 's', 1, 'k', 'st', ?, ?)",
    )
      .bind(now, now)
      .run()
    await env.DB.prepare(
      "INSERT INTO devices (uuid, user_uuid, name, type, identifier, push_token, refresh_token, twofactor_remember, created_at, updated_at) VALUES ('d-bk', 'u-bk', 'dev', 1, 'ident-bk', 'PUSHSECRET', 'REFRESHSECRET', 'REMEMBERSECRET', ?, ?)",
    )
      .bind(now, now)
      .run()
    try {
      const { manifest } = await exportDatabase(env.DB, env.ATTACHMENTS, NOW)
      const part = manifest.tables.find((t) => t.name === 'devices')?.parts[0]
      const text = (await (await env.ATTACHMENTS.get(part?.key ?? ''))?.text()) ?? ''
      expect(text).not.toContain('SECRET')
      const row = JSON.parse(text.trim().split('\n')[0] ?? '{}')
      expect(row).toMatchObject({
        uuid: 'd-bk',
        refresh_token: '',
        push_token: null,
        twofactor_remember: null,
      })
    } finally {
      await env.DB.exec("DELETE FROM users WHERE uuid = 'u-bk'")
    }
  })

  it('a rerun replaces a stale manifest and a failed run leaves no parts', async () => {
    const later = new Date(NOW.getTime() + 60_000)
    const prefix = 'backups/2026-10-01/run-1790824680/'
    await env.ATTACHMENTS.put(`${prefix}manifest.json`, 'stale')
    const failing = {
      prepare: (sql: string) => {
        if (sql.includes('zz_backup_test') && sql.includes('rowid >')) throw new Error('boom')
        return env.DB.prepare(sql)
      },
    } as unknown as D1Database
    await expect(exportDatabase(failing, env.ATTACHMENTS, later)).rejects.toThrow('boom')
    expect(await env.ATTACHMENTS.get(`${prefix}manifest.json`)).toBeNull()
    const left = (await env.ATTACHMENTS.list({ prefix })).objects.map((o) => o.key)
    expect(left).toEqual([])
  })

  it('prunes backups older than 14 days and keeps the rest', async () => {
    for (const d of ['2026-09-10', '2026-09-17', '2026-09-18', '2026-09-30']) {
      await env.ATTACHMENTS.put(`backups/${d}/run-1/manifest.json`, '{}')
      await env.ATTACHMENTS.put(`backups/${d}/run-1/users.0001.jsonl`, '')
    }
    await env.ATTACHMENTS.put('attachments/keep-me', 'x')
    const deleted = await pruneBackups(env.ATTACHMENTS, NOW)
    expect(deleted).toBe(4)
    const keys = (await env.ATTACHMENTS.list({ prefix: 'backups/' })).objects.map((o) => o.key)
    expect(keys).toContain('backups/2026-09-18/run-1/manifest.json')
    expect(keys).toContain('backups/2026-09-30/run-1/users.0001.jsonl')
    expect(
      keys.some((k) => k.startsWith('backups/2026-09-10/') || k.startsWith('backups/2026-09-17/')),
    ).toBe(false)
    expect(await env.ATTACHMENTS.get('attachments/keep-me')).not.toBeNull()
  })

  it('the scheduled handler awaits the export so failures surface', async () => {
    const broken = {
      DB: {
        prepare: () => {
          throw new Error('db down')
        },
      },
      ATTACHMENTS: env.ATTACHMENTS,
    } as unknown as typeof env
    const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext
    await expect(
      scheduled(
        {
          scheduledTime: NOW.getTime(),
          cron: '',
          type: 'scheduled',
          noRetry() {},
        } as ScheduledController,
        broken,
        ctx,
      ),
    ).rejects.toThrow('db down')
  })

  it('runBackup reports totals', async () => {
    const res = await runBackup(env, NOW)
    expect(res.prefix).toBe('backups/2026-10-01/run-1790824620/')
    expect(res.rows).toBeGreaterThanOrEqual(1203)
  })
})
