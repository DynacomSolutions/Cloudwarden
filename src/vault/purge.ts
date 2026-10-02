import { and, inArray, isNotNull, isNull, lt, lte } from 'drizzle-orm'
import { createDb, runBatch, schema } from '../db'
import type { Bindings } from '../env'
import { errorKind, log } from '../log'
import { deleteBlobsNow } from './blobs'
import { chunk } from './ciphers'

/** Uploads not completed within this window are abandoned. */
const PENDING_GRACE_MS = 24 * 60 * 60 * 1000
/** Objects younger than this are never treated as orphans (an upload may be in flight). */
const ORPHAN_GRACE_MS = 60 * 60 * 1000
const BATCH = 200
const ORPHAN_PAGE = 500
const CURSOR_KEY = 'meta/orphan-cursor'

export interface PurgeResult {
  sends: number
  attachments: number
  orphans: number
}

/** Deletes Sends past their deletion date or with an abandoned file upload, with their blobs. */
async function purgeSends(env: Bindings, now: number): Promise<number> {
  const db = createDb(env.DB)
  let total = 0
  for (let round = 0; round < 5; round++) {
    const rows = await db
      .select({ uuid: schema.sends.uuid, key: schema.sends.r2Key })
      .from(schema.sends)
      .where(lte(schema.sends.deletionDate, now))
      .limit(BATCH)
    const stale = await db
      .select({ uuid: schema.sends.uuid, key: schema.sends.r2Key })
      .from(schema.sends)
      .where(
        and(
          isNotNull(schema.sends.r2Key),
          isNull(schema.sends.uploadedAt),
          lt(schema.sends.createdAt, now - PENDING_GRACE_MS),
        ),
      )
      .limit(BATCH)
    const all = [...new Map([...rows, ...stale].map((r) => [r.uuid, r])).values()]
    if (all.length === 0) break
    await deleteBlobsNow(
      env,
      all.flatMap((r) => (r.key ? [r.key] : [])),
    )
    await runBatch(
      db,
      chunk(all.map((r) => r.uuid)).map((part) =>
        db.delete(schema.sends).where(inArray(schema.sends.uuid, part)),
      ),
    )
    total += all.length
    if (all.length < BATCH) break
  }
  // Mailed codes outlive their ten minutes only as rows nobody can use.
  await db.delete(schema.sendEmailCodes).where(lt(schema.sendEmailCodes.expiresAt, now))
  return total
}

/** Deletes attachment slots whose upload never finished, with any partial blob. */
async function purgePendingAttachments(env: Bindings, now: number): Promise<number> {
  const db = createDb(env.DB)
  let total = 0
  for (let round = 0; round < 5; round++) {
    const rows = await db
      .select({ id: schema.attachments.id, key: schema.attachments.r2Key })
      .from(schema.attachments)
      .where(
        and(
          isNull(schema.attachments.uploadedAt),
          lt(schema.attachments.createdAt, now - PENDING_GRACE_MS),
        ),
      )
      .limit(BATCH)
    if (rows.length === 0) break
    await deleteBlobsNow(
      env,
      rows.map((r) => r.key),
    )
    await runBatch(
      db,
      chunk(rows.map((r) => r.id)).map((part) =>
        db.delete(schema.attachments).where(inArray(schema.attachments.id, part)),
      ),
    )
    total += rows.length
    if (rows.length < BATCH) break
  }
  return total
}

/** Only these prefixes are ever listed or deleted by the sweep; other keys (backups) are not ours. */
const BLOB_PREFIXES = ['attachments/', 'sends/']

/**
 * Sweeps one page of one prefix per run, resuming from a cursor kept in the bucket itself,
 * and deletes objects no attachment or Send row refers to.
 */
async function purgeOrphans(env: Bindings, now: number): Promise<number> {
  const db = createDb(env.DB)
  const saved = await env.ATTACHMENTS.get(CURSOR_KEY)
  let state: { i: number; cursor?: string } = { i: 0 }
  try {
    const parsed = saved ? JSON.parse(await saved.text()) : null
    if (parsed && Number.isInteger(parsed.i) && parsed.i >= 0 && parsed.i < BLOB_PREFIXES.length) {
      state = { i: parsed.i, cursor: typeof parsed.cursor === 'string' ? parsed.cursor : undefined }
    }
  } catch {
    // A damaged cursor restarts the sweep.
  }
  const prefix = BLOB_PREFIXES[state.i] as string
  const page = await env.ATTACHMENTS.list({ prefix, limit: ORPHAN_PAGE, cursor: state.cursor })
  const objects = page.objects.filter(
    (o) => o.key.startsWith(prefix) && o.uploaded.getTime() < now - ORPHAN_GRACE_MS,
  )
  const known = new Set<string>()
  for (const part of chunk(objects.map((o) => o.key))) {
    const [a, s] = await Promise.all([
      db
        .select({ key: schema.attachments.r2Key })
        .from(schema.attachments)
        .where(inArray(schema.attachments.r2Key, part)),
      db
        .select({ key: schema.sends.r2Key })
        .from(schema.sends)
        .where(inArray(schema.sends.r2Key, part)),
    ])
    for (const r of [...a, ...s]) if (r.key) known.add(r.key)
  }
  const orphans = objects.filter((o) => !known.has(o.key)).map((o) => o.key)
  await deleteBlobsNow(env, orphans)
  if (page.truncated) {
    await env.ATTACHMENTS.put(CURSOR_KEY, JSON.stringify({ i: state.i, cursor: page.cursor }))
  } else if (state.i + 1 < BLOB_PREFIXES.length) {
    await env.ATTACHMENTS.put(CURSOR_KEY, JSON.stringify({ i: state.i + 1 }))
  } else {
    await env.ATTACHMENTS.delete(CURSOR_KEY)
  }
  return orphans.length
}

/** Runs one purge step; a failure is logged (never request data) and does not stop the others. */
async function step(name: string, run: () => Promise<number>): Promise<number> {
  try {
    return await run()
  } catch (err) {
    log('error', 'purge.step_failed', { step: name, errorKind: errorKind(err) })
    return 0
  }
}

/** Cron entry point (TASKS #84). Safe to run repeatedly. */
export async function purgeExpired(env: Bindings, now = Date.now()): Promise<PurgeResult> {
  return {
    sends: await step('sends', () => purgeSends(env, now)),
    attachments: await step('attachments', () => purgePendingAttachments(env, now)),
    orphans: await step('orphans', () => purgeOrphans(env, now)),
  }
}
