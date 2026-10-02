import { and, eq, isNotNull, isNull, sql } from 'drizzle-orm'
import { createDb, schema } from './db'
import { emergencyApprovedEmail } from './email'
import { sendNotice } from './email/send'
import type { Bindings } from './env'

const RECOVERY_INITIATED = 3
const DAY_MS = 24 * 3600 * 1000

/**
 * Emergency access approves itself once the wait time has passed (evaluated from timestamps).
 * This hourly sweep tells the contact. Each request is claimed with a conditional update first,
 * so overlapping runs mail it once. Returns how many contacts were told.
 */
export async function notifyElapsedRecoveries(env: Bindings, now = Date.now()): Promise<number> {
  const db = createDb(env.DB)
  const due = await db
    .select()
    .from(schema.emergencyAccess)
    .where(
      and(
        eq(schema.emergencyAccess.status, RECOVERY_INITIATED),
        isNull(schema.emergencyAccess.recoveryNotifiedAt),
        isNotNull(schema.emergencyAccess.recoveryInitiatedAt),
        isNotNull(schema.emergencyAccess.granteeUuid),
        sql`${schema.emergencyAccess.recoveryInitiatedAt} + ${schema.emergencyAccess.waitTimeDays} * ${DAY_MS} <= ${now}`,
      ),
    )
    .limit(100)
  let told = 0
  for (const row of due) {
    const claim = await db
      .update(schema.emergencyAccess)
      .set({ recoveryNotifiedAt: now })
      .where(
        and(
          eq(schema.emergencyAccess.uuid, row.uuid),
          eq(schema.emergencyAccess.status, RECOVERY_INITIATED),
          isNull(schema.emergencyAccess.recoveryNotifiedAt),
        ),
      )
    if (claim.meta.changes === 0 || !row.granteeUuid) continue
    const [grantee] = await db
      .select({ email: schema.users.email })
      .from(schema.users)
      .where(eq(schema.users.uuid, row.granteeUuid))
      .limit(1)
    const [grantor] = await db
      .select({ name: schema.users.name, email: schema.users.email })
      .from(schema.users)
      .where(eq(schema.users.uuid, row.grantorUuid))
      .limit(1)
    if (!grantee || !grantor) continue
    const sent = await sendNotice(
      env,
      grantee.email,
      emergencyApprovedEmail(grantor.name || grantor.email, true),
    )
    if (sent) told++
    else {
      // Release the claim so the next sweep retries.
      await db
        .update(schema.emergencyAccess)
        .set({ recoveryNotifiedAt: null })
        .where(eq(schema.emergencyAccess.uuid, row.uuid))
    }
  }
  return told
}
