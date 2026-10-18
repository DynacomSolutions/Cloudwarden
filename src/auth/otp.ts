import { and, eq, gt, isNotNull, lt, sql } from 'drizzle-orm'
import { rateLimit as d1Window } from '../admin/security'
import type { Db } from '../db'
import { schema } from '../db'
import { safeEqualStrings, sha256B64u } from './crypto'

/** Purposes keep a code issued for one flow from unlocking another. */
export type OtpPurpose = 'new-device' | 'user-verification' | 'email-change'

export const OTP_TTL_MS = 10 * 60 * 1000
export const MAX_ATTEMPTS = 5
const MAX_ISSUES_PER_HOUR = 5

/** Issues a six digit code for the user, replacing any pending one. The code is stored hashed. */
export async function issueOtp(
  db: Db,
  userUuid: string,
  purpose: OtpPurpose,
  binding = '',
): Promise<string | null> {
  const [cur] = await db
    .select({ at: schema.users.otpExpiresAt, n: schema.users.otpAttempts })
    .from(schema.users)
    .where(eq(schema.users.uuid, userUuid))
    .limit(1)
  const live = (cur?.at ?? 0) > Date.now()
  // Guesses count across reissues inside the window: 5 failed guesses block new issues for up to 10 minutes.
  if (live && (cur?.n ?? 0) >= MAX_ATTEMPTS) return null
  // Mail-bomb guard: a few codes per hour per account.
  if (
    !(await d1Window(
      db.$client,
      `otp-issue:${userUuid}`,
      MAX_ISSUES_PER_HOUR,
      3_600_000,
      Date.now(),
    ))
  ) {
    return null
  }
  const code = String((crypto.getRandomValues(new Uint32Array(1))[0] ?? 0) % 1_000_000).padStart(
    6,
    '0',
  )
  await db
    .update(schema.users)
    .set({
      otpHash: await sha256B64u(`${purpose}:${userUuid}:${binding}:${code}`),
      otpPurpose: purpose,
      otpExpiresAt: Date.now() + OTP_TTL_MS,
      otpAttempts: live ? (cur?.n ?? 0) : 0,
    })
    .where(eq(schema.users.uuid, userUuid))
  return code
}

/**
 * Consumes the pending code atomically: it matches once, within the lifetime and the attempt
 * budget. The attempt is reserved first, so concurrent guesses cannot exceed the budget; the
 * code dies on a match or when the budget is spent. `binding` must equal the one given to `issueOtp`.
 */
export async function consumeOtp(
  db: Db,
  userUuid: string,
  purpose: OtpPurpose,
  code: string,
  binding = '',
): Promise<boolean> {
  const hash = await sha256B64u(`${purpose}:${userUuid}:${binding}:${code.trim()}`)
  const [reserved] = await db
    .update(schema.users)
    .set({ otpAttempts: sql`${schema.users.otpAttempts} + 1` })
    .where(
      and(
        eq(schema.users.uuid, userUuid),
        eq(schema.users.otpPurpose, purpose),
        isNotNull(schema.users.otpHash),
        gt(schema.users.otpExpiresAt, Date.now()),
        lt(schema.users.otpAttempts, MAX_ATTEMPTS),
      ),
    )
    .returning({ hash: schema.users.otpHash })
  if (!reserved?.hash || !safeEqualStrings(reserved.hash, hash)) return false
  // Only one concurrent holder of the right code wins the clear.
  const hit = await db
    .update(schema.users)
    .set({ otpHash: null, otpPurpose: null, otpExpiresAt: null, otpAttempts: 0 })
    .where(and(eq(schema.users.uuid, userUuid), eq(schema.users.otpHash, hash)))
  return hit.meta.changes > 0
}
