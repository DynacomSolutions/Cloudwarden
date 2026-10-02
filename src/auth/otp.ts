import { and, eq, gt, isNotNull, lt, sql } from 'drizzle-orm'
import { rateLimit as d1Window } from '../admin/security'
import type { Db } from '../db'
import { schema } from '../db'
import { sha256B64u } from './crypto'

/** Purposes keep a code issued for one flow from unlocking another. */
export type OtpPurpose = 'new-device' | 'user-verification'

export const OTP_TTL_MS = 10 * 60 * 1000
const MAX_ATTEMPTS = 5
const MAX_ISSUES_PER_HOUR = 5

/** Issues a six digit code for the user, replacing any pending one. The code is stored hashed. */
export async function issueOtp(
  db: Db,
  userUuid: string,
  purpose: OtpPurpose,
): Promise<string | null> {
  const [cur] = await db
    .select({ at: schema.users.otpExpiresAt, n: schema.users.otpAttempts })
    .from(schema.users)
    .where(eq(schema.users.uuid, userUuid))
    .limit(1)
  const live = (cur?.at ?? 0) > Date.now()
  // Guesses count across reissues inside the window, and a spent budget locks issuing out.
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
      otpHash: await sha256B64u(`${purpose}:${userUuid}:${code}`),
      otpPurpose: purpose,
      otpExpiresAt: Date.now() + OTP_TTL_MS,
      otpAttempts: live ? (cur?.n ?? 0) : 0,
    })
    .where(eq(schema.users.uuid, userUuid))
  return code
}

/**
 * Consumes the pending code atomically: it matches once, within the lifetime and the attempt
 * budget. Every miss counts against that budget, and the code dies when it is spent.
 */
export async function consumeOtp(
  db: Db,
  userUuid: string,
  purpose: OtpPurpose,
  code: string,
): Promise<boolean> {
  const hash = await sha256B64u(`${purpose}:${userUuid}:${code.trim()}`)
  const live = and(
    eq(schema.users.uuid, userUuid),
    eq(schema.users.otpPurpose, purpose),
    isNotNull(schema.users.otpHash),
    gt(schema.users.otpExpiresAt, Date.now()),
    lt(schema.users.otpAttempts, MAX_ATTEMPTS),
  )
  const hit = await db
    .update(schema.users)
    .set({ otpHash: null, otpPurpose: null, otpExpiresAt: null, otpAttempts: 0 })
    .where(and(live, eq(schema.users.otpHash, hash)))
  if (hit.meta.changes > 0) return true
  await db
    .update(schema.users)
    .set({ otpAttempts: sql`${schema.users.otpAttempts} + 1` })
    .where(live)
  return false
}
