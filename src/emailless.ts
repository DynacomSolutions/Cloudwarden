import { sql } from 'drizzle-orm'
import { isAdminEmail } from './admin/security'
import { randomB64u, sha256B64u, timingSafeEqual, utf8 } from './auth/crypto'
import type { Db } from './db'
import { schema } from './db'
import { createEmailTransport } from './email'
import type { Bindings } from './env'

/**
 * Support for deployments that cannot send mail (TASKS #350, docs/emailless.md). Every feature
 * that needs a mailbox as proof or as a delivery channel has a defined behaviour without mail.
 */

/** True when outgoing mail works (the EMAIL binding and MAIL_FROM are present). */
export const mailConfigured = (env: Bindings): boolean => createEmailTransport(env).configured

/** Whether an account's address counts as verified. Without mail nobody can verify, so it is not required. */
export const emailVerifiedFor = (env: Bindings, user: { verifiedAt: number | null }): boolean =>
  user.verifiedAt !== null || !mailConfigured(env)

export type MailFeatureState = 'link' | 'refused' | 'skipped' | 'manual'

/** What each mail dependent feature does when no mail transport is configured. */
export const MAIL_FEATURES: { id: string; label: string; withoutMail: MailFeatureState }[] = [
  { id: 'first-admin', label: 'First instance admin registration', withoutMail: 'manual' },
  { id: 'instance-invite', label: 'Instance invitations', withoutMail: 'link' },
  { id: 'org-invite', label: 'Organisation member invitations', withoutMail: 'refused' },
  { id: 'org-invite-link', label: 'Organisation invite links', withoutMail: 'link' },
  { id: 'emergency-invite', label: 'Emergency access invitations', withoutMail: 'refused' },
  { id: 'new-device-otp', label: 'New device verification code', withoutMail: 'skipped' },
  { id: 'magic-link', label: 'Magic link login', withoutMail: 'refused' },
  { id: 'email-2fa', label: 'Email two-step login', withoutMail: 'refused' },
  { id: 'send-email-auth', label: 'Email protected Sends', withoutMail: 'refused' },
  { id: 'org-delete-email', label: 'Organisation deletion by email', withoutMail: 'refused' },
  { id: 'account-delete-email', label: 'Account deletion by email', withoutMail: 'refused' },
  { id: 'password-hint', label: 'Password hint by email', withoutMail: 'refused' },
  { id: 'verify-email', label: 'Email verification', withoutMail: 'skipped' },
  { id: 'email-otp', label: 'Verification codes sent by email', withoutMail: 'refused' },
  { id: 'email-change', label: 'Email address change', withoutMail: 'manual' },
  { id: 'notices', label: 'Notices (new device, welcome, changes)', withoutMail: 'skipped' },
]

export function mailStatus(env: Bindings, configured = mailConfigured(env)) {
  return {
    configured,
    features: MAIL_FEATURES.map((f) => ({
      id: f.id,
      label: f.label,
      state: configured ? 'available' : f.withoutMail,
    })),
  }
}

// ----- First admin setup token -----

export const SETUP_TOKEN_MIN_LENGTH = 32
export const INVITE_CODE_TTL_MS = 7 * 24 * 3600_000

/** The configured setup secret, or null when it is missing or too short to be safe. */
export const setupToken = (env: Bindings): string | null => {
  const t = env.ADMIN_SETUP_TOKEN
  return t && t.length >= SETUP_TOKEN_MIN_LENGTH ? t : null
}

const sha256 = async (s: string) => new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(s)))

/** Constant-time comparison of a presented code with the expected one (both hashed first). */
export async function codeMatches(presented: string, expected: string): Promise<boolean> {
  return timingSafeEqual(await sha256(presented), await sha256(expected))
}

/** Hash that identifies a setup secret in `admin_setup_uses`. */
export const setupTokenId = (token: string) => sha256B64u(`setup:${token}`)

/** Whether an account with an ADMIN_EMAILS address already exists. */
export async function adminAccountExists(env: Bindings, db: Db): Promise<boolean> {
  const list = (env.ADMIN_EMAILS ?? '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean)
  if (list.length === 0) return false
  const [row] = await db
    .select({ uuid: schema.users.uuid })
    .from(schema.users)
    .where(
      sql`lower(${schema.users.email}) IN (${sql.join(
        list.map((e) => sql`${e}`),
        sql`, `,
      )})`,
    )
    .limit(1)
  return row !== undefined
}

export async function setupTokenSpent(db: Db, token: string): Promise<boolean> {
  const [row] = await db
    .select({ id: schema.adminSetupUses.tokenHash })
    .from(schema.adminSetupUses)
    .where(sql`${schema.adminSetupUses.tokenHash} = ${await setupTokenId(token)}`)
    .limit(1)
  return row !== undefined
}

/** Whether the first admin may still be created with the setup secret. */
export async function setupOpen(env: Bindings, db: Db): Promise<boolean> {
  const token = setupToken(env)
  if (!token || mailConfigured(env)) return false
  if (await adminAccountExists(env, db)) return false
  return !(await setupTokenSpent(db, token))
}

export { isAdminEmail }

// ----- Invite codes for instance invitations -----

/** A fresh code and what to store: only the hash and an expiry are kept. */
export async function newInviteCode(now: number) {
  const code = randomB64u(24)
  return { code, hash: await sha256B64u(`invite:${code}`), expiresAt: now + INVITE_CODE_TTL_MS }
}

export const inviteCodeHash = (code: string) => sha256B64u(`invite:${code}`)
