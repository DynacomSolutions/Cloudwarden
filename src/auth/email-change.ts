// Parts of an account email change that the account route and the Public API share.
import { emailChangedNewEmail, emailChangedOldEmail } from '../email'
import { sendNotice } from '../email/send'
import type { Bindings } from '../env'

/** Tells the old and the new address that the email address changed. Best effort. */
export const sendEmailChangeNotices = (env: Bindings, oldEmail: string, newEmail: string) =>
  Promise.all([
    sendNotice(env, oldEmail, emailChangedOldEmail(newEmail)),
    sendNotice(env, newEmail, emailChangedNewEmail()),
  ])

/** Whether a database error is the unique email index refusing an address that is taken. */
export function isEmailTakenError(err: unknown): boolean {
  for (let e: unknown = err, depth = 0; e && depth < 5; depth++) {
    const text = e instanceof Error ? e.message : String(e)
    if (/users_email_unique|UNIQUE constraint failed: users\.email/i.test(text)) return true
    e = e instanceof Error ? e.cause : undefined
  }
  return false
}
