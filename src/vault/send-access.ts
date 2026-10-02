import { and, eq, sql } from 'drizzle-orm'
import type { Context } from 'hono'
import { rateLimit as d1Window } from '../admin/security'
import { safeEqualStrings, sha256B64u } from '../auth/crypto'
import { signJwt, verifyJwt } from '../auth/jwt'
import { type StoredPassword, verifyMasterPassword } from '../auth/passwords'
import type { Db } from '../db'
import { schema } from '../db'
import { createEmailTransport, sendCodeEmail } from '../email'
import type { Bindings, Env } from '../env'
import { ApiError } from '../errors'
import { errorKind, log } from '../log'
import { baseUrl, signBlobToken, signingKeyFor, verificationKeysFor } from './blobs'
import {
  allowedEmails,
  claimAccess,
  SEND_FILE,
  SEND_FILE_AUD,
  type SendRow,
  sendUuidFrom,
  unavailable,
} from './sends'

export const SEND_ACCESS_AUD = 'send_access'
export const SEND_TOKEN_TTL_SECONDS = 1800

export const notAvailable = () => new ApiError(404, 'Send not found.')

/** The Send a recipient asks for, or a 404 when it is missing or unusable (never says which). */
export async function loadForAccess(
  db: Db,
  idOrAccess: string,
  now = Date.now(),
): Promise<SendRow> {
  const uuid = sendUuidFrom(idOrAccess)
  const [row] = uuid
    ? await db.select().from(schema.sends).where(eq(schema.sends.uuid, uuid)).limit(1)
    : []
  if (!row || unavailable(row, now)) throw notAvailable()
  return row
}

export const OTP_TTL_MS = 10 * 60_000
/** A code is burned after this many wrong guesses; the recipient must ask for a new one. */
export const OTP_MAX_ATTEMPTS = 5
/** Asking again inside this window does not mail another code. */
export const OTP_RESEND_MS = 30_000
export const OTP_DIGITS = 8

/** Request limits (D1 windows). Every address, listed or not, consumes the same ones. */
const LIMITS = {
  ipAsk: { limit: 10, windowMs: 10 * 60_000 },
  addressAsk: { limit: 5, windowMs: 10 * 60_000 },
  addressDay: { limit: 8, windowMs: 24 * 3600_000 },
  /** High ceiling per Send; the per-address limits are what stop a lock-out of one recipient. */
  sendAsk: { limit: 300, windowMs: 3600_000 },
  ipTry: { limit: 30, windowMs: 10 * 60_000 },
  /** Cumulative guesses per address and day, across every code mailed in it. */
  addressTry: { limit: 40, windowMs: 24 * 3600_000 },
}

const otpHash = (sendUuid: string, email: string, code: string) =>
  sha256B64u(`send-otp:${sendUuid}:${email}:${code}`)

/** A uniformly random code of `OTP_DIGITS` digits. */
function newCode(): string {
  const space = 10 ** OTP_DIGITS
  const limit = Math.floor(2 ** 32 / space) * space
  const buf = new Uint32Array(1)
  if (limit === 0) throw new Error('code space too large')
  do crypto.getRandomValues(buf)
  while ((buf[0] as number) >= limit)
  return String((buf[0] as number) % space).padStart(OTP_DIGITS, '0')
}

const clientIp = (c: Context<Env>) => c.req.header('CF-Connecting-IP') ?? 'unknown'

/** True when every named limit still has room; all of them are counted even after one is full. */
async function within(
  c: Context<Env>,
  checks: [key: string, limit: { limit: number; windowMs: number }][],
  now: number,
): Promise<boolean> {
  let ok = true
  for (const [key, l] of checks) {
    if (!(await d1Window(c.env.DB, key, l.limit, l.windowMs, now))) ok = false
  }
  return ok
}

/**
 * Mails a fresh code to a recipient of an email-protected Send. The limits and the work done are
 * the same for an address on the list and one that is not (the mail alone is sent in the
 * background and only for listed ones), so the list cannot be probed. Returns false when the
 * request was rate limited.
 */
export async function requestSendCode(
  c: Context<Env>,
  db: Db,
  send: SendRow,
  email: string,
  now = Date.now(),
): Promise<boolean> {
  const transport = createEmailTransport(c.env)
  if (!transport.configured) throw new ApiError(400, 'Email delivery is not configured.')
  const who = await sha256B64u(`${send.uuid}:${email}`)
  const ok = await within(
    c,
    [
      [`send-otp-ip:${clientIp(c)}`, LIMITS.ipAsk],
      [`send-otp-addr:${who}`, LIMITS.addressAsk],
      [`send-otp-day:${who}`, LIMITS.addressDay],
      [`send-otp-send:${send.uuid}`, LIMITS.sendAsk],
    ],
    now,
  )
  if (!ok) return false
  const listed = allowedEmails(send).includes(email)
  const [prior] = await db
    .select({ sentAt: schema.sendEmailCodes.sentAt })
    .from(schema.sendEmailCodes)
    .where(
      and(eq(schema.sendEmailCodes.sendUuid, send.uuid), eq(schema.sendEmailCodes.email, email)),
    )
    .limit(1)
  if (prior && now - prior.sentAt < OTP_RESEND_MS) return true
  const code = newCode()
  const row = {
    codeHash: await otpHash(send.uuid, email, code),
    expiresAt: now + OTP_TTL_MS,
    sentAt: now,
    attempts: 0,
  }
  await db
    .insert(schema.sendEmailCodes)
    .values({ sendUuid: send.uuid, email, ...row })
    .onConflictDoUpdate({
      target: [schema.sendEmailCodes.sendUuid, schema.sendEmailCodes.email],
      set: row,
    })
  if (listed) {
    const work = transport
      .send({ to: email, ...sendCodeEmail(code, OTP_TTL_MS / 60_000) })
      .catch((e) => log('error', 'send_code_mail_failed', { errorKind: errorKind(e) }, c.env))
    try {
      c.executionCtx.waitUntil(work)
    } catch {
      void work
    }
  }
  return true
}

/** Checks a mailed code. Every try counts, and a correct code works once. */
export async function verifySendCode(
  c: Context<Env>,
  db: Db,
  send: SendRow,
  email: string,
  code: string,
  now = Date.now(),
): Promise<boolean> {
  const who = await sha256B64u(`${send.uuid}:${email}`)
  const roomy = await within(
    c,
    [
      [`send-otp-try-ip:${clientIp(c)}`, LIMITS.ipTry],
      [`send-otp-try:${who}`, LIMITS.addressTry],
    ],
    now,
  )
  if (!roomy || !allowedEmails(send).includes(email)) return false
  const key = and(
    eq(schema.sendEmailCodes.sendUuid, send.uuid),
    eq(schema.sendEmailCodes.email, email),
  )
  const counted = await db
    .update(schema.sendEmailCodes)
    .set({ attempts: sql`${schema.sendEmailCodes.attempts} + 1` })
    .where(
      and(
        key,
        sql`${schema.sendEmailCodes.expiresAt} > ${now}`,
        sql`${schema.sendEmailCodes.attempts} < ${OTP_MAX_ATTEMPTS}`,
      ),
    )
  if (counted.meta.changes === 0) return false
  const spent = await db
    .delete(schema.sendEmailCodes)
    .where(
      and(key, eq(schema.sendEmailCodes.codeHash, await otpHash(send.uuid, email, code.trim()))),
    )
  return spent.meta.changes > 0
}

export type PasswordCheck = 'ok' | 'required' | 'invalid'

export async function checkSendPassword(
  send: SendRow,
  password: string | null | undefined,
): Promise<PasswordCheck> {
  if (!send.passwordHash || !send.passwordSalt) return 'ok'
  if (!password) return 'required'
  const stored: StoredPassword = {
    passwordHash: send.passwordHash,
    salt: send.passwordSalt,
    passwordIterations: send.passwordIter ?? 100_000,
  }
  return (await verifyMasterPassword(stored, password)) ? 'ok' : 'invalid'
}

/** Legacy flows: translate a failed password check into the status the clients expect. */
export function passwordError(check: PasswordCheck): ApiError | null {
  if (check === 'required') return new ApiError(401, 'Password not provided.')
  if (check === 'invalid') {
    return new ApiError(400, 'The request is invalid.', { password: ['Invalid password.'] })
  }
  return null
}

const sendTokenLabel = 'send-access'

/** Binds a token to the Send's current password and revision, so edits revoke old tokens. */
const sendVersion = (send: SendRow) => sha256B64u(`${send.passwordHash ?? ''}:${send.updatedAt}`)

export async function signSendAccessToken(env: Bindings, send: SendRow): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return signJwt(
    {
      aud: SEND_ACCESS_AUD,
      sub: send.uuid,
      v: await sendVersion(send),
      nbf: now - 5,
      exp: now + SEND_TOKEN_TTL_SECONDS,
    },
    await signingKeyFor(env, sendTokenLabel),
  )
}

/** The Send named by a valid `send_access` bearer token that still matches it, or null. */
export async function sendFromBearer(
  env: Bindings,
  db: Db,
  header: string | undefined,
): Promise<SendRow | null> {
  const match = /^Bearer\s+(\S+)$/i.exec(header ?? '')
  if (!match?.[1]) return null
  const claims = await verifyJwt<{ aud?: string; sub?: string; v?: string; exp: number }>(
    match[1],
    await verificationKeysFor(env, sendTokenLabel),
  )
  if (claims?.aud !== SEND_ACCESS_AUD || !claims.sub || !claims.v) return null
  const [send] = await db
    .select()
    .from(schema.sends)
    .where(eq(schema.sends.uuid, claims.sub))
    .limit(1)
  if (!send || !safeEqualStrings(claims.v, await sendVersion(send))) return null
  return send
}

/** Counts the access and returns the signed URL for a File Send's blob. */
export async function fileDownloadUrl(db: Db, env: Bindings, send: SendRow, fileId: string) {
  if (send.atype !== SEND_FILE || !send.r2Key) throw notAvailable()
  const data = JSON.parse(send.data) as { id?: string }
  if (!data.id || !safeEqualStrings(data.id, fileId)) throw notAvailable()
  if (!(await claimAccess(db, send.uuid, Date.now()))) throw notAvailable()
  const token = await signBlobToken(env, SEND_FILE_AUD, `${send.uuid}/${fileId}`)
  return {
    object: 'send-fileDownload',
    id: fileId,
    url: `${baseUrl(env)}/send-files/${send.uuid}/${fileId}?token=${token}`,
  }
}
