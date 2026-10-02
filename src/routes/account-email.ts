import { eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { requireAuth } from '../auth/middleware'
import { consumeOtp, issueOtp, OTP_TTL_MS } from '../auth/otp'
import { verifyMasterPassword } from '../auth/passwords'
import { signPurposeToken, verifyPurposeToken } from '../auth/purpose-token'
import { findUserByEmail } from '../auth/users'
import { createDb, schema } from '../db'
import {
  createEmailTransport,
  deleteAccountEmail,
  otpEmail,
  passwordHintEmail,
  verifyEmailEmail,
} from '../email'
import { later, sendNotice, vaultBase } from '../email/send'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { overLimit, rateLimit, tooManyRequests } from '../ratelimit'
import { parseBody } from '../validation'
import { eraseAccount } from './accounts'

/** Account emails the clients trigger: password hint, email verification, codes, new device login. */
export const accountEmail = new Hono<Env>()

type Ctx = import('hono').Context<Env>

const VERIFY_EMAIL_PURPOSE = 'verify-email'
const VERIFY_EMAIL_TTL_SECONDS = 5 * 24 * 60 * 60
const DELETE_TTL_SECONDS = 5 * 24 * 60 * 60

const noMail = () =>
  new ApiError(400, 'This server cannot send email, so this feature is not available.')

// Password hint: the answer never depends on whether the address has an account. The hint is
// looked up and mailed after the response, so timing does not tell either.
accountEmail.post('/api/accounts/password-hint', rateLimit('password-hint', 5), async (c) => {
  const { email } = await parseBody(c, z.object({ email: z.string().min(1) }))
  if (!createEmailTransport(c.env).configured) throw noMail()
  later(
    c,
    (async () => {
      const user = await findUserByEmail(createDb(c.env.DB), email)
      if (user?.enabled) await sendNotice(c.env, user.email, passwordHintEmail(user.passwordHint))
    })(),
  )
  return c.body(null, 200)
})

// Verify email: the signed link goes to the address on file, so opening it proves control.
accountEmail.post('/api/accounts/verify-email', requireAuth, async (c) => {
  const user = c.var.user
  if (!createEmailTransport(c.env).configured) throw noMail()
  if (user.verifiedAt !== null) return c.body(null, 200)
  if (await overLimit(c, 'verify-email', user.uuid)) return tooManyRequests(c)
  const token = await signPurposeToken(
    c.env,
    VERIFY_EMAIL_PURPOSE,
    { sub: user.uuid, email: user.email },
    VERIFY_EMAIL_TTL_SECONDS,
  )
  const url = `${vaultBase(c.env)}/#/verify-email?userId=${encodeURIComponent(user.uuid)}&token=${encodeURIComponent(token)}`
  const sent = await sendNotice(c.env, user.email, verifyEmailEmail(url))
  if (!sent) throw new ApiError(400, 'The email could not be sent. Try again later.')
  return c.body(null, 200)
})

accountEmail.post(
  '/api/accounts/verify-email-token',
  rateLimit('verify-email-token', 20),
  async (c) => {
    const body = await parseBody(
      c,
      z.object({ userId: z.string().min(1), token: z.string().min(1) }),
    )
    const claims = await verifyPurposeToken(c.env, VERIFY_EMAIL_PURPOSE, body.token)
    const db = createDb(c.env.DB)
    const [user] = claims
      ? await db.select().from(schema.users).where(eq(schema.users.uuid, claims.sub)).limit(1)
      : []
    // The address must be unchanged since the link was issued.
    if (!user || claims?.sub !== body.userId || claims.email !== user.email) {
      throw new ApiError(400, 'Invalid token.')
    }
    const now = Date.now()
    await db
      .update(schema.users)
      .set({ verifiedAt: user.verifiedAt ?? now, updatedAt: now })
      .where(eq(schema.users.uuid, user.uuid))
    return c.body(null, 200)
  },
)

// One-time code for users who verify themselves by email instead of a master password.
accountEmail.post('/api/accounts/request-otp', requireAuth, async (c) => {
  const user = c.var.user
  if (!createEmailTransport(c.env).configured) throw noMail()
  if (await overLimit(c, 'request-otp', user.uuid)) return tooManyRequests(c)
  const code = await issueOtp(createDb(c.env.DB), user.uuid, 'user-verification')
  if (!code) return tooManyRequests(c)
  const sent = await sendNotice(
    c.env,
    user.email,
    otpEmail('verification', code, OTP_TTL_MS / 60_000),
  )
  if (!sent) throw new ApiError(400, 'The email could not be sent. Try again later.')
  return c.body(null, 200)
})

accountEmail.post('/api/accounts/verify-otp', requireAuth, async (c) => {
  const user = c.var.user
  // The client sends `OTP`; keys are normalised to a lowercase first letter before parsing.
  const body = await parseBody(c, z.object({ oTP: z.string().min(1) }))
  if (await overLimit(c, 'verify-otp', user.uuid)) return tooManyRequests(c)
  if (!(await consumeOtp(createDb(c.env.DB), user.uuid, 'user-verification', body.oTP))) {
    throw new ApiError(400, 'Invalid verification code.')
  }
  return c.body(null, 200)
})

// New device login verification. Turning it off needs proof: the master password or a code.
const verifyDevicesSchema = z.object({
  masterPasswordHash: z.string().nullish(),
  otp: z.string().nullish(),
  verifyDevices: z.boolean(),
})
accountEmail.post('/api/accounts/verify-devices', requireAuth, async (c: Ctx) => {
  const user = c.var.user
  const body = await parseBody(c, verifyDevicesSchema)
  const db = createDb(c.env.DB)
  const ok = body.masterPasswordHash
    ? await verifyMasterPassword(user, body.masterPasswordHash)
    : body.otp
      ? !(await overLimit(c, 'verify-otp', user.uuid)) &&
        (await consumeOtp(db, user.uuid, 'user-verification', body.otp))
      : false
  if (!ok) throw new ApiError(400, 'Invalid verification.')
  await db
    .update(schema.users)
    .set({ verifyDevices: body.verifyDevices, updatedAt: Date.now() })
    .where(eq(schema.users.uuid, user.uuid))
  return c.body(null, 200)
})

// Account deletion by email, for people who cannot give their master password. Answers the
// same for every address; the signed link goes only to the address on file.
const DELETE_PURPOSE = 'delete-account'

accountEmail.post('/api/accounts/delete-recover', rateLimit('delete-recover', 5), async (c) => {
  const { email } = await parseBody(c, z.object({ email: z.string().min(1) }))
  if (!createEmailTransport(c.env).configured) throw noMail()
  later(
    c,
    (async () => {
      const user = await findUserByEmail(createDb(c.env.DB), email)
      if (!user?.enabled) return
      const token = await signPurposeToken(
        c.env,
        DELETE_PURPOSE,
        { sub: user.uuid, email: user.email, ref: user.securityStamp },
        DELETE_TTL_SECONDS,
      )
      const url = `${vaultBase(c.env)}/#/verify-recover-delete?userId=${encodeURIComponent(user.uuid)}&token=${encodeURIComponent(token)}&email=${encodeURIComponent(user.email)}`
      await sendNotice(c.env, user.email, deleteAccountEmail(url))
    })(),
  )
  return c.body(null, 200)
})

accountEmail.post(
  '/api/accounts/delete-recover-token',
  rateLimit('delete-recover-token', 10),
  async (c) => {
    const body = await parseBody(
      c,
      z.object({ userId: z.string().min(1), token: z.string().min(1) }),
    )
    const claims = await verifyPurposeToken(c.env, DELETE_PURPOSE, body.token)
    const db = createDb(c.env.DB)
    const [user] = claims
      ? await db.select().from(schema.users).where(eq(schema.users.uuid, claims.sub)).limit(1)
      : []
    if (
      !user ||
      claims?.sub !== body.userId ||
      claims.email !== user.email ||
      claims.ref !== user.securityStamp
    ) {
      throw new ApiError(400, 'Invalid token.')
    }
    await eraseAccount(c, user)
    return c.body(null, 200)
  },
)
