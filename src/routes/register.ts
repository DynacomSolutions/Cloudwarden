import { sql } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { isAdminEmail } from '../admin/security'
import { authenticationData, checkNested, unlockData } from '../auth/credentials'
import { signingSecret, signJwt, verifyJwt } from '../auth/jwt'
import { hashMasterPassword } from '../auth/passwords'
import { findUserByEmail, normalizeEmail } from '../auth/users'
import { createDb, type Db, runBatch, schema } from '../db'
import { createEmailTransport, genericEmail, welcomeEmail } from '../email'
import { later, sendNotice, vaultBase } from '../email/send'
import type { Bindings, Env } from '../env'
import { ApiError } from '../errors'
import { rateLimit } from '../ratelimit'
import { type KdfParams, kdfProblem, parseBody } from '../validation'

export const register = new Hono<Env>()

/**
 * Whether `email` may self-register: signups are open, the address (or its domain) is in
 * SIGNUPS_DOMAINS_WHITELIST, or an admin invited the address (invitations table).
 */
export async function signupAllowed(env: Bindings, db: Db, email: string): Promise<boolean> {
  if (env.SIGNUPS_ALLOWED === 'true') return true
  const list = (env.SIGNUPS_DOMAINS_WHITELIST ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
  const addr = normalizeEmail(email)
  const domain = addr.slice(addr.lastIndexOf('@') + 1)
  if (list.some((entry) => (entry.includes('@') ? entry === addr : entry === domain))) return true
  const [invite] = await db
    .select({ uuid: schema.invitations.uuid })
    .from(schema.invitations)
    .where(sql`lower(${schema.invitations.email}) = ${addr}`)
    .limit(1)
  return invite !== undefined
}

// Registration tokens use a derived secret so they can never validate as access tokens.
const registerSecret = (env: Bindings) => `register:${signingSecret(env)}`
const REGISTER_TOKEN_TTL_SECONDS = 30 * 60

interface RegisterClaims {
  purpose: 'register'
  email: string
  name: string
  exp: number
  nbf: number
}

const keysSchema = z.object({
  publicKey: z.string().min(1),
  encryptedPrivateKey: z.string().min(1),
})

const registerSchema = z.object({
  email: z.string().email(),
  name: z.string().max(50).nullish(),
  masterPasswordHash: z.string().min(1).nullish(),
  // Nested shape sent by clients 2026.9 and later.
  masterPasswordAuthentication: authenticationData.nullish(),
  masterPasswordUnlock: unlockData.nullish(),
  masterPasswordHint: z.string().max(50).nullish(),
  // Current clients send key/keys; the finish flow sends userSymmetricKey/userAsymmetricKeys.
  key: z.string().min(1).nullish(),
  userSymmetricKey: z.string().min(1).nullish(),
  keys: keysSchema.nullish(),
  userAsymmetricKeys: keysSchema.nullish(),
  kdf: z.number().int().default(0),
  kdfIterations: z.number().int().default(600000),
  kdfMemory: z.number().int().nullish(),
  kdfParallelism: z.number().int().nullish(),
  emailVerificationToken: z.string().nullish(),
})

async function createAccount(c: import('hono').Context<Env>) {
  const body = await parseBody(c, registerSchema)
  const email = normalizeEmail(body.email)

  let name = body.name ?? ''
  const db = createDb(c.env.DB)
  // A valid emailed token proves control of the mailbox. Invitations and the domain whitelist
  // only say who may register, so they need that proof. Fully open signups may skip it, except
  // for admin addresses, which must never be claimable by whoever registers them first.
  let verified = false
  if (body.emailVerificationToken) {
    const claims = await verifyJwt<RegisterClaims>(body.emailVerificationToken, [
      registerSecret(c.env),
    ])
    if (claims?.purpose === 'register' && claims.email === email) {
      verified = true
      name = body.name ?? claims.name
    }
  }
  const open = c.env.SIGNUPS_ALLOWED === 'true' && !isAdminEmail(c.env.ADMIN_EMAILS, email)
  if (!verified && !open) throw new ApiError(400, 'Registration is not allowed.')

  const keys = body.keys ?? body.userAsymmetricKeys
  let key = body.key ?? body.userSymmetricKey
  let masterPasswordHash = body.masterPasswordHash
  let kdfSettings: KdfParams = body
  if (body.masterPasswordAuthentication && body.masterPasswordUnlock) {
    kdfSettings = checkNested(body.masterPasswordAuthentication, body.masterPasswordUnlock, email)
    masterPasswordHash = body.masterPasswordAuthentication.masterPasswordAuthenticationHash
    key = body.masterPasswordUnlock.masterKeyWrappedUserKey
  }
  if (!masterPasswordHash) {
    throw new ApiError(400, 'The request is invalid.', {
      masterPasswordHash: ['masterPasswordHash is required'],
    })
  }
  if (!key) throw new ApiError(400, 'The request is invalid.', { key: ['key is required'] })
  const problem = kdfProblem(kdfSettings)
  if (problem) throw new ApiError(400, problem)

  if (await findUserByEmail(db, email)) throw new ApiError(400, 'Email is already registered.')

  const now = Date.now()
  const stored = await hashMasterPassword(masterPasswordHash)
  const argon = kdfSettings.kdf === 1
  try {
    // The invitation (if any) is consumed in the same batch as the account insert.
    const insert = db.insert(schema.users).values({
      uuid: crypto.randomUUID(),
      email,
      name,
      ...stored,
      passwordHint: body.masterPasswordHint ?? null,
      akey: key,
      publicKey: keys?.publicKey ?? null,
      privateKey: keys?.encryptedPrivateKey ?? null,
      kdfType: kdfSettings.kdf,
      kdfIterations: kdfSettings.kdfIterations,
      kdfMemory: argon ? (kdfSettings.kdfMemory ?? null) : null,
      kdfParallelism: argon ? (kdfSettings.kdfParallelism ?? null) : null,
      securityStamp: crypto.randomUUID(),
      // Verified by the emailed token; open signups are trusted as before (never admin addresses).
      verifiedAt: now,
      createdAt: now,
      updatedAt: now,
    })
    await runBatch(db, [
      insert,
      db.delete(schema.invitations).where(sql`lower(${schema.invitations.email}) = ${email}`),
    ])
  } catch {
    // Lost a race with a concurrent registration of the same address.
    throw new ApiError(400, 'Email is already registered.')
  }
  later(c, sendNotice(c.env, email, welcomeEmail(vaultBase(c.env))))
  return c.json({ object: 'register', captchaBypassToken: '' })
}

register.post('/identity/accounts/register', rateLimit('register'), createAccount)
register.post('/api/accounts/register', rateLimit('register'), createAccount)
register.post('/identity/accounts/register/finish', rateLimit('register'), createAccount)

const sendSchema = z.object({
  email: z.string().email(),
  name: z.string().max(50).nullish(),
  receiveMarketingEmails: z.boolean().nullish(),
})

// With a mail transport the link is emailed (204). Without one, verification is disabled
// and the token is returned directly (200).
register.post(
  '/identity/accounts/register/send-verification-email',
  rateLimit('register'),
  async (c) => {
    const body = await parseBody(c, sendSchema)
    const email = normalizeEmail(body.email)
    if (!(await signupAllowed(c.env, createDb(c.env.DB), email))) {
      throw new ApiError(400, 'Registration is not allowed.')
    }
    // Without a mail transport the token is handed straight back, which proves nothing.
    if (isAdminEmail(c.env.ADMIN_EMAILS, email) && !createEmailTransport(c.env).configured) {
      throw new ApiError(400, 'Registration is not allowed.')
    }
    const now = Math.floor(Date.now() / 1000)
    const claims: RegisterClaims = {
      purpose: 'register',
      email,
      name: body.name ?? '',
      nbf: now,
      exp: now + REGISTER_TOKEN_TTL_SECONDS,
    }
    const verification = await signJwt(claims, registerSecret(c.env))
    const transport = createEmailTransport(c.env)
    if (!transport.configured) return c.json(verification)
    const base = c.env.DOMAIN.replace(/\/+$/, '')
    const link = `${base}/#/finish-signup?email=${encodeURIComponent(email)}&token=${encodeURIComponent(verification)}&fromEmail=true`
    await transport.send({
      to: email,
      ...genericEmail('Verify your email address', [
        'Use the link below to finish creating your Cloudwarden account.',
        link,
      ]),
    })
    return c.body(null, 204)
  },
)

const clickedSchema = z.object({
  email: z.string().email(),
  emailVerificationToken: z.string().min(1),
})

// The web vault calls this when the emailed link is opened, before showing the finish form.
register.post(
  '/identity/accounts/register/verification-email-clicked',
  rateLimit('register'),
  async (c) => {
    const body = await parseBody(c, clickedSchema)
    const email = normalizeEmail(body.email)
    const claims = await verifyJwt<RegisterClaims>(body.emailVerificationToken, [
      registerSecret(c.env),
    ])
    if (claims?.purpose !== 'register' || claims.email !== email) {
      throw new ApiError(400, 'Invalid or expired email verification token.')
    }
    if (await findUserByEmail(createDb(c.env.DB), email)) {
      throw new ApiError(400, 'Email is already registered.')
    }
    return c.body(null, 200)
  },
)
