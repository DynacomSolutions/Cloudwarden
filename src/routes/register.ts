import { sql } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { isAdminEmail, rateLimit as windowLimit } from '../admin/security'
import { authenticationData, checkNested, unlockData } from '../auth/credentials'
import { signingSecret, signJwt, verifyJwt } from '../auth/jwt'
import { hashMasterPassword } from '../auth/passwords'
import { findUserByEmail, normalizeEmail } from '../auth/users'
import { createDb, type Db, runBatch, schema } from '../db'
import { createEmailTransport, genericEmail, welcomeEmail } from '../email'
import { later, sendNotice, vaultBase } from '../email/send'
import {
  adminAccountExists,
  codeMatches,
  inviteCodeHash,
  mailConfigured,
  setupToken,
  setupTokenId,
  setupTokenSpent,
} from '../emailless'
import type { Bindings, Env } from '../env'
import { ApiError } from '../errors'
import { rateLimit, tooManyRequests } from '../ratelimit'
import { type KdfParams, kdfProblem, parseBody } from '../validation'
import { findLink, linkAllows } from './org-settings'

export const register = new Hono<Env>()

/**
 * Whether `email` may self-register: signups are open, the address (or its domain) is in
 * SIGNUPS_DOMAINS_WHITELIST, or an admin invited the address (invitations table).
 */
export async function signupAllowed(env: Bindings, db: Db, email: string): Promise<boolean> {
  return (await signupBasis(env, db, email)) !== null
}

/** Whether the organisation's current link matches `ref` and allows the address's domain. */
async function linkAdmits(db: Db, ref: { organizationId: string; code: string }, email: string) {
  const { organizationId, code } = ref
  const link = await findLink(db, organizationId, code)
  return link !== undefined && linkAllows(link, normalizeEmail(email))
}

/**
 * Why `email` may register: an organisation invite link that allows its domain (independent
 * of the env whitelist), open signups, the domain whitelist, or an invitation.
 */
export async function signupBasis(
  env: Bindings,
  db: Db,
  email: string,
  via?: { organizationId: string; code: string } | null,
): Promise<'inviteLink' | 'open' | 'whitelist' | 'invite' | null> {
  if (via && (await linkAdmits(db, via, email))) return 'inviteLink'
  if (env.SIGNUPS_ALLOWED === 'true') return 'open'
  const list = (env.SIGNUPS_DOMAINS_WHITELIST ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
  const addr = normalizeEmail(email)
  const domain = addr.slice(addr.lastIndexOf('@') + 1)
  if (list.some((entry) => (entry.includes('@') ? entry === addr : entry === domain))) {
    return 'whitelist'
  }
  return (await hasInvitation(db, addr)) ? 'invite' : null
}

async function hasInvitation(db: Db, email: string) {
  const [invite] = await db
    .select({ uuid: schema.invitations.uuid })
    .from(schema.invitations)
    .where(sql`lower(${schema.invitations.email}) = ${normalizeEmail(email)}`)
    .limit(1)
  return invite !== undefined
}

const NO_MAIL_HINT =
  ' This server cannot send email: if you have an invite or setup code, open the page /#/instance-setup.'
const notAllowed = (env: Bindings) =>
  new ApiError(400, `Registration is not allowed.${mailConfigured(env) ? '' : NO_MAIL_HINT}`)

// Registration tokens use a derived secret so they can never validate as access tokens.
const registerSecret = (env: Bindings) => `register:${signingSecret(env)}`
const REGISTER_TOKEN_TTL_SECONDS = 30 * 60

interface RegisterClaims {
  purpose: 'register'
  email: string
  name: string
  /** Issued by the setup code redemption (no mail): the holder may create the first admin. */
  setup?: boolean
  /** The org invite link that admitted this address; re-checked at finish when mail is off. */
  link?: { organizationId: string; code: string }
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
  let setupClaim = false
  let linkClaim: RegisterClaims['link']
  if (body.emailVerificationToken) {
    const claims = await verifyJwt<RegisterClaims>(body.emailVerificationToken, [
      registerSecret(c.env),
    ])
    if (claims?.purpose === 'register' && claims.email === email) {
      verified = true
      setupClaim = claims.setup === true
      linkClaim = claims.link
      name = body.name ?? claims.name
    }
  }
  // Without mail the token proves nothing, so a link-bound token dies with its link.
  if (linkClaim && !mailConfigured(c.env) && !(await linkAdmits(db, linkClaim, email))) {
    throw notAllowed(c.env)
  }
  const adminAddress = isAdminEmail(c.env.ADMIN_EMAILS, email)
  const open = c.env.SIGNUPS_ALLOWED === 'true' && !adminAddress
  if (!verified && !open) throw notAllowed(c.env)
  // Without mail an admin address has no proof of ownership, so only the one-time setup secret
  // (redeemed into a setup token) may create it, once, and never when an admin already exists.
  let setupId: string | null = null
  if (adminAddress && !mailConfigured(c.env)) {
    const secret = setupToken(c.env)
    if (!setupClaim || !secret) throw notAllowed(c.env)
    if ((await adminAccountExists(c.env, db)) || (await setupTokenSpent(db, secret))) {
      throw notAllowed(c.env)
    }
    setupId = await setupTokenId(secret)
  }

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
    const uuid = crypto.randomUUID()
    const insert = db.insert(schema.users).values({
      uuid,
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
      // Spends the setup secret in the same batch: a lost race fails the whole batch.
      ...(setupId
        ? [
            db
              .insert(schema.adminSetupUses)
              .values({ tokenHash: setupId, userUuid: uuid, usedAt: now }),
          ]
        : []),
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
  // Sent by the web vault when registering from an organisation invite link.
  openOrgInvite: z.object({ organizationId: z.string().min(1), code: z.string().min(1) }).nullish(),
})

// With a mail transport the link is emailed (204). Without one, verification is disabled
// and the token is returned directly (200).
register.post(
  '/identity/accounts/register/send-verification-email',
  rateLimit('register'),
  async (c) => {
    const body = await parseBody(c, sendSchema)
    const email = normalizeEmail(body.email)
    const db = createDb(c.env.DB)
    const basis = await signupBasis(c.env, db, email, body.openOrgInvite)
    if (basis === null) throw notAllowed(c.env)
    // Without a mail transport the token is handed straight back, which proves nothing. Admin
    // addresses need the setup secret and invitations need their invite code (both go through
    // `registration/redeem`); open signups, the domain whitelist and org invite links keep working.
    if (!mailConfigured(c.env) && (isAdminEmail(c.env.ADMIN_EMAILS, email) || basis === 'invite')) {
      throw notAllowed(c.env)
    }
    // An invited address keeps needing its invite code without mail, so a link cannot bypass it.
    if (!mailConfigured(c.env) && basis === 'inviteLink' && (await hasInvitation(db, email))) {
      throw notAllowed(c.env)
    }
    const now = Math.floor(Date.now() / 1000)
    const claims: RegisterClaims = {
      purpose: 'register',
      email,
      name: body.name ?? '',
      ...(basis === 'inviteLink' && body.openOrgInvite ? { link: body.openOrgInvite } : {}),
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
const emailClicked = async (c: import('hono').Context<Env>) => {
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
}
register.post(
  '/identity/accounts/register/verification-email-clicked',
  rateLimit('register'),
  emailClicked,
)
// The iOS app posts the same request to the API host.
register.post(
  '/api/accounts/register/verification-email-clicked',
  rateLimit('register'),
  emailClicked,
)

// Without mail, the first admin and invited users prove their right to register with a code that
// was handed over out of band: the ADMIN_SETUP_TOKEN secret, or the code in an invite link an admin
// copied from the Instance admin page. A valid code yields the same registration token that the
// emailed link would (TASKS #350, docs/emailless.md). Every refusal reads the same.
const redeemSchema = z.object({ email: z.string().email(), code: z.string().min(1).max(512) })
const REDEEM_ATTEMPTS = 5
const REDEEM_WINDOW_MS = 10 * 60_000

register.post(
  '/api/cloudwarden/registration/redeem',
  rateLimit('registration-redeem', 5),
  async (c) => {
    const { email: rawEmail, code: presented } = await parseBody(c, redeemSchema)
    const email = normalizeEmail(rawEmail)
    if (mailConfigured(c.env)) {
      throw new ApiError(400, 'This server sends email, so register with the usual email link.')
    }
    const db = createDb(c.env.DB)
    const refuse = () => new ApiError(400, 'The code is not valid, or it has already been used.')
    // Failures are counted per address and client, so someone who only knows an address cannot use
    // up the allowance of the person holding the right code. A blocked client is refused before
    // anything is checked.
    const failKey = `redeem:${email}:${c.req.header('CF-Connecting-IP') ?? 'unknown'}`
    if (await redeemBlocked(c.env.DB, failKey)) return tooManyRequests(c)
    let setup = false
    try {
      if (isAdminEmail(c.env.ADMIN_EMAILS, email)) {
        const secret = setupToken(c.env)
        // Always compare, so the work done does not depend on whether a secret is set.
        const matches = await codeMatches(presented, secret ?? crypto.randomUUID())
        if (!secret || !matches) throw refuse()
        if ((await adminAccountExists(c.env, db)) || (await setupTokenSpent(db, secret))) {
          throw refuse()
        }
        setup = true
      } else {
        const [invite] = await db
          .select({
            hash: schema.invitations.tokenHash,
            expires: schema.invitations.tokenExpiresAt,
          })
          .from(schema.invitations)
          .where(sql`lower(${schema.invitations.email}) = ${email}`)
          .limit(1)
        const matches = await codeMatches(
          await inviteCodeHash(presented),
          invite?.hash ?? crypto.randomUUID(),
        )
        if (!invite?.hash || !matches || (invite.expires ?? 0) < Date.now()) throw refuse()
      }
    } catch (e) {
      await windowLimit(c.env.DB, failKey, REDEEM_ATTEMPTS, REDEEM_WINDOW_MS, Date.now())
      throw e
    }
    if (await findUserByEmail(db, email)) throw refuse()
    const now = Math.floor(Date.now() / 1000)
    const claims: RegisterClaims = {
      purpose: 'register',
      email,
      name: '',
      ...(setup ? { setup: true } : {}),
      nbf: now,
      exp: now + REGISTER_TOKEN_TTL_SECONDS,
    }
    return c.json({ emailVerificationToken: await signJwt(claims, registerSecret(c.env)) })
  },
)

/** Whether this address and client already failed REDEEM_ATTEMPTS times in the current window. */
async function redeemBlocked(db: D1Database, key: string): Promise<boolean> {
  const windowStart = Math.floor(Date.now() / REDEEM_WINDOW_MS) * REDEEM_WINDOW_MS
  const row = await db
    .prepare('SELECT count FROM admin_rate_limits WHERE key = ?1 AND window_start = ?2')
    .bind(key, windowStart)
    .first<{ count: number }>()
  return (row?.count ?? 0) >= REDEEM_ATTEMPTS
}
