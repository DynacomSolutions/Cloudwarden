import { Hono } from 'hono'
import { z } from 'zod'
import { signingSecret, signJwt, verifyJwt } from '../auth/jwt'
import { hashMasterPassword } from '../auth/passwords'
import { findUserByEmail, normalizeEmail } from '../auth/users'
import { createDb, schema } from '../db'
import type { Bindings, Env } from '../env'
import { ApiError } from '../errors'
import { rateLimit } from '../ratelimit'
import { kdfProblem, parseBody } from '../validation'

export const register = new Hono<Env>()

/**
 * Whether `email` may self-register: signups are open, or the address (or its domain)
 * is in SIGNUPS_DOMAINS_WHITELIST. TODO(TASKS #61): also accept organisation invites.
 */
export function signupAllowed(env: Bindings, email: string): boolean {
  if (env.SIGNUPS_ALLOWED === 'true') return true
  const list = (env.SIGNUPS_DOMAINS_WHITELIST ?? '')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean)
  const addr = normalizeEmail(email)
  const domain = addr.slice(addr.lastIndexOf('@') + 1)
  return list.some((entry) => (entry.includes('@') ? entry === addr : entry === domain))
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
  masterPasswordHash: z.string().min(1),
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
  let permitted = signupAllowed(c.env, email)
  if (body.emailVerificationToken) {
    const claims = await verifyJwt<RegisterClaims>(body.emailVerificationToken, [
      registerSecret(c.env),
    ])
    if (claims?.purpose === 'register' && claims.email === email) {
      permitted = true
      name = body.name ?? claims.name
    }
  }
  if (!permitted) throw new ApiError(400, 'Registration is not allowed.')

  const key = body.key ?? body.userSymmetricKey
  if (!key) throw new ApiError(400, 'The request is invalid.', { key: ['key is required'] })
  const keys = body.keys ?? body.userAsymmetricKeys
  const problem = kdfProblem(body)
  if (problem) throw new ApiError(400, problem)

  const db = createDb(c.env.DB)
  if (await findUserByEmail(db, email)) throw new ApiError(400, 'Email is already registered.')

  const now = Date.now()
  const stored = await hashMasterPassword(body.masterPasswordHash)
  const argon = body.kdf === 1
  try {
    await db.insert(schema.users).values({
      uuid: crypto.randomUUID(),
      email,
      name,
      ...stored,
      passwordHint: body.masterPasswordHint ?? null,
      akey: key,
      publicKey: keys?.publicKey ?? null,
      privateKey: keys?.encryptedPrivateKey ?? null,
      kdfType: body.kdf,
      kdfIterations: body.kdfIterations,
      kdfMemory: argon ? (body.kdfMemory ?? null) : null,
      kdfParallelism: argon ? (body.kdfParallelism ?? null) : null,
      securityStamp: crypto.randomUUID(),
      // No mail transport yet (TASKS #141), so addresses are treated as verified.
      verifiedAt: now,
      createdAt: now,
      updatedAt: now,
    })
  } catch {
    // Lost a race with a concurrent registration of the same address.
    throw new ApiError(400, 'Email is already registered.')
  }
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

// No mail transport exists yet (TASKS #141), so verification is disabled: instead of
// emailing a link (204) the server returns the verification token directly (200).
register.post(
  '/identity/accounts/register/send-verification-email',
  rateLimit('register'),
  async (c) => {
    const body = await parseBody(c, sendSchema)
    const email = normalizeEmail(body.email)
    if (!signupAllowed(c.env, email)) throw new ApiError(400, 'Registration is not allowed.')
    const now = Math.floor(Date.now() / 1000)
    const claims: RegisterClaims = {
      purpose: 'register',
      email,
      name: body.name ?? '',
      nbf: now,
      exp: now + REGISTER_TOKEN_TTL_SECONDS,
    }
    return c.json(await signJwt(claims, registerSecret(c.env)))
  },
)
