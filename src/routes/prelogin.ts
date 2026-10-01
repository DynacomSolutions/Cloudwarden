import { Hono } from 'hono'
import { z } from 'zod'
import { findUserByEmail, normalizeEmail } from '../auth/users'
import { createDb } from '../db'
import type { Env } from '../env'
import { rateLimit } from '../ratelimit'
import { parseBody } from '../validation'

export const prelogin = new Hono<Env>()

const preloginSchema = z.object({ email: z.string().email() })

// Returned for unknown emails so the response does not reveal whether an account exists.
const DEFAULT_KDF = { kdf: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null }

const handler = async (c: import('hono').Context<Env>) => {
  const { email } = await parseBody(c, preloginSchema)
  const user = await findUserByEmail(createDb(c.env.DB), email)
  if (!user) return c.json(DEFAULT_KDF)
  return c.json({
    kdf: user.kdfType,
    kdfIterations: user.kdfIterations,
    kdfMemory: user.kdfMemory,
    kdfParallelism: user.kdfParallelism,
  })
}

prelogin.post('/api/accounts/prelogin', rateLimit('prelogin'), handler)
prelogin.post('/identity/accounts/prelogin', rateLimit('prelogin'), handler)

// Current clients (2026.x) call this instead: nested KDF settings plus the salt used for the master
// key, which is the normalised email. Unknown emails get defaults and the same deterministic salt.
const passwordHandler = async (c: import('hono').Context<Env>) => {
  const { email } = await parseBody(c, preloginSchema)
  const user = await findUserByEmail(createDb(c.env.DB), email)
  const kdf = user
    ? {
        kdf: user.kdfType,
        kdfIterations: user.kdfIterations,
        kdfMemory: user.kdfMemory,
        kdfParallelism: user.kdfParallelism,
      }
    : DEFAULT_KDF
  return c.json({
    kdfSettings: {
      kdfType: kdf.kdf,
      iterations: kdf.kdfIterations,
      memory: kdf.kdfMemory,
      parallelism: kdf.kdfParallelism,
    },
    salt: normalizeEmail(email),
  })
}

prelogin.post('/identity/accounts/prelogin/password', rateLimit('prelogin'), passwordHandler)
prelogin.post('/api/accounts/prelogin/password', rateLimit('prelogin'), passwordHandler)
