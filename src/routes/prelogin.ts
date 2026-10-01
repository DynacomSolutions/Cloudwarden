import { Hono } from 'hono'
import { z } from 'zod'
import { findUserByEmail } from '../auth/users'
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
