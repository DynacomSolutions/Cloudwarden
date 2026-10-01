import { Hono } from 'hono'
import { z } from 'zod'
import type { Env } from '../env'

export const prelogin = new Hono<Env>()

const preloginSchema = z.object({ email: z.string().email() })

// Default KDF parameters (PBKDF2-SHA256).
const DEFAULT_KDF = { kdf: 0, kdfIterations: 600000 } as const

const handler = async (c: import('hono').Context<Env>) => {
  const body = await c.req.json().catch(() => null)
  const parsed = preloginSchema.safeParse(body)
  if (!parsed.success) {
    return c.json(
      {
        message: 'Invalid request',
        validationErrors: { email: ['A valid email is required'] },
        object: 'error',
      },
      400,
    )
  }
  // TODO: look up the user and return their stored KDF settings.
  return c.json({ ...DEFAULT_KDF })
}

prelogin.post('/api/accounts/prelogin', handler)
prelogin.post('/identity/accounts/prelogin', handler)
