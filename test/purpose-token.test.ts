import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { signJwt } from '../src/auth/jwt'
import { issuerFor } from '../src/auth/middleware'
import { signPurposeToken, verifyPurposeToken } from '../src/auth/purpose-token'

const now = () => Math.floor(Date.now() / 1000)

it('accepts a purpose token signed with its derived key', async () => {
  const token = await signPurposeToken(
    env,
    'verify-email',
    { sub: 'u', email: 'a@example.com' },
    60,
  )
  expect(await verifyPurposeToken(env, 'verify-email', token)).toMatchObject({ sub: 'u' })
})

it('refuses a purpose token signed with the raw JWT secret', async () => {
  const token = await signJwt(
    {
      nbf: now() - 5,
      exp: now() + 60,
      iss: issuerFor(env.DOMAIN),
      purpose: 'verify-email',
      sub: 'u',
      email: 'a@example.com',
    },
    env.JWT_SECRET as string,
  )
  expect(await verifyPurposeToken(env, 'verify-email', token)).toBeNull()
})
