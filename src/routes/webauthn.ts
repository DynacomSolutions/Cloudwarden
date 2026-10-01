// Passkey login credentials (TASKS #125). Request and response shapes follow the web vault
// settings page (`/api/webauthn`) and the login flow (`/identity/accounts/webauthn`).
import { and, eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { requireAuth } from '../auth/middleware'
import {
  assertionCredentialId,
  cleanTransports,
  creationOptions,
  credentialJson,
  loginAssertionOptions,
  MAX_PASSKEYS,
  ownAssertionOptions,
  PASSKEY_ASSERT,
  registrationChallengeOk,
  spendAssertion,
  verifyPasskeyAssertion,
} from '../auth/passkeys'
import { dig, lowerKeys, verifyIdentity } from '../auth/twofactor'
import { originFor, rpIdFor, verifyRegistration, WebAuthnError } from '../auth/webauthn'
import { createDb, schema } from '../db'
import type { Env, User } from '../env'
import { ApiError } from '../errors'
import { overLimit, rateLimit } from '../ratelimit'
import { parseBody } from '../validation'

export const webauthn = new Hono<Env>()

type Ctx = import('hono').Context<Env>

const limit = rateLimit('passkey-manage', 60)
webauthn.use('/api/webauthn', limit)
webauthn.use('/api/webauthn/*', limit)
webauthn.use('/identity/accounts/webauthn/*', rateLimit('passkey-options', 60))

/** `SecretVerificationRequest`: the master password hash (or a verification token). */
const proofSchema = z.object({
  masterPasswordHash: z.string().nullish(),
  userVerificationToken: z.string().nullish(),
})

async function authorise(c: Ctx, body: z.infer<typeof proofSchema>): Promise<User> {
  if (await overLimit(c, 'passkey-verify', c.var.user.uuid)) {
    throw new ApiError(429, 'Too many requests. Try again later.')
  }
  await verifyIdentity(c.env, c.var.user, body)
  return c.var.user
}

const ownRows = (c: Ctx, userUuid: string) =>
  createDb(c.env.DB)
    .select()
    .from(schema.webauthnCredentials)
    .where(eq(schema.webauthnCredentials.userUuid, userUuid))
    .orderBy(schema.webauthnCredentials.createdAt)

const keyField = z.string().min(1).max(4096)
const keyset = {
  encryptedUserKey: keyField.nullish(),
  encryptedPublicKey: keyField.nullish(),
  encryptedPrivateKey: keyField.nullish(),
}

/** Either all three wrapped keys or none. Returns them as a column set. */
function keysetColumns(b: {
  encryptedUserKey?: string | null
  encryptedPublicKey?: string | null
  encryptedPrivateKey?: string | null
}) {
  const given = [b.encryptedUserKey, b.encryptedPublicKey, b.encryptedPrivateKey].filter(Boolean)
  if (given.length !== 0 && given.length !== 3) {
    throw new ApiError(400, 'The encrypted user key, public key and private key go together.')
  }
  return given.length === 0
    ? null
    : {
        encryptedUserKey: b.encryptedUserKey as string,
        encryptedPublicKey: b.encryptedPublicKey as string,
        encryptedPrivateKey: b.encryptedPrivateKey as string,
      }
}

webauthn.get('/api/webauthn', requireAuth, async (c) => {
  const rows = await ownRows(c, c.var.user.uuid)
  return c.json({ data: rows.map(credentialJson), continuationToken: null, object: 'list' })
})

webauthn.post('/api/webauthn/attestation-options', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofSchema))
  const rows = await ownRows(c, user.uuid)
  if (rows.length >= MAX_PASSKEYS) throw new ApiError(400, 'Too many passkeys.')
  return c.json(await creationOptions(c.env, user, rows))
})

webauthn.post('/api/webauthn/assertion-options', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofSchema))
  return c.json(await ownAssertionOptions(c.env, user.uuid, await ownRows(c, user.uuid)))
})

const saveSchema = z.object({
  deviceResponse: z.record(z.string(), z.unknown()),
  name: z.string().trim().min(1).max(50),
  token: z.string().min(1),
  supportsPrf: z.boolean().default(false),
  ...keyset,
})

webauthn.post('/api/webauthn', requireAuth, async (c) => {
  const body = await parseBody(c, saveSchema)
  const user = c.var.user
  const keys = keysetColumns(body)
  if (keys && !body.supportsPrf) {
    throw new ApiError(400, 'Keys can only be stored for a credential that supports PRF.')
  }
  const dr = lowerKeys(body.deviceResponse)
  const attestation = dig(dr, 'response', 'attestationobject')
  const clientData = dig(dr, 'response', 'clientdatajson')
  if (typeof attestation !== 'string' || typeof clientData !== 'string') {
    throw new ApiError(400, 'Invalid passkey response.')
  }
  const rows = await ownRows(c, user.uuid)
  if (rows.length >= MAX_PASSKEYS) throw new ApiError(400, 'Too many passkeys.')

  let reg: Awaited<ReturnType<typeof verifyRegistration>>
  try {
    reg = await verifyRegistration({
      attestationObject: attestation,
      clientDataJSON: clientData,
      rpId: rpIdFor(c.env),
      origin: originFor(c.env),
      requireUv: true,
      challengeOk: registrationChallengeOk(c.env, user.uuid, body.token),
    })
  } catch (err) {
    if (err instanceof WebAuthnError) throw new ApiError(400, 'Passkey could not be verified.')
    throw err
  }

  const now = Date.now()
  try {
    await createDb(c.env.DB)
      .insert(schema.webauthnCredentials)
      .values({
        uuid: crypto.randomUUID(),
        userUuid: user.uuid,
        name: body.name,
        credentialId: reg.credentialId,
        alg: reg.alg,
        jwk: JSON.stringify(reg.jwk),
        signCount: reg.signCount,
        transports: JSON.stringify(cleanTransports(dig(dr, 'response', 'transports'))),
        supportsPrf: body.supportsPrf,
        encryptedUserKey: keys?.encryptedUserKey ?? null,
        encryptedPublicKey: keys?.encryptedPublicKey ?? null,
        encryptedPrivateKey: keys?.encryptedPrivateKey ?? null,
        createdAt: now,
        updatedAt: now,
      })
  } catch {
    // The credential id is unique across all accounts.
    throw new ApiError(400, 'This passkey is already registered.')
  }
  return c.body(null, 200)
})

const updateSchema = z.object({
  deviceResponse: z.record(z.string(), z.unknown()),
  token: z.string().min(1),
  encryptedUserKey: keyField,
  encryptedPublicKey: keyField,
  encryptedPrivateKey: keyField,
})

// Adds (or replaces) the PRF wrapped keyset of a credential after a fresh assertion proved
// the caller holds it. The assertion is what authorises the change.
webauthn.put('/api/webauthn', requireAuth, async (c) => {
  const body = await parseBody(c, updateSchema)
  const user = c.var.user
  if (await overLimit(c, 'passkey-verify', user.uuid)) {
    throw new ApiError(429, 'Too many requests. Try again later.')
  }
  const id = assertionCredentialId(body.deviceResponse)
  const credential = (await ownRows(c, user.uuid)).find((r) => r.credentialId === id)
  if (!credential) throw new ApiError(400, 'Passkey not found.')
  const fail = () => new ApiError(400, 'Passkey could not be verified.')
  let verified: Awaited<ReturnType<typeof verifyPasskeyAssertion>>
  try {
    verified = await verifyPasskeyAssertion(c.env, {
      purpose: PASSKEY_ASSERT,
      subject: user.uuid,
      token: body.token,
      deviceResponse: body.deviceResponse,
      credential,
    })
  } catch (err) {
    if (err instanceof WebAuthnError) throw fail()
    throw err
  }
  const ok = await spendAssertion(createDb(c.env.DB), verified, {
    supportsPrf: true,
    encryptedUserKey: body.encryptedUserKey,
    encryptedPublicKey: body.encryptedPublicKey,
    encryptedPrivateKey: body.encryptedPrivateKey,
    updatedAt: Date.now(),
  })
  if (!ok) throw fail()
  return c.body(null, 200)
})

webauthn.post('/api/webauthn/:id/delete', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofSchema))
  const result = await createDb(c.env.DB)
    .delete(schema.webauthnCredentials)
    .where(
      and(
        eq(schema.webauthnCredentials.uuid, c.req.param('id')),
        eq(schema.webauthnCredentials.userUuid, user.uuid),
      ),
    )
  if (result.meta.changes === 0) throw new ApiError(404, 'Passkey not found.')
  return c.body(null, 200)
})

webauthn.get('/identity/accounts/webauthn/assertion-options', async (c) =>
  c.json(await loginAssertionOptions(c.env)),
)
