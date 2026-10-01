import { and, eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { toB64u, utf8 } from '../auth/crypto'
import { requireAuth } from '../auth/middleware'
import { verifyMasterPassword } from '../auth/passwords'
import { base32Decode, generateTotpKey, verifyTotp } from '../auth/totp'
import {
  CHALLENGE_REGISTER,
  clearRememberStatement,
  clock,
  consumeEmailCode,
  dig,
  type EmailData,
  enabledProviders,
  enableProviderStatements,
  generateRecoveryCode,
  issueVerificationToken,
  lowerKeys,
  parseData,
  providerRow,
  storeEmailCode,
  TwoFactorType,
  useRecoveryCode,
  verifyIdentity,
  type WebAuthnData,
} from '../auth/twofactor'
import { findUserByEmail, normalizeEmail } from '../auth/users'
import {
  COSE_ES256,
  COSE_RS256,
  checkChallenge,
  createChallenge,
  originFor,
  rpIdFor,
  verifyRegistration,
  WebAuthnError,
} from '../auth/webauthn'
import { createDb, runBatch, schema } from '../db'
import { createEmailTransport, twoFactorCodeEmail } from '../email'
import type { Env, User } from '../env'
import { ApiError } from '../errors'
import { overLimit, rateLimit, tooManyRequests } from '../ratelimit'
import { parseBody } from '../validation'

export const twofactor = new Hono<Env>()

type Ctx = import('hono').Context<Env>

const limit = rateLimit('two-factor-manage', 60)
twofactor.use('/api/two-factor', limit)
twofactor.use('/api/two-factor/*', limit)
twofactor.use('/identity/accounts/two-factor/*', limit)

const MAX_WEBAUTHN_KEYS = 5

const proof = {
  masterPasswordHash: z.string().nullish(),
  userVerificationToken: z.string().nullish(),
}
const proofOnly = z.object(proof)

/** Verifies the caller and returns the user. Used by every management endpoint. */
async function authorise(c: Ctx, body: z.infer<typeof proofOnly>): Promise<User> {
  if (await overLimit(c, 'two-factor-verify', c.var.user.uuid)) {
    throw new ApiError(429, 'Too many requests. Try again later.')
  }
  await verifyIdentity(c.env, c.var.user, body)
  return c.var.user
}

const providerJson = (type: number, enabled: boolean) => ({
  enabled,
  type,
  object: 'twoFactorProvider',
})

twofactor.get('/api/two-factor', requireAuth, async (c) => {
  const rows = await enabledProviders(createDb(c.env.DB), c.var.user.uuid)
  return c.json({
    data: rows.map((r) => providerJson(r.atype, true)),
    continuationToken: null,
    object: 'list',
  })
})

async function removeProvider(c: Ctx, user: User, type: number) {
  const db = createDb(c.env.DB)
  await runBatch(db, [
    db
      .delete(schema.twofactor)
      .where(and(eq(schema.twofactor.userUuid, user.uuid), eq(schema.twofactor.atype, type))),
    clearRememberStatement(db, user.uuid),
  ])
}

twofactor.post('/api/two-factor/disable', requireAuth, async (c) => {
  const body = await parseBody(c, proofOnly.extend({ type: z.number().int() }))
  const user = await authorise(c, body)
  await removeProvider(c, user, body.type)
  return c.json(providerJson(body.type, false))
})

// ---------------------------------------------------------------------------
// Authenticator app (TOTP), TASKS #120
// ---------------------------------------------------------------------------

twofactor.post('/api/two-factor/get-authenticator', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  const row = await providerRow(createDb(c.env.DB), user.uuid, TwoFactorType.Authenticator)
  const data = row?.enabled ? parseData<{ key: string }>(row) : null
  return c.json({
    authenticator: { enabled: data !== null, key: data?.key ?? generateTotpKey() },
    userVerificationToken: await issueVerificationToken(c.env, user),
  })
})

const authenticatorSchema = proofOnly.extend({
  key: z.string().min(16).max(128),
  token: z.string(),
})
const putAuthenticator = async (c: Ctx) => {
  const body = await parseBody(c, authenticatorSchema)
  const user = await authorise(c, body)
  const key = body.key.replace(/[\s-]/g, '').toUpperCase()
  const secret = base32Decode(key)
  if (!secret || secret.length < 10) throw new ApiError(400, 'Invalid key.')
  const step = await verifyTotp(key, body.token, clock.now(), 0)
  if (step === null) throw new ApiError(400, 'Invalid token.')
  const db = createDb(c.env.DB)
  await runBatch(
    db,
    enableProviderStatements(db, user, TwoFactorType.Authenticator, { key }, { lastUsed: step }),
  )
  return c.json({ authenticator: { enabled: true, key } })
}
twofactor.put('/api/two-factor/authenticator', requireAuth, putAuthenticator)
twofactor.post('/api/two-factor/authenticator', requireAuth, putAuthenticator)
twofactor.delete('/api/two-factor/authenticator', requireAuth, async (c) => {
  const body = await parseBody(c, proofOnly.extend({ key: z.string().nullish() }))
  const user = await authorise(c, body)
  await removeProvider(c, user, TwoFactorType.Authenticator)
  return c.body(null, 200)
})

// ---------------------------------------------------------------------------
// Recovery code, TASKS #121
// ---------------------------------------------------------------------------

twofactor.post('/api/two-factor/get-recover', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  let code = user.totpRecover
  if (!code) {
    code = generateRecoveryCode()
    await createDb(c.env.DB)
      .update(schema.users)
      .set({ totpRecover: code, updatedAt: Date.now() })
      .where(eq(schema.users.uuid, user.uuid))
  }
  return c.json({ code, object: 'twoFactorRecover' })
})

const recoverSchema = z.object({
  email: z.string().min(1),
  masterPasswordHash: z.string().min(1),
  recoveryCode: z.string().min(1),
})
/** Anonymous: proves possession of the password and the recovery code, then drops all 2FA. */
const recover = async (c: Ctx) => {
  const body = await parseBody(c, recoverSchema)
  const db = createDb(c.env.DB)
  const user = await findUserByEmail(db, body.email)
  if (user && (await overLimit(c, 'two-factor-recover', user.uuid))) return tooManyRequests(c)
  const passwordOk = await verifyMasterPassword(user, body.masterPasswordHash)
  const spent = passwordOk && user ? await useRecoveryCode(db, user, body.recoveryCode) : false
  if (!user || !spent || !user.enabled) {
    throw new ApiError(400, 'Recovery code is incorrect. Try again.')
  }
  return c.body(null, 200)
}
twofactor.post('/api/two-factor/recover', recover)
twofactor.post('/identity/accounts/two-factor/recover', recover)

// ---------------------------------------------------------------------------
// Email, TASKS #123
// ---------------------------------------------------------------------------

async function sendCode(c: Ctx, to: string, code: string) {
  const transport = createEmailTransport(c.env)
  if (!transport.configured) throw new ApiError(400, 'Email delivery is not configured.')
  await transport.send({ to, ...twoFactorCodeEmail(code, 10) })
}

twofactor.post('/api/two-factor/get-email', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  const row = await providerRow(createDb(c.env.DB), user.uuid, TwoFactorType.Email)
  const data = row?.enabled ? parseData<EmailData>(row) : null
  return c.json({
    email: { enabled: data !== null, email: data?.email ?? null },
    userVerificationToken: await issueVerificationToken(c.env, user),
  })
})

twofactor.post('/api/two-factor/send-email', requireAuth, async (c) => {
  const body = await parseBody(c, proofOnly.extend({ email: z.string().email() }))
  const user = await authorise(c, body)
  const db = createDb(c.env.DB)
  const row = await providerRow(db, user.uuid, TwoFactorType.Email)
  if (row?.enabled) throw new ApiError(400, 'Email two-factor is already enabled.')
  if (!createEmailTransport(c.env).configured) {
    throw new ApiError(400, 'Email delivery is not configured.')
  }
  const email = normalizeEmail(body.email)
  const code = await storeEmailCode(db, user, row, email)
  await sendCode(c, email, code)
  return c.body(null, 200)
})

const putEmail = async (c: Ctx) => {
  const body = await parseBody(
    c,
    proofOnly.extend({ email: z.string().email(), token: z.string() }),
  )
  const user = await authorise(c, body)
  const db = createDb(c.env.DB)
  const row = await providerRow(db, user.uuid, TwoFactorType.Email)
  const data = parseData<EmailData>(row)
  const email = normalizeEmail(body.email)
  if (!row || row.enabled || !data || data.email !== email) {
    throw new ApiError(400, 'Invalid token.')
  }
  if (!(await consumeEmailCode(db, user, row, body.token))) {
    throw new ApiError(400, 'Invalid token.')
  }
  await runBatch(
    db,
    enableProviderStatements(db, user, TwoFactorType.Email, { email, attempts: 0 }),
  )
  return c.json({ email: { enabled: true, email } })
}
twofactor.put('/api/two-factor/email', requireAuth, putEmail)
twofactor.post('/api/two-factor/email', requireAuth, putEmail)
twofactor.delete('/api/two-factor/email', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  await removeProvider(c, user, TwoFactorType.Email)
  return c.body(null, 200)
})

/** Anonymous: mails a login code once the primary credential has been shown. */
twofactor.post('/api/two-factor/send-email-login', async (c) => {
  const body = await parseBody(
    c,
    z.object({ email: z.string().min(1), masterPasswordHash: z.string().nullish() }).loose(),
  )
  const db = createDb(c.env.DB)
  const user = await findUserByEmail(db, body.email)
  if (user && (await overLimit(c, 'two-factor-email', user.uuid))) return tooManyRequests(c)
  const ok = await verifyMasterPassword(user, body.masterPasswordHash ?? '')
  if (!user || !ok || !user.enabled) {
    throw new ApiError(400, 'Username or password is incorrect. Try again.')
  }
  const row = await providerRow(db, user.uuid, TwoFactorType.Email)
  const data = parseData<EmailData>(row)
  if (!row?.enabled || !data) throw new ApiError(400, 'Email two-factor is not enabled.')
  const code = await storeEmailCode(db, user, row, data.email)
  await sendCode(c, data.email, code)
  return c.body(null, 200)
})

// ---------------------------------------------------------------------------
// WebAuthn, TASKS #122
// ---------------------------------------------------------------------------

const keysJson = (data: WebAuthnData | null) => ({
  enabled: data !== null && data.credentials.length > 0,
  keys: (data?.credentials ?? []).map((k) => ({ name: k.name, id: k.id, migrated: false })),
})

twofactor.post('/api/two-factor/get-webauthn', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  const row = await providerRow(createDb(c.env.DB), user.uuid, TwoFactorType.WebAuthn)
  return c.json({
    webAuthn: keysJson(row?.enabled ? parseData<WebAuthnData>(row) : null),
    userVerificationToken: await issueVerificationToken(c.env, user),
  })
})

twofactor.post('/api/two-factor/get-webauthn-challenge', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  const row = await providerRow(createDb(c.env.DB), user.uuid, TwoFactorType.WebAuthn)
  const existing = parseData<WebAuthnData>(row)?.credentials ?? []
  if (existing.length >= MAX_WEBAUTHN_KEYS) throw new ApiError(400, 'Too many security keys.')
  return c.json({
    options: {
      challenge: await createChallenge(c.env, CHALLENGE_REGISTER, user.uuid, clock.now()),
      rp: { id: rpIdFor(c.env), name: 'Cloudwarden' },
      user: { id: toB64u(utf8(user.uuid)), name: user.email, displayName: user.name || user.email },
      pubKeyCredParams: [
        { type: 'public-key', alg: COSE_ES256 },
        { type: 'public-key', alg: COSE_RS256 },
      ],
      timeout: 60000,
      attestation: 'none',
      excludeCredentials: existing.map((k) => ({ type: 'public-key', id: k.credentialId })),
      authenticatorSelection: { residentKey: 'discouraged', userVerification: 'discouraged' },
      extensions: {},
    },
  })
})

const webauthnSchema = proofOnly.extend({
  deviceResponse: z.record(z.string(), z.unknown()),
  name: z.string().max(50).default('Security key'),
  id: z.number().int().min(1).max(MAX_WEBAUTHN_KEYS),
})
const putWebAuthn = async (c: Ctx) => {
  const body = await parseBody(c, webauthnSchema)
  const user = await authorise(c, body)
  const dr = lowerKeys(body.deviceResponse)
  const attestation = dig(dr, 'response', 'attestationobject')
  const clientData = dig(dr, 'response', 'clientdatajson')
  if (typeof attestation !== 'string' || typeof clientData !== 'string') {
    throw new ApiError(400, 'Invalid security key response.')
  }
  let reg: Awaited<ReturnType<typeof verifyRegistration>>
  try {
    reg = await verifyRegistration({
      attestationObject: attestation,
      clientDataJSON: clientData,
      rpId: rpIdFor(c.env),
      origin: originFor(c.env),
      challengeOk: async (challenge) =>
        (await checkChallenge(c.env, CHALLENGE_REGISTER, user.uuid, challenge, clock.now())) !==
        null,
    })
  } catch (err) {
    if (err instanceof WebAuthnError) throw new ApiError(400, 'Security key could not be verified.')
    throw err
  }
  const db = createDb(c.env.DB)
  const row = await providerRow(db, user.uuid, TwoFactorType.WebAuthn)
  const current = parseData<WebAuthnData>(row)?.credentials ?? []
  if (current.some((k) => k.credentialId === reg.credentialId && k.id !== body.id)) {
    throw new ApiError(400, 'This security key is already registered.')
  }
  const credentials = [
    ...current.filter((k) => k.id !== body.id),
    {
      id: body.id,
      name: body.name,
      credentialId: reg.credentialId,
      alg: reg.alg,
      jwk: reg.jwk,
      signCount: reg.signCount,
    },
  ].sort((a, b) => a.id - b.id)
  if (credentials.length > MAX_WEBAUTHN_KEYS) throw new ApiError(400, 'Too many security keys.')
  await runBatch(
    db,
    enableProviderStatements(
      db,
      user,
      TwoFactorType.WebAuthn,
      { credentials } satisfies WebAuthnData,
      {
        lastUsed: row?.lastUsed ?? 0,
      },
    ),
  )
  return c.json({ webAuthn: keysJson({ credentials }) })
}
twofactor.put('/api/two-factor/webauthn', requireAuth, putWebAuthn)
twofactor.post('/api/two-factor/webauthn', requireAuth, putWebAuthn)

twofactor.delete('/api/two-factor/webauthn', requireAuth, async (c) => {
  const body = await parseBody(c, proofOnly.extend({ id: z.number().int() }))
  const user = await authorise(c, body)
  const db = createDb(c.env.DB)
  const row = await providerRow(db, user.uuid, TwoFactorType.WebAuthn)
  const data = parseData<WebAuthnData>(row)
  if (!row || !data) throw new ApiError(400, 'Security key not found.')
  const credentials = data.credentials.filter((k) => k.id !== body.id)
  if (credentials.length === data.credentials.length) {
    throw new ApiError(400, 'Security key not found.')
  }
  if (credentials.length === 0) {
    await removeProvider(c, user, TwoFactorType.WebAuthn)
    return c.json({ webAuthn: keysJson(null) })
  }
  await db
    .update(schema.twofactor)
    .set({ data: JSON.stringify({ credentials }) })
    .where(eq(schema.twofactor.uuid, row.uuid))
  return c.json({ webAuthn: keysJson({ credentials }) })
})

twofactor.delete('/api/two-factor/webauthn/all', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  await removeProvider(c, user, TwoFactorType.WebAuthn)
  return c.body(null, 200)
})

// ---------------------------------------------------------------------------
// YubiKey OTP and Duo are not supported, TASKS #124
// ---------------------------------------------------------------------------

const unsupported = (name: string) => () => {
  throw new ApiError(400, `${name} two-factor authentication is not supported by this server.`)
}
for (const [slug, name] of [
  ['duo', 'Duo'],
  ['yubikey', 'YubiKey'],
] as const) {
  twofactor.post(`/api/two-factor/get-${slug}`, requireAuth, unsupported(name))
  twofactor.put(`/api/two-factor/${slug}`, requireAuth, unsupported(name))
  twofactor.post(`/api/two-factor/${slug}`, requireAuth, unsupported(name))
  twofactor.delete(`/api/two-factor/${slug}`, requireAuth, unsupported(name))
}
