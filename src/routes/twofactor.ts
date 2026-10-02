import { and, eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { z } from 'zod'
import { toB64u, utf8 } from '../auth/crypto'
import {
  DUO_CLIENT_ID_RE,
  DUO_CLIENT_SECRET_RE,
  duoHealthCheck,
  isDuoHost,
  isMasked,
  maskSecret,
} from '../auth/duo'
import { requireAuth } from '../auth/middleware'
import { verifyMasterPassword } from '../auth/passwords'
import { base32Decode, generateTotpKey, verifyTotp } from '../auth/totp'
import {
  CHALLENGE_REGISTER,
  clearRememberStatement,
  clock,
  consumeEmailCode,
  type DuoData,
  dig,
  type EmailData,
  enabledProviders,
  enableProviderStatements,
  generateRecoveryCode,
  issueVerificationToken,
  lowerKeys,
  MAX_YUBIKEYS,
  parseData,
  providerRow,
  storeEmailCode,
  TwoFactorType,
  useRecoveryCode,
  verifyIdentity,
  type WebAuthnData,
  type YubiKeyData,
  yubicoConfig,
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
import { isOtp, isPublicId, type OtpPosition, publicIdOf, verifyOtp } from '../auth/yubico'
import { createDb, runBatch, schema } from '../db'
import {
  createEmailTransport,
  recoveryCodeUsedEmail,
  twoFactorChangedEmail,
  twoFactorCodeEmail,
} from '../email'
import { later, sendNotice } from '../email/send'
import type { Env, User } from '../env'
import { ApiError } from '../errors'
import { requirePermission } from '../orgs/access'
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

const PROVIDER_NAMES: Record<number, string> = {
  [TwoFactorType.Authenticator]: 'an authenticator app',
  [TwoFactorType.Email]: 'email',
  [TwoFactorType.WebAuthn]: 'a security key',
}

/** Tells the account owner that two-step login changed (best effort, after the response). */
function announceChange(c: Ctx, user: User, change: 'enabled' | 'disabled', type: number) {
  later(
    c,
    sendNotice(
      c.env,
      user.email,
      twoFactorChangedEmail(change, PROVIDER_NAMES[type] ?? 'another provider'),
    ),
  )
}

async function removeProvider(c: Ctx, user: User, type: number) {
  const db = createDb(c.env.DB)
  await runBatch(db, [
    db
      .delete(schema.twofactor)
      .where(and(eq(schema.twofactor.userUuid, user.uuid), eq(schema.twofactor.atype, type))),
    clearRememberStatement(db, user.uuid),
  ])
  announceChange(c, user, 'disabled', type)
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
  announceChange(c, user, 'enabled', TwoFactorType.Authenticator)
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
  later(c, sendNotice(c.env, user.email, recoveryCodeUsedEmail()))
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
  announceChange(c, user, 'enabled', TwoFactorType.Email)
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
  if (!row?.enabled) announceChange(c, user, 'enabled', TwoFactorType.WebAuthn)
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
// Duo, TASKS #124
// ---------------------------------------------------------------------------

const duoJson = (data: DuoData | null) => ({
  enabled: data !== null,
  host: data?.host ?? null,
  clientId: data?.clientId ?? null,
  clientSecret: data ? maskSecret(data.clientSecret) : null,
})

const duoSchema = proofOnly.extend({
  host: z.string().trim().min(1).max(100),
  clientId: z.string().trim().min(1).max(100),
  clientSecret: z.string().trim().min(1).max(200),
})

/** Validates a Duo configuration the caller submitted, keeping a stored secret when masked. */
async function checkDuoInput(
  body: z.infer<typeof duoSchema>,
  existing: DuoData | null,
): Promise<DuoData> {
  const host = body.host.toLowerCase()
  const secret = isMasked(body.clientSecret) ? existing?.clientSecret : body.clientSecret
  if (!isDuoHost(host)) {
    throw new ApiError(400, 'Invalid Duo API hostname.', { host: ['Invalid Duo API hostname.'] })
  }
  if (!DUO_CLIENT_ID_RE.test(body.clientId)) throw new ApiError(400, 'Invalid Duo client id.')
  if (!secret || !DUO_CLIENT_SECRET_RE.test(secret)) {
    throw new ApiError(400, 'Invalid Duo client secret.')
  }
  const cfg: DuoData = { host, clientId: body.clientId, clientSecret: secret }
  if (!(await duoHealthCheck(cfg))) {
    throw new ApiError(
      400,
      'Duo configuration could not be verified. Check host, client id and secret.',
    )
  }
  return cfg
}

twofactor.post('/api/two-factor/get-duo', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  const row = await providerRow(createDb(c.env.DB), user.uuid, TwoFactorType.Duo)
  return c.json({
    duo: duoJson(row?.enabled ? parseData<DuoData>(row) : null),
    userVerificationToken: await issueVerificationToken(c.env, user),
  })
})

const putDuo = async (c: Ctx) => {
  const body = await parseBody(c, duoSchema)
  const user = await authorise(c, body)
  const db = createDb(c.env.DB)
  const existing = parseData<DuoData>(await providerRow(db, user.uuid, TwoFactorType.Duo))
  const cfg = await checkDuoInput(body, existing)
  await runBatch(db, enableProviderStatements(db, user, TwoFactorType.Duo, cfg))
  return c.json({ duo: duoJson(cfg) })
}
twofactor.put('/api/two-factor/duo', requireAuth, putDuo)
twofactor.post('/api/two-factor/duo', requireAuth, putDuo)
twofactor.delete('/api/two-factor/duo', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  await removeProvider(c, user, TwoFactorType.Duo)
  return c.body(null, 200)
})

// Organisation Duo (provider 6): every confirmed member must complete it at login.
const orgParam = (c: Ctx) => c.req.param('id') as string

async function orgDuoRow(c: Ctx) {
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, orgParam(c), 'managePolicies')
  const [row] = await db
    .select()
    .from(schema.organizationTwofactor)
    .where(
      and(
        eq(schema.organizationTwofactor.organizationUuid, orgParam(c)),
        eq(schema.organizationTwofactor.atype, TwoFactorType.OrganizationDuo),
      ),
    )
    .limit(1)
  return { db, row }
}

twofactor.get('/api/organizations/:id/two-factor', requireAuth, async (c) => {
  const { row } = await orgDuoRow(c)
  return c.json({
    data: row?.enabled ? [providerJson(TwoFactorType.OrganizationDuo, true)] : [],
    continuationToken: null,
    object: 'list',
  })
})

twofactor.post('/api/organizations/:id/two-factor/get-duo', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  const { row } = await orgDuoRow(c)
  let data: DuoData | null = null
  if (row?.enabled) {
    try {
      data = JSON.parse(row.data) as DuoData
    } catch {
      data = null
    }
  }
  return c.json({
    duo: duoJson(data),
    userVerificationToken: await issueVerificationToken(c.env, user),
  })
})

const putOrgDuo = async (c: Ctx) => {
  const body = await parseBody(c, duoSchema)
  await authorise(c, body)
  const { db, row } = await orgDuoRow(c)
  let existing: DuoData | null = null
  try {
    existing = row ? (JSON.parse(row.data) as DuoData) : null
  } catch {
    existing = null
  }
  const cfg = await checkDuoInput(body, existing)
  await db
    .insert(schema.organizationTwofactor)
    .values({
      uuid: crypto.randomUUID(),
      organizationUuid: orgParam(c),
      atype: TwoFactorType.OrganizationDuo,
      enabled: true,
      data: JSON.stringify(cfg),
    })
    .onConflictDoUpdate({
      target: [schema.organizationTwofactor.organizationUuid, schema.organizationTwofactor.atype],
      set: { enabled: true, data: JSON.stringify(cfg) },
    })
  return c.json({ duo: duoJson(cfg) })
}
twofactor.put('/api/organizations/:id/two-factor/duo', requireAuth, putOrgDuo)
twofactor.post('/api/organizations/:id/two-factor/duo', requireAuth, putOrgDuo)
twofactor.delete('/api/organizations/:id/two-factor/duo', requireAuth, async (c) => {
  await authorise(c, await parseBody(c, proofOnly))
  const { db } = await orgDuoRow(c)
  await db
    .delete(schema.organizationTwofactor)
    .where(
      and(
        eq(schema.organizationTwofactor.organizationUuid, orgParam(c)),
        eq(schema.organizationTwofactor.atype, TwoFactorType.OrganizationDuo),
      ),
    )
  return c.body(null, 200)
})

// ---------------------------------------------------------------------------
// YubiKey OTP, TASKS #124
// ---------------------------------------------------------------------------

const yubiJson = (data: YubiKeyData | null) => ({
  enabled: data !== null && data.keys.length > 0,
  key1: data?.keys[0] ?? null,
  key2: data?.keys[1] ?? null,
  key3: data?.keys[2] ?? null,
  key4: data?.keys[3] ?? null,
  key5: data?.keys[4] ?? null,
  nfc: data?.nfc ?? false,
})

twofactor.post('/api/two-factor/get-yubikey', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  const row = await providerRow(createDb(c.env.DB), user.uuid, TwoFactorType.YubiKey)
  return c.json({
    yubiKey: yubiJson(row?.enabled ? parseData<YubiKeyData>(row) : null),
    userVerificationToken: await issueVerificationToken(c.env, user),
  })
})

const yubiKeySchema = proofOnly.extend({
  key1: z.string().nullish(),
  key2: z.string().nullish(),
  key3: z.string().nullish(),
  key4: z.string().nullish(),
  key5: z.string().nullish(),
  nfc: z.boolean().nullish(),
})
const putYubiKey = async (c: Ctx) => {
  const body = await parseBody(c, yubiKeySchema)
  const user = await authorise(c, body)
  const db = createDb(c.env.DB)
  const existing = parseData<YubiKeyData>(await providerRow(db, user.uuid, TwoFactorType.YubiKey))
  const cfg = yubicoConfig(c.env)
  const keys: string[] = []
  const last: Record<string, OtpPosition> = {}
  for (const raw of [body.key1, body.key2, body.key3, body.key4, body.key5]) {
    const value = (raw ?? '').trim().toLowerCase()
    if (!value) continue
    let id: string
    if (isPublicId(value) && existing?.keys.includes(value)) {
      id = value // A key that is already registered, as shown by the get call.
    } else if (isOtp(value)) {
      if (!cfg) {
        throw new ApiError(
          400,
          'YubiKey validation is not configured on this server. The administrator must set YUBICO_CLIENT_ID and YUBICO_SECRET_KEY.',
        )
      }
      const position = await verifyOtp(cfg, value)
      if (!position) {
        throw new ApiError(400, 'A YubiKey OTP could not be verified. Touch the key again.')
      }
      id = publicIdOf(value)
      last[id] = position
    } else {
      throw new ApiError(400, 'Invalid YubiKey OTP.')
    }
    if (!keys.includes(id)) keys.push(id)
  }
  if (keys.length === 0) throw new ApiError(400, 'Enter at least one YubiKey.')
  if (keys.length > MAX_YUBIKEYS) throw new ApiError(400, 'Too many YubiKeys.')
  const kept = Object.fromEntries(
    keys.flatMap((id) => {
      const position = last[id] ?? existing?.last?.[id]
      return position ? [[id, position]] : []
    }),
  )
  const data: YubiKeyData = { keys, nfc: body.nfc === true, last: kept }
  await runBatch(db, enableProviderStatements(db, user, TwoFactorType.YubiKey, data))
  return c.json({ yubiKey: yubiJson(data) })
}
twofactor.put('/api/two-factor/yubikey', requireAuth, putYubiKey)
twofactor.post('/api/two-factor/yubikey', requireAuth, putYubiKey)
twofactor.delete('/api/two-factor/yubikey', requireAuth, async (c) => {
  const user = await authorise(c, await parseBody(c, proofOnly))
  await removeProvider(c, user, TwoFactorType.YubiKey)
  return c.body(null, 200)
})
