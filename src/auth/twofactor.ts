import { and, eq, inArray, isNull, lt } from 'drizzle-orm'
import type { Context } from 'hono'
import type { Db } from '../db'
import { createDb, schema } from '../db'
import type { Bindings, Env, User } from '../env'
import { ApiError, oauthError } from '../errors'
import { overLimit, tooManyRequests } from '../ratelimit'
import { randomB64u, safeEqualStrings, sha256B64u } from './crypto'
import { signingSecret, signJwt, verificationSecrets, verifyJwt } from './jwt'
import { verifyMasterPassword } from './passwords'
import { base32Encode, generateTotpKey, verifyTotp } from './totp'
import {
  checkChallenge,
  createChallenge,
  originFor,
  rpIdFor,
  type StoredCredential,
  verifyAssertion,
  WebAuthnError,
} from './webauthn'

/** Provider type numbers used on the wire. */
export const TwoFactorType = {
  Authenticator: 0,
  Email: 1,
  Duo: 2,
  YubiKey: 3,
  Remember: 5,
  OrganizationDuo: 6,
  WebAuthn: 7,
  RecoveryCode: 8,
} as const

/** Providers this server can verify. Duo and YubiKey OTP are not supported (TASKS #124). */
export const SUPPORTED_TYPES: number[] = [
  TwoFactorType.Authenticator,
  TwoFactorType.Email,
  TwoFactorType.WebAuthn,
]

export const EMAIL_CODE_TTL_MS = 10 * 60 * 1000
export const EMAIL_CODE_MAX_ATTEMPTS = 5
export const REMEMBER_TTL_MS = 30 * 24 * 3600 * 1000
export const VERIFICATION_TOKEN_TTL_S = 30 * 60

/** Time source for the provider checks. Tests replace `now` to pin the clock. */
export const clock = { now: (): number => Date.now() }

export type TwoFactorRow = typeof schema.twofactor.$inferSelect

export function parseData<T>(row: TwoFactorRow | undefined): T | null {
  if (!row) return null
  try {
    return JSON.parse(row.data) as T
  } catch {
    return null
  }
}

export async function enabledProviders(db: Db, userUuid: string): Promise<TwoFactorRow[]> {
  return db
    .select()
    .from(schema.twofactor)
    .where(
      and(
        eq(schema.twofactor.userUuid, userUuid),
        eq(schema.twofactor.enabled, true),
        inArray(schema.twofactor.atype, SUPPORTED_TYPES),
      ),
    )
}

export async function providerRow(
  db: Db,
  userUuid: string,
  atype: number,
): Promise<TwoFactorRow | undefined> {
  const [row] = await db
    .select()
    .from(schema.twofactor)
    .where(and(eq(schema.twofactor.userUuid, userUuid), eq(schema.twofactor.atype, atype)))
    .limit(1)
  return row
}

/** Compare-and-swap on the data column so concurrent attempts cannot both succeed. */
async function swapData(
  db: Db,
  row: TwoFactorRow,
  data: unknown,
  extra: { lastUsed?: number } = {},
  guardLastUsedBelow?: number,
): Promise<boolean> {
  const conditions = [eq(schema.twofactor.uuid, row.uuid), eq(schema.twofactor.data, row.data)]
  if (guardLastUsedBelow !== undefined) {
    conditions.push(lt(schema.twofactor.lastUsed, guardLastUsedBelow))
  }
  const result = await db
    .update(schema.twofactor)
    .set({ data: JSON.stringify(data), ...extra })
    .where(and(...conditions))
  return result.meta.changes > 0
}

// ---------------------------------------------------------------------------
// Recovery code and shared write helpers
// ---------------------------------------------------------------------------

export const generateRecoveryCode = (): string =>
  base32Encode(crypto.getRandomValues(new Uint8Array(20)))

/** Upserts a provider row and, if the user has no recovery code yet, creates one. */
export function enableProviderStatements(
  db: Db,
  user: User,
  atype: number,
  data: unknown,
  opts: { enabled?: boolean; lastUsed?: number } = {},
) {
  const enabled = opts.enabled ?? true
  const lastUsed = opts.lastUsed ?? 0
  return [
    db
      .insert(schema.twofactor)
      .values({
        uuid: crypto.randomUUID(),
        userUuid: user.uuid,
        atype,
        enabled,
        data: JSON.stringify(data),
        lastUsed,
      })
      .onConflictDoUpdate({
        target: [schema.twofactor.userUuid, schema.twofactor.atype],
        set: { enabled, data: JSON.stringify(data), lastUsed },
      }),
    ...(enabled
      ? [
          db
            .update(schema.users)
            .set({ totpRecover: generateRecoveryCode(), updatedAt: Date.now() })
            .where(and(eq(schema.users.uuid, user.uuid), isNull(schema.users.totpRecover))),
        ]
      : []),
  ]
}

export function clearRememberStatement(db: Db, userUuid: string) {
  return db
    .update(schema.devices)
    .set({ twofactorRemember: null })
    .where(eq(schema.devices.userUuid, userUuid))
}

// ---------------------------------------------------------------------------
// Re-authentication for the management endpoints
// ---------------------------------------------------------------------------

const VERIFY_PURPOSE = 'two-factor-verify'

export async function issueVerificationToken(env: Bindings, user: User): Promise<string> {
  const now = Math.floor(clock.now() / 1000)
  return signJwt(
    { purpose: VERIFY_PURPOSE, sub: user.uuid, nbf: now, exp: now + VERIFICATION_TOKEN_TTL_S },
    signingSecret(env),
  )
}

export interface IdentityProof {
  masterPasswordHash?: string | null
  userVerificationToken?: string | null
}

/** Accepts the master password hash or a verification token from an earlier `get-*` call. */
export async function verifyIdentity(env: Bindings, user: User, proof: IdentityProof) {
  if (proof.userVerificationToken) {
    const claims = await verifyJwt<{ purpose?: string; sub?: string; exp: number }>(
      proof.userVerificationToken,
      verificationSecrets(env),
      Math.floor(clock.now() / 1000),
    )
    if (claims?.purpose === VERIFY_PURPOSE && claims.sub === user.uuid) return
  } else if (
    proof.masterPasswordHash &&
    (await verifyMasterPassword(user, proof.masterPasswordHash))
  ) {
    return
  }
  throw new ApiError(400, 'User verification failed.', {
    masterPasswordHash: ['Invalid password.'],
  })
}

// ---------------------------------------------------------------------------
// Email provider
// ---------------------------------------------------------------------------

export interface EmailData {
  email: string
  codeHash?: string | null
  expiresAt?: number
  attempts?: number
}

export const maskEmail = (email: string): string => {
  const at = email.indexOf('@')
  if (at < 1) return '***'
  return `${email.slice(0, 1)}***${email.slice(at)}`
}

/** Uniform 6 digit code (rejection sampling avoids modulo bias). */
export function generateEmailCode(): string {
  const limit = 4_294_000_000 - (4_294_000_000 % 1_000_000)
  const buf = new Uint32Array(1)
  for (;;) {
    crypto.getRandomValues(buf)
    if ((buf[0] as number) < limit) return String((buf[0] as number) % 1_000_000).padStart(6, '0')
  }
}

const codeHash = (userUuid: string, code: string) => sha256B64u(`${userUuid}:${code}`)

/** Stores a fresh code on the row (creating a disabled row during setup) and returns it. */
export async function storeEmailCode(
  db: Db,
  user: User,
  row: TwoFactorRow | undefined,
  email: string,
): Promise<string> {
  const code = generateEmailCode()
  const data: EmailData = {
    email,
    codeHash: await codeHash(user.uuid, code),
    expiresAt: clock.now() + EMAIL_CODE_TTL_MS,
    attempts: 0,
  }
  if (row) {
    await db
      .update(schema.twofactor)
      .set({ data: JSON.stringify(data) })
      .where(eq(schema.twofactor.uuid, row.uuid))
  } else {
    await db.insert(schema.twofactor).values({
      uuid: crypto.randomUUID(),
      userUuid: user.uuid,
      atype: TwoFactorType.Email,
      enabled: false,
      data: JSON.stringify(data),
      lastUsed: 0,
    })
  }
  return code
}

/** Checks and consumes an emailed code. Wrong guesses count toward the attempt limit. */
export async function consumeEmailCode(
  db: Db,
  user: User,
  row: TwoFactorRow,
  code: string,
): Promise<boolean> {
  const data = parseData<EmailData>(row)
  if (!data?.codeHash || !data.expiresAt) return false
  const attempts = data.attempts ?? 0
  if (clock.now() > data.expiresAt || attempts >= EMAIL_CODE_MAX_ATTEMPTS) return false
  const match = safeEqualStrings(data.codeHash, await codeHash(user.uuid, code.trim()))
  if (match) {
    return swapData(db, row, { email: data.email, codeHash: null, attempts: 0 })
  }
  await swapData(db, row, { ...data, attempts: attempts + 1 })
  return false
}

// ---------------------------------------------------------------------------
// WebAuthn provider
// ---------------------------------------------------------------------------

export interface WebAuthnData {
  credentials: StoredCredential[]
}

export const CHALLENGE_REGISTER = 'webauthn-register'
export const CHALLENGE_LOGIN = 'webauthn-login'

/** Lowercases object keys recursively; clients disagree on casing of assertion fields. */
export function lowerKeys(value: unknown, depth = 4): unknown {
  if (Array.isArray(value)) return value.map((v) => lowerKeys(v, depth))
  if (value && typeof value === 'object' && depth > 0) {
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [k.toLowerCase(), lowerKeys(v, depth - 1)]),
    )
  }
  return value
}

/** Reads a nested property from untyped JSON; undefined when any step is missing. */
export function dig(value: unknown, ...path: string[]): unknown {
  let cur = value
  for (const key of path) {
    if (!cur || typeof cur !== 'object') return undefined
    cur = (cur as Record<string, unknown>)[key]
  }
  return cur
}

async function assertionOptions(env: Bindings, user: User, data: WebAuthnData) {
  return {
    challenge: await createChallenge(env, CHALLENGE_LOGIN, user.uuid, clock.now()),
    timeout: 60000,
    rpId: rpIdFor(env),
    allowCredentials: data.credentials.map((c) => ({ type: 'public-key', id: c.credentialId })),
    userVerification: 'discouraged',
    extensions: {},
  }
}

async function verifyWebAuthnLogin(
  c: Context<Env>,
  db: Db,
  user: User,
  row: TwoFactorRow,
  token: string,
): Promise<boolean> {
  const data = parseData<WebAuthnData>(row)
  if (!data) return false
  let parsed: unknown
  try {
    parsed = lowerKeys(JSON.parse(token))
  } catch {
    return false
  }
  const id = String(dig(parsed, 'rawid') ?? dig(parsed, 'id') ?? '')
  const credential = data.credentials.find((k) => k.credentialId === id)
  if (!credential || !dig(parsed, 'response')) return false
  const field = (name: string) => String(dig(parsed, 'response', name) ?? '')

  let challengeTs: number | null = null
  try {
    const signCount = await verifyAssertion({
      credential,
      authenticatorData: field('authenticatordata'),
      clientDataJSON: field('clientdatajson'),
      signature: field('signature'),
      rpId: rpIdFor(c.env),
      origin: originFor(c.env),
      challengeOk: async (challenge) => {
        challengeTs = await checkChallenge(
          c.env,
          CHALLENGE_LOGIN,
          user.uuid,
          challenge,
          clock.now(),
        )
        return challengeTs !== null
      },
    })
    if (challengeTs === null) return false
    const credentials = data.credentials.map((k) =>
      k.credentialId === id ? { ...k, signCount } : k,
    )
    // lastUsed holds the newest accepted challenge time, so a challenge works only once.
    return swapData(db, row, { credentials }, { lastUsed: challengeTs }, challengeTs)
  } catch (err) {
    if (err instanceof WebAuthnError) return false
    throw err
  }
}

// ---------------------------------------------------------------------------
// Remember-me tokens (provider 5)
// ---------------------------------------------------------------------------

/** Stores a hashed remember token on the device and returns the secret for the client. */
export async function issueRememberToken(
  db: Db,
  userUuid: string,
  deviceIdentifier: string,
): Promise<string> {
  const token = randomB64u(32)
  await db
    .update(schema.devices)
    .set({ twofactorRemember: `${await sha256B64u(token)}.${clock.now() + REMEMBER_TTL_MS}` })
    .where(
      and(eq(schema.devices.userUuid, userUuid), eq(schema.devices.identifier, deviceIdentifier)),
    )
  return token
}

async function rememberValid(
  db: Db,
  userUuid: string,
  deviceIdentifier: string | undefined,
  token: string,
): Promise<boolean> {
  if (!deviceIdentifier) return false
  const [device] = await db
    .select({ remember: schema.devices.twofactorRemember })
    .from(schema.devices)
    .where(
      and(eq(schema.devices.userUuid, userUuid), eq(schema.devices.identifier, deviceIdentifier)),
    )
    .limit(1)
  const [hash, exp] = (device?.remember ?? '').split('.')
  if (!hash || !exp || Number(exp) <= clock.now()) return false
  return safeEqualStrings(hash, await sha256B64u(token))
}

// ---------------------------------------------------------------------------
// Token endpoint hook
// ---------------------------------------------------------------------------

/**
 * Hook for second-factor enforcement, called by the token endpoint after the primary
 * credential is verified and before any token is issued. Returns a Response to stop the
 * login (the Bitwarden two-factor challenge, an error or 429), or null to continue.
 */
export type TwoFactorHook = (
  c: Context<Env>,
  user: User,
  form: Record<string, string>,
) => Promise<Response | null>

async function challengeBody(c: Context<Env>, user: User, rows: TwoFactorRow[], message: string) {
  const types = [...new Set(rows.map((r) => r.atype))].sort((a, b) => a - b)
  const params: Record<string, unknown> = {}
  for (const row of rows) {
    if (row.atype === TwoFactorType.Email) {
      const data = parseData<EmailData>(row)
      params[String(row.atype)] = { Email: maskEmail(data?.email ?? user.email) }
    } else if (row.atype === TwoFactorType.WebAuthn) {
      const data = parseData<WebAuthnData>(row) ?? { credentials: [] }
      params[String(row.atype)] = await assertionOptions(c.env, user, data)
    } else {
      params[String(row.atype)] = null
    }
  }
  return c.json(
    {
      error: 'invalid_grant',
      error_description: message,
      TwoFactorProviders: types.map(String),
      TwoFactorProviders2: params,
      SsoEmail2faSessionToken: null,
      MasterPasswordPolicy: { Object: 'masterPasswordPolicy' },
      ErrorModel: { Message: message, Object: 'error' },
    },
    400,
  )
}

export const enforceTwoFactor: TwoFactorHook = async (c, user, form) => {
  // API key sessions authenticate with the key alone, as the official clients expect.
  if (form.grant_type === 'client_credentials') return null
  const db = createDb(c.env.DB)
  const rows = await enabledProviders(db, user.uuid)
  if (rows.length === 0) return null

  const provider = Number.parseInt(form.twoFactorProvider ?? '', 10)
  const token = form.twoFactorToken
  if (!token || !Number.isFinite(provider)) {
    return challengeBody(c, user, rows, 'Two factor required.')
  }

  if (await overLimit(c, 'two-factor', user.uuid)) return tooManyRequests(c)

  if (provider === TwoFactorType.Remember) {
    if (await rememberValid(db, user.uuid, form.deviceIdentifier?.trim(), token)) return null
    return challengeBody(c, user, rows, 'Two factor required.')
  }

  const row = rows.find((r) => r.atype === provider)
  let ok = false
  if (row?.atype === TwoFactorType.Authenticator) {
    const data = parseData<{ key: string }>(row)
    const step = data ? await verifyTotp(data.key, token, clock.now(), row.lastUsed) : null
    if (step !== null) {
      const result = await db
        .update(schema.twofactor)
        .set({ lastUsed: step })
        .where(and(eq(schema.twofactor.uuid, row.uuid), lt(schema.twofactor.lastUsed, step)))
      ok = result.meta.changes > 0
    }
  } else if (row?.atype === TwoFactorType.Email) {
    ok = await consumeEmailCode(db, user, row, token)
  } else if (row?.atype === TwoFactorType.WebAuthn) {
    ok = await verifyWebAuthnLogin(c, db, user, row, token)
  }

  if (!ok) {
    return oauthError(
      c,
      'invalid_grant',
      'Two-step token is invalid. Try again.',
      'Two-step token is invalid. Try again.',
    )
  }
  c.set('twoFactorVerified', true)
  return null
}

export { generateTotpKey }
