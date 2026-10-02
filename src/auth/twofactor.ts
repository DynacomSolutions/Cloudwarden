import { and, eq, inArray, isNull, lt, sql } from 'drizzle-orm'
import type { Context } from 'hono'
import type { Db } from '../db'
import { createDb, runBatch, schema } from '../db'
import { recoveryCodeUsedEmail } from '../email'
import { later, sendNotice } from '../email/send'
import type { Bindings, Env, User } from '../env'
import { ApiError, oauthError } from '../errors'
import { Status } from '../orgs/constants'
import { overLimit, tooManyRequests } from '../ratelimit'
import { randomB64u, safeEqualStrings, sha256B64u } from './crypto'
import { type DuoConfig, duoAuthUrl, duoVerifyCode } from './duo'
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
import {
  isLater,
  isOtp,
  type OtpPosition,
  publicIdOf,
  verifyOtp,
  type YubicoConfig,
} from './yubico'

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

/** Providers this server can verify. */
export const SUPPORTED_TYPES: number[] = [
  TwoFactorType.Authenticator,
  TwoFactorType.Email,
  TwoFactorType.Duo,
  TwoFactorType.YubiKey,
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
    {
      purpose: VERIFY_PURPOSE,
      sub: user.uuid,
      sstamp: user.securityStamp,
      nbf: now,
      exp: now + VERIFICATION_TOKEN_TTL_S,
    },
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
    const claims = await verifyJwt<{
      purpose?: string
      sub?: string
      sstamp?: string
      exp: number
    }>(proof.userVerificationToken, verificationSecrets(env), Math.floor(clock.now() / 1000))
    if (
      claims?.purpose === VERIFY_PURPOSE &&
      claims.sub === user.uuid &&
      safeEqualStrings(claims.sstamp ?? '', user.securityStamp)
    ) {
      return
    }
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

const attemptsOf = sql`coalesce(json_extract(${schema.twofactor.data}, '$.attempts'), 0)`

/**
 * Checks and consumes an emailed code. Every guess is counted first, atomically and only
 * while below the limit, so parallel guesses cannot exceed it. A match clears the hash in
 * one guarded update, so a code works once.
 */
export async function consumeEmailCode(
  db: Db,
  user: User,
  row: TwoFactorRow,
  code: string,
): Promise<boolean> {
  const counted = await db
    .update(schema.twofactor)
    .set({
      data: sql`json_set(${schema.twofactor.data}, '$.attempts', ${attemptsOf} + 1)`,
    })
    .where(
      and(eq(schema.twofactor.uuid, row.uuid), sql`${attemptsOf} < ${EMAIL_CODE_MAX_ATTEMPTS}`),
    )
  if (counted.meta.changes === 0) return false

  const [fresh] = await db
    .select()
    .from(schema.twofactor)
    .where(eq(schema.twofactor.uuid, row.uuid))
    .limit(1)
  const data = parseData<EmailData>(fresh)
  if (!data?.codeHash || !data.expiresAt || clock.now() > data.expiresAt) return false
  const supplied = await codeHash(user.uuid, code.trim())
  if (!safeEqualStrings(data.codeHash, supplied)) return false
  const used = await db
    .update(schema.twofactor)
    .set({ data: sql`json_set(${schema.twofactor.data}, '$.codeHash', null, '$.attempts', 0)` })
    .where(
      and(
        eq(schema.twofactor.uuid, row.uuid),
        sql`json_extract(${schema.twofactor.data}, '$.codeHash') = ${data.codeHash}`,
      ),
    )
  return used.meta.changes > 0
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
// Duo (user type 2, organisation type 6)
// ---------------------------------------------------------------------------

export type DuoData = DuoConfig

export const CHALLENGE_DUO = 'duo-login'

/** Connector page client names the web vault understands. */
const DUO_CLIENTS = new Set(['web', 'browser', 'desktop', 'mobile'])

/** Redirect target registered with Duo: the vault's connector page, told which client to hand off to. */
export function duoRedirectUri(c: Context<Env>): string {
  const name = (c.req.header('bitwarden-client-name') ?? '').toLowerCase()
  return `${originFor(c.env)}/duo-redirect-connector.html?client=${DUO_CLIENTS.has(name) ? name : 'web'}`
}

/** Challenge purpose: bound to the device the login came from, so a state cannot move devices. */
const duoPurpose = (device: string | undefined) => `${CHALLENGE_DUO}:${device ?? ''}`

async function duoParams(
  c: Context<Env>,
  user: User,
  cfg: DuoData | null,
  device: string | undefined,
) {
  if (!cfg) return { Host: null, AuthUrl: null }
  const state = await createChallenge(c.env, duoPurpose(device), user.uuid, clock.now())
  return {
    Host: cfg.host,
    AuthUrl: await duoAuthUrl(
      cfg,
      user.email,
      state,
      duoRedirectUri(c),
      Math.floor(clock.now() / 1000),
    ),
  }
}

/**
 * Spends a Duo state: the newest accepted state time is stored (on the user's Duo row, or on a
 * disabled ledger row for organisation Duo), so each state works once and older ones die.
 */
async function spendDuoState(db: Db, user: User, atype: number, ts: number): Promise<boolean> {
  await db
    .insert(schema.twofactor)
    .values({
      uuid: crypto.randomUUID(),
      userUuid: user.uuid,
      atype,
      enabled: false,
      data: '{}',
      lastUsed: 0,
    })
    .onConflictDoNothing()
  const result = await db
    .update(schema.twofactor)
    .set({ lastUsed: ts })
    .where(
      and(
        eq(schema.twofactor.userUuid, user.uuid),
        eq(schema.twofactor.atype, atype),
        lt(schema.twofactor.lastUsed, ts),
      ),
    )
  return result.meta.changes > 0
}

/** `configs` are tried in turn: a user in several organisations with Duo may satisfy any of them. */
async function verifyDuoLogin(
  c: Context<Env>,
  db: Db,
  user: User,
  atype: number,
  configs: DuoData[],
  token: string,
  device: string | undefined,
): Promise<boolean> {
  const sep = token.lastIndexOf('|')
  if (configs.length === 0 || sep < 1) return false
  const code = token.slice(0, sep)
  const state = token.slice(sep + 1)
  const ts = await checkChallenge(c.env, duoPurpose(device), user.uuid, state, clock.now())
  if (ts === null || !(await spendDuoState(db, user, atype, ts))) return false
  for (const cfg of configs) {
    const ok = await duoVerifyCode(
      cfg,
      code,
      user.email,
      duoRedirectUri(c),
      state,
      Math.floor(clock.now() / 1000),
    )
    if (ok) return true
  }
  return false
}

/**
 * Duo configurations of every organisation the user is a confirmed member of that enables Duo,
 * ordered by organisation id. The wire format has one entry per provider type, so the challenge
 * offers the first and verification accepts any of them.
 */
export async function organizationDuoRows(db: Db, user: User): Promise<TwoFactorRow[]> {
  const rows = await db
    .select({
      orgUuid: schema.organizationTwofactor.organizationUuid,
      data: schema.organizationTwofactor.data,
    })
    .from(schema.organizationTwofactor)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.organizationUuid, schema.organizationTwofactor.organizationUuid),
    )
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, user.uuid),
        eq(schema.usersOrganizations.status, Status.Confirmed),
        eq(schema.organizationTwofactor.atype, TwoFactorType.OrganizationDuo),
        eq(schema.organizationTwofactor.enabled, true),
      ),
    )
    .orderBy(schema.organizationTwofactor.organizationUuid)
  return rows.map((row) => ({
    uuid: row.orgUuid,
    userUuid: user.uuid,
    atype: TwoFactorType.OrganizationDuo,
    enabled: true,
    data: row.data,
    lastUsed: 0,
  }))
}

// ---------------------------------------------------------------------------
// YubiKey OTP (type 3)
// ---------------------------------------------------------------------------

export interface YubiKeyData {
  /** Twelve character public ids of the registered keys (at most five). */
  keys: string[]
  nfc: boolean
  /** Newest accepted OTP position per public id; anything not later is a replay. */
  last?: Record<string, OtpPosition>
}

export const MAX_YUBIKEYS = 5

export function yubicoConfig(env: Bindings): YubicoConfig | null {
  if (!env.YUBICO_CLIENT_ID || !env.YUBICO_SECRET_KEY) return null
  return {
    clientId: env.YUBICO_CLIENT_ID,
    secretKey: env.YUBICO_SECRET_KEY,
    server: env.YUBICO_SERVER?.startsWith('https://') ? env.YUBICO_SERVER : undefined,
  }
}

async function verifyYubiKeyLogin(
  env: Bindings,
  db: Db,
  row: TwoFactorRow,
  token: string,
): Promise<boolean> {
  const data = parseData<YubiKeyData>(row)
  const cfg = yubicoConfig(env)
  const otp = token.trim().toLowerCase()
  if (!data || !cfg || !isOtp(otp)) return false
  const id = publicIdOf(otp)
  if (!data.keys.includes(id)) return false
  const position = await verifyOtp(cfg, otp)
  // Anything not later than the newest accepted OTP of this key is a replay, even if the
  // validation service did not notice.
  if (!position || !isLater(position, data.last?.[id])) return false
  return swapData(db, row, { ...data, last: { ...data.last, [id]: position } })
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
// Recovery code use (shared by the recover endpoint and provider 8 at login)
// ---------------------------------------------------------------------------

const RECOVERY_FORMAT = /^[A-Z2-7]{32}$/

/** Upper-cases and strips spaces and hyphens. Returns null unless it looks like a code. */
export function normaliseRecoveryCode(input: string): string | null {
  const code = input.replace(/[\s-]/g, '').toUpperCase()
  return RECOVERY_FORMAT.test(code) ? code : null
}

/**
 * Spends the recovery code: removes every provider and remember token and rotates the code,
 * all guarded on the old code so it works once. Returns false if the code is not valid.
 */
export async function useRecoveryCode(db: Db, user: User, input: string): Promise<boolean> {
  const supplied = normaliseRecoveryCode(input)
  const stored = user.totpRecover
  if (!supplied || !stored || !safeEqualStrings(stored, supplied)) return false
  const next = generateRecoveryCode()
  const rotated = sql`exists (select 1 from users where uuid = ${user.uuid} and totp_recover = ${next})`
  await runBatch(db, [
    db
      .update(schema.users)
      .set({ totpRecover: next, updatedAt: Date.now() })
      .where(and(eq(schema.users.uuid, user.uuid), eq(schema.users.totpRecover, stored))),
    db.delete(schema.twofactor).where(and(eq(schema.twofactor.userUuid, user.uuid), rotated)),
    db
      .update(schema.devices)
      .set({ twofactorRemember: null })
      .where(and(eq(schema.devices.userUuid, user.uuid), rotated)),
  ])
  const [after] = await db
    .select({ code: schema.users.totpRecover })
    .from(schema.users)
    .where(eq(schema.users.uuid, user.uuid))
    .limit(1)
  return after?.code === next
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

async function challengeBody(
  c: Context<Env>,
  user: User,
  rows: TwoFactorRow[],
  message: string,
  device: string | undefined,
) {
  const types = [...new Set(rows.map((r) => r.atype))].sort((a, b) => a - b)
  const params: Record<string, unknown> = {}
  for (const row of rows) {
    if (row.atype === TwoFactorType.Email) {
      const data = parseData<EmailData>(row)
      params[String(row.atype)] = { Email: maskEmail(data?.email ?? user.email) }
    } else if (row.atype === TwoFactorType.WebAuthn) {
      const data = parseData<WebAuthnData>(row) ?? { credentials: [] }
      params[String(row.atype)] = await assertionOptions(c.env, user, data)
    } else if (row.atype === TwoFactorType.Duo || row.atype === TwoFactorType.OrganizationDuo) {
      params[String(row.atype)] = await duoParams(c, user, parseData<DuoData>(row), device)
    } else if (row.atype === TwoFactorType.YubiKey) {
      params[String(row.atype)] = { Nfc: parseData<YubiKeyData>(row)?.nfc ?? false }
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
  const all = await db
    .select()
    .from(schema.twofactor)
    .where(and(eq(schema.twofactor.userUuid, user.uuid), eq(schema.twofactor.enabled, true)))
  const orgDuo = await organizationDuoRows(db, user)
  if (all.length === 0 && orgDuo.length === 0) return null
  const rows = all.filter((r) => SUPPORTED_TYPES.includes(r.atype))
  const unsupported = all.length > rows.length
  if (orgDuo[0]) rows.push(orgDuo[0])

  const provider = Number.parseInt(form.twoFactorProvider ?? '', 10)
  const token = form.twoFactorToken
  if (unsupported && (!token || !Number.isFinite(provider))) {
    return oauthError(
      c,
      'invalid_grant',
      'A two-factor provider on this account is not supported by this server. Use your recovery code.',
    )
  }
  if (!token || !Number.isFinite(provider)) {
    return challengeBody(c, user, rows, 'Two factor required.', form.deviceIdentifier?.trim())
  }

  if (await overLimit(c, 'two-factor', user.uuid)) return tooManyRequests(c)

  // The recovery code is accepted as provider 8: it spends the code, then login continues.
  if (provider === TwoFactorType.RecoveryCode) {
    if (await useRecoveryCode(db, user, token)) {
      later(c, sendNotice(c.env, user.email, recoveryCodeUsedEmail()))
      return null
    }
    return oauthError(c, 'invalid_grant', 'Recovery code is incorrect. Try again.')
  }

  // Fail closed: a provider we cannot verify must never be skipped.
  if (unsupported) {
    return oauthError(
      c,
      'invalid_grant',
      'A two-factor provider on this account is not supported by this server. Use your recovery code.',
    )
  }

  if (provider === TwoFactorType.Remember) {
    if (await rememberValid(db, user.uuid, form.deviceIdentifier?.trim(), token)) return null
    return challengeBody(c, user, rows, 'Two factor required.', form.deviceIdentifier?.trim())
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
  } else if (row?.atype === TwoFactorType.Duo || row?.atype === TwoFactorType.OrganizationDuo) {
    const configs = (row.atype === TwoFactorType.Duo ? [row] : orgDuo)
      .map((r) => parseData<DuoData>(r))
      .filter((d): d is DuoData => d !== null)
    ok = await verifyDuoLogin(c, db, user, row.atype, configs, token, form.deviceIdentifier?.trim())
  } else if (row?.atype === TwoFactorType.YubiKey) {
    ok = await verifyYubiKeyLogin(c.env, db, row, token)
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
