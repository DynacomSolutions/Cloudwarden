import { and, eq, isNull } from 'drizzle-orm'
import { Hono } from 'hono'
import { randomB64u, safeEqualStrings, sha256B64u } from '../auth/crypto'
import { announceNewDevice, newDeviceState, requireNewDeviceCode } from '../auth/new-device'
import {
  assertionCredentialId,
  PASSKEY_LOGIN,
  prfOptionJson,
  spendAssertion,
  verifyPasskeyAssertion,
} from '../auth/passkeys'
import { verifyMasterPassword } from '../auth/passwords'
import {
  type DeviceInput,
  REFRESH_TOKEN_TTL_MS,
  registerDevice,
  tokenResponse,
} from '../auth/session'
import { enforceTwoFactor, issueRememberToken } from '../auth/twofactor'
import { findUserByEmail } from '../auth/users'
import { WebAuthnError } from '../auth/webauthn'
import { createDb, schema } from '../db'
import type { Env, User } from '../env'
import { oauthError, sendAccessError } from '../errors'
import { organizationLoginGrant } from '../orgs/api-keys'
import { rateLimit, tooManyRequests } from '../ratelimit'
import { MACHINE_SCOPE, machineLoginGrant } from '../sm/auth'
import { consumeCode, findRedeemableCode } from '../sso/flow'
import { requiredSsoIdentifier } from '../sso/policy'
import {
  checkSendPassword,
  requestSendCode,
  SEND_TOKEN_TTL_SECONDS,
  signSendAccessToken,
  verifySendCode,
} from '../vault/send-access'
import {
  authTypeOf,
  normaliseEmail,
  SEND_AUTH_EMAIL,
  SEND_AUTH_PASSWORD,
  sendUuidFrom,
  unavailable,
} from '../vault/sends'
import { AUTH_REQUEST_TTL_MS } from './auth-requests'

export const token = new Hono<Env>()

type Ctx = import('hono').Context<Env>
type Form = Record<string, string>

const BAD_LOGIN = (c: Ctx) =>
  oauthError(
    c,
    'invalid_grant',
    'invalid_username_or_password',
    'Username or password is incorrect. Try again.',
  )

function deviceFrom(form: Form): DeviceInput | null {
  const identifier = form.deviceIdentifier?.trim()
  if (!identifier) return null
  const type = Number.parseInt(form.deviceType ?? '', 10)
  return {
    identifier,
    name: form.deviceName?.trim() || 'Unknown device',
    type: Number.isFinite(type) ? type : 14,
  }
}

type AuthRequestRow = typeof schema.authRequests.$inferSelect

/**
 * Finds an approved login-with-device request that this device may redeem: a type 0
 * request owned by the user, bound to the requesting device, unexpired, unused, with the
 * right access code. Does not consume it; see `consumeAuthRequest`.
 */
async function findRedeemableAuthRequest(
  db: ReturnType<typeof createDb>,
  user: User | null,
  requestId: string,
  accessCode: string,
  deviceIdentifier: string,
): Promise<AuthRequestRow | null> {
  if (!user) return null
  const [row] = await db
    .select()
    .from(schema.authRequests)
    .where(
      and(eq(schema.authRequests.uuid, requestId), eq(schema.authRequests.userUuid, user.uuid)),
    )
    .limit(1)
  if (!row) return null
  if (
    row.type !== 0 ||
    row.approved !== true ||
    row.authenticatedAt !== null ||
    Date.now() - row.createdAt >= AUTH_REQUEST_TTL_MS ||
    row.requestDeviceIdentifier !== deviceIdentifier ||
    !safeEqualStrings(row.accessCodeHash, await sha256B64u(accessCode))
  ) {
    return null
  }
  return row
}

/** Marks the request used. Atomic: only one concurrent redemption wins. */
async function consumeAuthRequest(db: ReturnType<typeof createDb>, uuid: string) {
  const result = await db
    .update(schema.authRequests)
    .set({ authenticatedAt: Date.now() })
    .where(and(eq(schema.authRequests.uuid, uuid), isNull(schema.authRequests.authenticatedAt)))
  return result.meta.changes > 0
}

/** 400 the clients turn into a redirect to SSO with the organisation identifier. */
const ssoRequired = (c: Ctx, identifier: string) =>
  c.json(
    {
      error: 'invalid_grant',
      error_description: 'sso_required',
      ErrorModel: { Message: 'SSO authentication is required.', Object: 'error' },
      SsoOrganizationIdentifier: identifier,
    },
    400,
  )

async function passwordGrant(c: Ctx, form: Form) {
  const db = createDb(c.env.DB)
  if (!form.username || !form.password) {
    return oauthError(
      c,
      'invalid_grant',
      'invalid_username_or_password',
      'Username and password are required.',
    )
  }
  const device = deviceFrom(form)
  if (!device) return oauthError(c, 'invalid_request', 'Device information is required.')

  const user = await findUserByEmail(db, form.username)
  // Login with device: the "password" is the request's access code, approved on another device.
  const authRequest = form.authRequest
    ? await findRedeemableAuthRequest(db, user, form.authRequest, form.password, device.identifier)
    : null
  const ok = form.authRequest
    ? authRequest !== null
    : await verifyMasterPassword(user, form.password)
  if (!ok || !user) return BAD_LOGIN(c)
  if (!user.enabled) {
    return oauthError(
      c,
      'invalid_grant',
      'this account has been disabled',
      'This account has been disabled.',
    )
  }

  // "Require single sign-on" policy (TASKS #283): members must sign in through their identity
  // provider. Login with a device approval is not a master password login and stays allowed.
  if (!authRequest) {
    const identifier = await requiredSsoIdentifier(db, user.uuid)
    if (identifier) return ssoRequired(c, identifier)
  }
  // A device approved from another device needs no emailed code.
  const state = await newDeviceState(db, user.uuid, device.identifier)
  const verify = authRequest ? null : await requireNewDeviceCode(c, db, user, state, form)
  if (verify) return verify

  const challenge = await enforceTwoFactor(c, user, form)
  if (challenge) return challenge

  // Spend the approval only now that every check has passed, right before issuing tokens.
  if (authRequest && !(await consumeAuthRequest(db, authRequest.uuid))) return BAD_LOGIN(c)

  const refreshToken = await registerDevice(db, user.uuid, device)
  if (state.isNew && state.hasOthers && !form.newDeviceOtp) announceNewDevice(c, user, device)
  const body = await tokenResponse(c.env, user, {
    deviceIdentifier: device.identifier,
    scope: ['api', 'offline_access'],
    refreshToken,
    clientId: form.client_id,
  })
  if (c.var.twoFactorVerified && form.twoFactorRemember === '1') {
    const TwoFactorToken = await issueRememberToken(db, user.uuid, device.identifier)
    return c.json({ ...body, TwoFactorToken })
  }
  return c.json(body)
}

/**
 * `webauthn` grant: passkey login. The assertion (user verified) is both factors, so no second
 * step follows. When the credential holds a PRF keyset it is returned for unlocking.
 */
async function webauthnGrant(c: Ctx, form: Form) {
  const db = createDb(c.env.DB)
  const bad = () => oauthError(c, 'invalid_grant', 'Passkey could not be verified.')
  const device = deviceFrom(form)
  if (!device) return oauthError(c, 'invalid_request', 'Device information is required.')
  let deviceResponse: unknown
  try {
    deviceResponse = JSON.parse(form.deviceResponse ?? '')
  } catch {
    return bad()
  }
  if (!form.token) return bad()
  const [credential] = await db
    .select()
    .from(schema.webauthnCredentials)
    .where(eq(schema.webauthnCredentials.credentialId, assertionCredentialId(deviceResponse)))
    .limit(1)
  if (!credential) return bad()
  let verified: Awaited<ReturnType<typeof verifyPasskeyAssertion>>
  try {
    verified = await verifyPasskeyAssertion(c.env, {
      purpose: PASSKEY_LOGIN,
      subject: 'anonymous',
      token: form.token,
      deviceResponse,
      credential,
    })
  } catch (err) {
    if (err instanceof WebAuthnError) return bad()
    throw err
  }
  const [user] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.uuid, credential.userUuid))
    .limit(1)
  if (!user) return bad()
  if (!user.enabled) {
    return oauthError(
      c,
      'invalid_grant',
      'this account has been disabled',
      'This account has been disabled.',
    )
  }
  const identifier = await requiredSsoIdentifier(db, user.uuid)
  if (identifier) return ssoRequired(c, identifier)
  // Spend the challenge only now: a replayed response finds it used and fails here.
  if (!(await spendAssertion(db, verified))) return bad()

  const refreshToken = await registerDevice(db, user.uuid, device)
  return c.json(
    await tokenResponse(c.env, user, {
      deviceIdentifier: device.identifier,
      scope: ['api', 'offline_access'],
      refreshToken,
      clientId: form.client_id,
      webAuthnPrf: prfOptionJson(credential),
    }),
  )
}

/**
 * `authorization_code` grant: the end of an SSO login (TASKS #280). The code is bound to the client,
 * its redirect URI and its PKCE challenge, and is spent only once every check (including two-step
 * login) has passed.
 */
async function authorizationCodeGrant(c: Ctx, form: Form) {
  const db = createDb(c.env.DB)
  const bad = () =>
    oauthError(c, 'invalid_grant', 'invalid_grant', 'The sign-in code is invalid or has expired.')
  const device = deviceFrom(form)
  if (!device) return oauthError(c, 'invalid_request', 'Device information is required.')
  const code = await findRedeemableCode(db, form)
  if (!code) return bad()
  const [user] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.uuid, code.userUuid))
    .limit(1)
  if (!user) return bad()
  if (!user.enabled) {
    return oauthError(
      c,
      'invalid_grant',
      'this account has been disabled',
      'This account has been disabled.',
    )
  }
  const challenge = await enforceTwoFactor(c, user, form)
  if (challenge) return challenge
  if (!(await consumeCode(db, code.codeHash))) return bad()

  const refreshToken = await registerDevice(db, user.uuid, device)
  const body = await tokenResponse(c.env, user, {
    deviceIdentifier: device.identifier,
    scope: ['api', 'offline_access'],
    refreshToken,
    clientId: form.client_id,
    ssoOrgUuid: code.organizationUuid,
  })
  if (c.var.twoFactorVerified && form.twoFactorRemember === '1') {
    const TwoFactorToken = await issueRememberToken(db, user.uuid, device.identifier)
    return c.json({ ...body, TwoFactorToken })
  }
  return c.json(body)
}

async function refreshGrant(c: Ctx, form: Form) {
  const db = createDb(c.env.DB)
  const invalid = () => oauthError(c, 'invalid_grant', 'invalid_grant', 'Invalid refresh token.')
  const raw = form.refresh_token ?? ''
  const dot = raw.indexOf('.')
  if (dot < 1) return invalid()
  const deviceUuid = raw.slice(0, dot)
  const hash = await sha256B64u(raw.slice(dot + 1))

  const [device] = await db
    .select()
    .from(schema.devices)
    .where(eq(schema.devices.uuid, deviceUuid))
    .limit(1)
  if (
    !device ||
    device.refreshToken === '' ||
    !safeEqualStrings(device.refreshToken, hash) ||
    Date.now() - device.updatedAt > REFRESH_TOKEN_TTL_MS
  ) {
    return invalid()
  }
  const [user] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.uuid, device.userUuid))
    .limit(1)
  if (!user?.enabled) return invalid()

  // Rotate the refresh token. The WHERE clause makes a replayed token lose the race.
  const next = randomB64u(32)
  const result = await db
    .update(schema.devices)
    .set({ refreshToken: await sha256B64u(next), updatedAt: Date.now() })
    .where(
      and(
        eq(schema.devices.uuid, device.uuid),
        eq(schema.devices.refreshToken, device.refreshToken),
      ),
    )
  if (result.meta.changes === 0) return invalid()

  return c.json(
    await tokenResponse(c.env, user, {
      deviceIdentifier: device.identifier,
      scope: ['api', 'offline_access'],
      refreshToken: `${device.uuid}.${next}`,
      clientId: form.client_id,
    }),
  )
}

async function clientCredentialsGrant(c: Ctx, form: Form) {
  const db = createDb(c.env.DB)
  const bad = () => oauthError(c, 'invalid_client', 'invalid_client', 'Invalid client credentials.')
  const clientId = form.client_id ?? ''
  if (!clientId.startsWith('user.') || !form.client_secret) return bad()
  const [user] = await db
    .select()
    .from(schema.users)
    .where(eq(schema.users.uuid, clientId.slice(5)))
    .limit(1)
  const matches = safeEqualStrings(user?.apiKey ?? '\0', form.client_secret)
  if (!user?.apiKey || !matches || !user.enabled) return bad()

  const challenge = await enforceTwoFactor(c, user, form)
  if (challenge) return challenge

  const device = deviceFrom(form) ?? { identifier: crypto.randomUUID(), name: 'API key', type: 14 }
  await registerDevice(db, user.uuid, device)
  // API key sessions get no refresh token: clients re-authenticate with the key.
  return c.json(
    await tokenResponse(c.env, user, {
      deviceIdentifier: device.identifier,
      scope: ['api'],
      clientId,
    }),
  )
}

/**
 * `send_access` grant: issues a short-lived token naming one Send once the recipient has met its
 * authentication: nothing, a password hash (`password_hash_b64`), or an emailed code (`email`
 * first, which mails the code, then `email` and `otp`). Errors carry `send_access_error_type`,
 * which the client SDK maps to the next step of the page.
 */
async function sendAccessGrant(c: Ctx, form: Form) {
  const db = createDb(c.env.DB)
  const uuid = sendUuidFrom(form.send_id ?? '')
  const [send] = uuid
    ? await db.select().from(schema.sends).where(eq(schema.sends.uuid, uuid)).limit(1)
    : []
  if (!send || unavailable(send, Date.now())) {
    return sendAccessError(c, 'invalid_grant', 'send_id_invalid', 'Send not found.')
  }
  const kind = authTypeOf(send)
  if (kind === SEND_AUTH_PASSWORD) {
    const check = await checkSendPassword(send, form.password_hash_b64)
    if (check === 'required') {
      return sendAccessError(
        c,
        'invalid_request',
        'password_hash_b64_required',
        'Password required.',
      )
    }
    if (check === 'invalid') {
      return sendAccessError(c, 'invalid_grant', 'password_hash_b64_invalid', 'Invalid password.')
    }
  } else if (kind === SEND_AUTH_EMAIL) {
    const email = normaliseEmail(form.email ?? '')
    if (!email) return sendAccessError(c, 'invalid_request', 'email_required', 'Email required.')
    const otp = (form.otp ?? '').trim()
    const needCode = () =>
      sendAccessError(
        c,
        'invalid_request',
        'email_and_otp_required',
        'Email and verification code required.',
      )
    if (!otp) {
      if (!(await requestSendCode(c, db, send, email))) return tooManyRequests(c)
      return needCode()
    }
    if (!(await verifySendCode(c, db, send, email, otp))) return needCode()
  }
  return c.json({
    access_token: await signSendAccessToken(c.env, send),
    expires_in: SEND_TOKEN_TTL_SECONDS,
    token_type: 'Bearer',
    scope: 'api.send.access',
  })
}

token.post('/identity/connect/token', rateLimit('token'), async (c) => {
  const body = await c.req.parseBody().catch(() => ({}))
  const form: Form = {}
  for (const [k, v] of Object.entries(body)) if (typeof v === 'string') form[k] = v

  switch (form.grant_type) {
    case 'password':
      return passwordGrant(c, form)
    case 'webauthn':
      return webauthnGrant(c, form)
    case 'authorization_code':
      return authorizationCodeGrant(c, form)
    case 'refresh_token':
      return refreshGrant(c, form)
    case 'client_credentials':
      // Secrets Manager machine accounts log in with their access token (TASKS #220).
      if ((form.scope ?? '').split(' ').includes(MACHINE_SCOPE)) return machineLoginGrant(c, form)
      // Organisation API key: Public API and Directory Connector (TASKS #270).
      if ((form.client_id ?? '').startsWith('organization.')) return organizationLoginGrant(c, form)
      return clientCredentialsGrant(c, form)
    case 'send_access':
      return sendAccessGrant(c, form)
    default:
      return oauthError(
        c,
        'unsupported_grant_type',
        'unsupported_grant_type',
        'Unsupported grant type.',
      )
  }
})
