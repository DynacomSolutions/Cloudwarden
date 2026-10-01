import { and, eq } from 'drizzle-orm'
import { Hono } from 'hono'
import { randomB64u, safeEqualStrings, sha256B64u } from '../auth/crypto'
import { verifyMasterPassword } from '../auth/passwords'
import {
  type DeviceInput,
  REFRESH_TOKEN_TTL_MS,
  registerDevice,
  tokenResponse,
} from '../auth/session'
import { enforceTwoFactor, issueRememberToken } from '../auth/twofactor'
import { findUserByEmail } from '../auth/users'
import { createDb, schema } from '../db'
import type { Env } from '../env'
import { oauthError } from '../errors'
import { rateLimit } from '../ratelimit'

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
  const ok = await verifyMasterPassword(user, form.password)
  if (!ok || !user) return BAD_LOGIN(c)
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

  const refreshToken = await registerDevice(db, user.uuid, device)
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

token.post('/identity/connect/token', rateLimit('token'), async (c) => {
  const body = await c.req.parseBody().catch(() => ({}))
  const form: Form = {}
  for (const [k, v] of Object.entries(body)) if (typeof v === 'string') form[k] = v

  switch (form.grant_type) {
    case 'password':
      return passwordGrant(c, form)
    case 'refresh_token':
      return refreshGrant(c, form)
    case 'client_credentials':
      return clientCredentialsGrant(c, form)
    default:
      return oauthError(
        c,
        'unsupported_grant_type',
        'unsupported_grant_type',
        'Unsupported grant type.',
      )
  }
})
