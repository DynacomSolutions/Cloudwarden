import { and, eq } from 'drizzle-orm'
import type { Context } from 'hono'
import type { Db } from '../db'
import { schema } from '../db'
import { createEmailTransport, newDeviceLoginEmail, otpEmail } from '../email'
import { later, sendNotice } from '../email/send'
import type { Env, User } from '../env'
import { oauthError } from '../errors'
import { consumeOtp, issueOtp, OTP_TTL_MS } from './otp'
import type { DeviceInput } from './session'

const TYPE_NAMES: Record<number, string> = {
  0: 'Android',
  1: 'iOS',
  2: 'Chrome extension',
  3: 'Firefox extension',
  4: 'Opera extension',
  5: 'Edge extension',
  6: 'Windows desktop',
  7: 'macOS desktop',
  8: 'Linux desktop',
  9: 'Chrome',
  10: 'Firefox',
  11: 'Opera',
  12: 'Edge',
  13: 'Internet Explorer',
  14: 'Web browser',
  15: 'Android (Amazon)',
  16: 'Windows app',
  17: 'Safari',
  18: 'Vivaldi',
  19: 'Vivaldi extension',
  20: 'Safari extension',
  21: 'SDK',
  22: 'Server',
  23: 'Windows CLI',
  24: 'macOS CLI',
  25: 'Linux CLI',
  26: 'DuckDuckGo',
  27: 'DuckDuckGo extension',
}
export const deviceTypeName = (type: number) => TYPE_NAMES[type] ?? 'Unknown device'

/** The message the official clients match to open the "enter your emailed code" step. */
export const NEW_DEVICE_REQUIRED = 'new device verification required'

export interface NewDeviceState {
  /** The login came from a device this account has not used before. */
  isNew: boolean
  /** The account already has at least one other device, so this is not its first login. */
  hasOthers: boolean
}

export async function newDeviceState(
  db: Db,
  userUuid: string,
  identifier: string,
): Promise<NewDeviceState> {
  const rows = await db
    .select({ identifier: schema.devices.identifier })
    .from(schema.devices)
    .where(eq(schema.devices.userUuid, userUuid))
  const known = rows.some((r) => r.identifier === identifier)
  return { isNew: !known, hasOthers: rows.some((r) => r.identifier !== identifier) }
}

/**
 * Email verification of unknown devices, before a session is issued. Applies only when the
 * account keeps it on, mail can be sent, this is not the account's first device and no second
 * factor already proves the person (callers skip accounts with two-step login).
 * Returns an error response to send, or null to continue.
 */
export async function requireNewDeviceCode(
  c: Context<Env>,
  db: Db,
  user: User,
  state: NewDeviceState,
  form: Record<string, string>,
) {
  if (!state.isNew || !state.hasOthers || !user.verifyDevices) return null
  if (!createEmailTransport(c.env).configured) return null
  const [factor] = await db
    .select({ uuid: schema.twofactor.uuid })
    .from(schema.twofactor)
    .where(and(eq(schema.twofactor.userUuid, user.uuid), eq(schema.twofactor.enabled, true)))
    .limit(1)
  if (factor) return null
  const code = form.newDeviceOtp?.trim()
  if (code) {
    if (await consumeOtp(db, user.uuid, 'new-device', code)) return null
    return oauthError(c, 'invalid_grant', 'invalid_new_device_otp', 'Invalid new device code.')
  }
  const issued = await issueOtp(db, user.uuid, 'new-device')
  if (!issued) {
    return oauthError(
      c,
      'invalid_grant',
      'too_many_verification_requests',
      'Too many verification attempts. Try again later.',
    )
  }
  const sent = await sendNotice(
    c.env,
    user.email,
    otpEmail('new-device', issued, OTP_TTL_MS / 60_000),
  )
  if (!sent) {
    // Failing closed would lock the owner out when mail is broken; say why instead.
    return oauthError(
      c,
      'invalid_grant',
      'new_device_verification_unavailable',
      'The verification email could not be sent. Try again later.',
    )
  }
  return oauthError(c, 'invalid_grant', NEW_DEVICE_REQUIRED, NEW_DEVICE_REQUIRED)
}

/** Tells the account owner about a login from a device they have not used before. */
export function announceNewDevice(c: Context<Env>, user: User, device: DeviceInput): void {
  later(
    c,
    sendNotice(
      c.env,
      user.email,
      newDeviceLoginEmail({
        deviceName: device.name,
        deviceType: deviceTypeName(device.type),
        ip: c.req.header('CF-Connecting-IP') ?? null,
        at: new Date(),
      }),
    ),
  )
}
