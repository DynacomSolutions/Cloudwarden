import { and, eq, inArray, ne } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import type { User } from '../env'
import { can } from '../orgs/access'
import { PolicyType, Status } from '../orgs/constants'
import { MemberDecryptionType, parseConfigData } from './config'

/**
 * `UserDecryptionOptions` of the token response (TASKS #284, #285): which ways the client may
 * unlock. Key names and casing follow what the official clients check literally
 * (`TrustedDeviceOption`, `KeyConnectorOption`, `EncryptedPrivateKey`, `EncryptedUserKey`).
 */

/** Device types that can approve a login: mobile, desktop, browser extensions and web vaults. */
const NON_APPROVING_TYPES = [21, 22, 23, 24, 25]

export const hasMasterPassword = (user: Pick<User, 'passwordHash'>) => user.passwordHash !== ''

type DeviceRow = typeof schema.devices.$inferSelect

export const isTrustedDevice = (
  d: Pick<DeviceRow, 'encryptedUserKey' | 'encryptedPublicKey' | 'encryptedPrivateKey'>,
) => Boolean(d.encryptedUserKey && d.encryptedPublicKey && d.encryptedPrivateKey)

/**
 * The organisation whose SSO settings govern the user's decryption: the one named by the login
 * (SSO), else the first organisation the user is linked to by SSO whose configuration is enabled.
 */
async function governingSso(db: Db, user: User, ssoOrgUuid: string | undefined) {
  const orgIds = ssoOrgUuid
    ? [ssoOrgUuid]
    : (
        await db
          .select({ org: schema.ssoUsers.organizationUuid })
          .from(schema.ssoUsers)
          .where(eq(schema.ssoUsers.userUuid, user.uuid))
      ).map((r) => r.org)
  if (orgIds.length === 0) return null
  const rows = await db
    .select({ cfg: schema.ssoConfigs, m: schema.usersOrganizations })
    .from(schema.ssoConfigs)
    .innerJoin(
      schema.usersOrganizations,
      and(
        eq(schema.usersOrganizations.organizationUuid, schema.ssoConfigs.organizationUuid),
        eq(schema.usersOrganizations.userUuid, user.uuid),
      ),
    )
    .where(
      and(
        inArray(schema.ssoConfigs.organizationUuid, orgIds),
        eq(schema.ssoConfigs.enabled, true),
        ne(schema.usersOrganizations.status, Status.Revoked),
      ),
    )
  const row = ssoOrgUuid ? rows[0] : rows.find(Boolean)
  if (!row) return null
  return { member: row.m, data: parseConfigData(row.cfg) }
}

/** The key connector URL for a key connector user: the organisation configured for it. */
export async function keyConnectorUrlFor(db: Db, userUuid: string): Promise<string | null> {
  const rows = await db
    .select({ cfg: schema.ssoConfigs })
    .from(schema.ssoConfigs)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.organizationUuid, schema.ssoConfigs.organizationUuid),
    )
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, userUuid),
        eq(schema.ssoConfigs.enabled, true),
        ne(schema.usersOrganizations.status, Status.Revoked),
      ),
    )
  for (const { cfg } of rows) {
    const data = parseConfigData(cfg)
    if (data.memberDecryptionType === MemberDecryptionType.KeyConnector && data.keyConnectorUrl) {
      return data.keyConnectorUrl
    }
  }
  return null
}

export interface DecryptionContext {
  deviceIdentifier: string
  /** Organisation of an SSO login. */
  ssoOrgUuid?: string
}

export async function decryptionOptions(db: Db, user: User, ctx: DecryptionContext) {
  const out: Record<string, unknown> = {}
  const mp = hasMasterPassword(user)

  if (user.usesKeyConnector) {
    const url = await keyConnectorUrlFor(db, user.uuid)
    if (url) out.KeyConnectorOption = { KeyConnectorUrl: url }
  }

  const sso = await governingSso(db, user, ctx.ssoOrgUuid)
  if (!sso) return out
  const type = sso.data.memberDecryptionType ?? MemberDecryptionType.MasterPassword

  if (
    type === MemberDecryptionType.KeyConnector &&
    !mp &&
    !out.KeyConnectorOption &&
    sso.data.keyConnectorUrl
  ) {
    // A new member of a key connector organisation: the client enrols with the key connector.
    out.KeyConnectorOption = { KeyConnectorUrl: sso.data.keyConnectorUrl }
  }

  // Trusted devices, or offboarding from them: a member without a master password whose
  // organisation stopped using trusted devices still unlocks on trusted devices until they set one.
  const offboarding =
    type !== MemberDecryptionType.TrustedDeviceEncryption &&
    ctx.ssoOrgUuid !== undefined &&
    !mp &&
    // Only members who already unlocked with trusted devices (they have account keys).
    user.privateKey !== null &&
    !user.usesKeyConnector &&
    type !== MemberDecryptionType.KeyConnector
  if (type === MemberDecryptionType.TrustedDeviceEncryption || offboarding) {
    const devices = await db
      .select()
      .from(schema.devices)
      .where(eq(schema.devices.userUuid, user.uuid))
    const current = devices.find((d) => d.identifier === ctx.deviceIdentifier)
    const approving = devices.some(
      (d) =>
        d.identifier !== ctx.deviceIdentifier &&
        d.refreshToken !== '' &&
        !NON_APPROVING_TYPES.includes(d.type),
    )
    // Admin approval needs an enrolment and the recovery policy still enabled for the organisation.
    const [recovery] =
      sso.member.resetPasswordKey !== null
        ? await db
            .select({ enabled: schema.policies.enabled })
            .from(schema.policies)
            .where(
              and(
                eq(schema.policies.organizationUuid, sso.member.organizationUuid),
                eq(schema.policies.atype, PolicyType.ResetPassword),
              ),
            )
            .limit(1)
        : []
    out.TrustedDeviceOption = {
      HasAdminApproval: sso.member.resetPasswordKey !== null && recovery?.enabled === true,
      HasLoginApprovingDevice: approving,
      HasManageResetPasswordPermission: can(sso.member, 'manageResetPassword'),
      IsTdeOffboarding: offboarding,
      ...(current && isTrustedDevice(current)
        ? {
            EncryptedPrivateKey: current.encryptedPrivateKey,
            EncryptedUserKey: current.encryptedUserKey,
          }
        : {}),
    }
  }
  return out
}
