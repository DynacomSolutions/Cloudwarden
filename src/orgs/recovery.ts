import { and, eq, inArray, isNotNull } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import { ApiError } from '../errors'
import { can, type Member, requireMember } from './access'
import { PolicyType, Role, Status } from './constants'
import { parseData } from './policies'

/**
 * Account recovery (admin password reset, TASKS #240). A member enrols by wrapping their user key
 * with the organisation public key (`resetPasswordKey`). An administrator holding
 * `manageResetPassword` unwraps it client side with the organisation private key, which the
 * server only ever stores encrypted with the organisation key. The server never sees a plain key.
 */

/** Statuses whose members can be recovered: the same set the official Admin Console offers. */
export const RECOVERABLE_STATUSES: number[] = [Status.Accepted, Status.Confirmed, Status.Revoked]

export interface ResetPasswordPolicy {
  enabled: boolean
  autoEnrollEnabled: boolean
}

export async function resetPasswordPolicy(db: Db, orgUuid: string): Promise<ResetPasswordPolicy> {
  const [p] = await db
    .select()
    .from(schema.policies)
    .where(
      and(
        eq(schema.policies.organizationUuid, orgUuid),
        eq(schema.policies.atype, PolicyType.ResetPassword),
      ),
    )
    .limit(1)
  const enabled = p?.enabled === true
  return { enabled, autoEnrollEnabled: enabled && parseData(p.data)?.autoEnrollEnabled === true }
}

export async function assertPolicyEnabled(db: Db, orgUuid: string) {
  if (!(await resetPasswordPolicy(db, orgUuid)).enabled) {
    throw new ApiError(400, 'Organization does not have the account recovery policy enabled.')
  }
}

/**
 * The calling administrator for a recovery action on `target`: a confirmed member with
 * `manageResetPassword` who outranks the target (owners recover anyone, admins anyone but owners,
 * custom members only users). Nobody recovers their own account here.
 */
export async function requireRecoveryAdmin(
  db: Db,
  userUuid: string,
  orgUuid: string,
): Promise<Member> {
  const actor = await requireMember(db, userUuid, orgUuid)
  if (!can(actor, 'manageResetPassword')) {
    throw new ApiError(403, 'You do not have permission to do this.')
  }
  return actor
}

export function assertCanRecover(actor: Member, target: Member) {
  const outranks =
    actor.atype === Role.Owner ||
    (actor.atype === Role.Admin && target.atype !== Role.Owner) ||
    (actor.atype === Role.Custom && target.atype !== Role.Owner && target.atype !== Role.Admin)
  if (!outranks) throw new ApiError(403, 'You do not have permission to manage this member.')
  if (target.uuid === actor.uuid || (target.userUuid && target.userUuid === actor.userUuid)) {
    throw new ApiError(400, 'You cannot recover your own account.')
  }
}

/** A target that is enrolled, linked to an account and in a recoverable status. */
export function assertRecoverable(target: Member): asserts target is Member & {
  userUuid: string
  resetPasswordKey: string
} {
  if (!target.userUuid || !RECOVERABLE_STATUSES.includes(target.status)) {
    throw new ApiError(400, 'This member cannot be recovered.')
  }
  if (!target.resetPasswordKey) {
    throw new ApiError(400, 'This member is not enrolled in account recovery.')
  }
}

type OrgRow = typeof schema.organizations.$inferSelect
type UserRow = typeof schema.users.$inferSelect

export function assertOrgKeys(org: OrgRow): asserts org is OrgRow & { privateKey: string } {
  if (!org.publicKey || !org.privateKey) {
    throw new ApiError(400, 'Organization does not have encryption keys.')
  }
}

/** `organizationUserResetPasswordDetails`: what the admin client needs to rewrap the user key. */
export const recoveryDetailsJson = (
  m: Member & { resetPasswordKey: string },
  u: UserRow,
  org: OrgRow & { privateKey: string },
) => ({
  object: 'organizationUserResetPasswordDetails',
  organizationUserId: m.uuid,
  kdf: u.kdfType,
  kdfIterations: u.kdfIterations,
  kdfMemory: u.kdfMemory,
  kdfParallelism: u.kdfParallelism,
  masterPasswordSalt: u.email,
  resetPasswordKey: m.resetPasswordKey,
  // The organisation private key, still encrypted with the organisation symmetric key.
  encryptedPrivateKey: org.privateKey,
})

/** Members of `orgUuid` enrolled in account recovery, joined to their accounts. */
export async function enrolledMembers(db: Db, orgUuid: string, ids: string[]) {
  if (ids.length === 0) return []
  return db
    .select({ m: schema.usersOrganizations, u: schema.users })
    .from(schema.usersOrganizations)
    .innerJoin(schema.users, eq(schema.users.uuid, schema.usersOrganizations.userUuid))
    .where(
      and(
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
        inArray(schema.usersOrganizations.uuid, ids),
        isNotNull(schema.usersOrganizations.resetPasswordKey),
      ),
    )
}

/** True when the account has a master password (TDE accounts created by SSO may not). */
export { hasMasterPassword } from '../sso/decryption'
