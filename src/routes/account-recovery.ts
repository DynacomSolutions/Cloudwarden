import { eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { holdsInstanceRole } from '../admin/security'
import { authenticationData, checkNested, unlockData } from '../auth/credentials'
import { hashMasterPassword, verifyMasterPassword } from '../auth/passwords'
import { stampRotationStatements } from '../auth/session'
import { createDb, type Db, schema } from '../db'
import { createEmailTransport, genericEmail } from '../email'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { isStandInUser } from '../federation/standin'
import { pushLogOut } from '../notifications/publish'
import { getMember, requireOrg } from '../orgs/access'
import { EventType, Status } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { getTarget } from '../orgs/members'
import { defer } from '../orgs/notify'
import {
  assertCanRecover,
  assertNotUnrecoverable,
  assertOrgKeys,
  assertPolicyEnabled,
  assertRecoverable,
  enrolledMembers,
  hasMasterPassword,
  recoveryDetailsJson,
  requireRecoveryAdmin,
  resetPasswordPolicy,
  unrecoverableMembers,
} from '../orgs/recovery'
import { authOnce, batch } from '../orgs/util'
import { overLimit, rateLimit, tooManyRequests } from '../ratelimit'
import { kdfProblem, parseBody } from '../validation'

/**
 * Account recovery (admin password reset), TASKS #240. Mounted before `orgUsers` so the static
 * `users/account-recovery-details` path is not taken for a member id.
 */
export const accountRecovery = new Hono<Env>()
accountRecovery.use('/api/organizations/*', authOnce)

type Ctx = Context<Env>
const org = (c: Ctx) => c.req.param('orgId') ?? ''

/** An encrypted key as the clients send it (`<type>.<base64 parts>`); never interpreted here. */
const encString = z
  .string()
  .max(10_000)
  .regex(/^\d+\.[A-Za-z0-9+/=|_-]+$/, 'Invalid encrypted key.')

// ----- member enrolment -----

const enrollmentSchema = z.object({
  resetPasswordKey: z.union([encString, z.literal('')]).nullish(),
  masterPasswordHash: z.string().nullish(),
  otp: z.string().nullish(),
})

accountRecovery.put(
  '/api/organizations/:orgId/users/:userId/reset-password-enrollment',
  async (c) => {
    const orgUuid = org(c)
    const user = c.var.user
    // The path names the account (user id); only that account may change its own enrolment.
    if (c.req.param('userId') !== user.uuid) throw new ApiError(404, 'User not found.')
    const body = await parseBody(c, enrollmentSchema)
    const db = createDb(c.env.DB)
    const member = await getMember(db, user.uuid, orgUuid)
    if (!member || (member.status !== Status.Accepted && member.status !== Status.Confirmed)) {
      throw new ApiError(404, 'User not found.')
    }
    const policy = await resetPasswordPolicy(db, orgUuid)
    const key = body.resetPasswordKey || null
    if (key) {
      // Federated members keep their credentials on the home instance: no recovery key here.
      const [federated] = await db
        .select({ id: schema.federationMembers.organizationUserUuid })
        .from(schema.federationMembers)
        .where(eq(schema.federationMembers.organizationUserUuid, member.uuid))
        .limit(1)
      if (federated || isStandInUser(user)) {
        throw new ApiError(400, 'Federated members cannot enrol in account recovery.')
      }
      if (!policy.enabled) {
        throw new ApiError(400, 'Organization does not have the account recovery policy enabled.')
      }
      assertOrgKeys(await requireOrg(db, orgUuid))
      // Enrolling hands the organisation a way into the vault, so it needs the master password.
      // Accounts without one (trusted device encryption) are enrolled by their client on first login.
      if (hasMasterPassword(user) && (await overLimit(c, 'recovery-enroll', user.uuid))) {
        return tooManyRequests(c)
      }
      if (
        hasMasterPassword(user) &&
        !(await verifyMasterPassword(user, body.masterPasswordHash ?? ''))
      ) {
        throw new ApiError(400, 'Invalid password.', { masterPasswordHash: ['Invalid password.'] })
      }
    } else if (policy.autoEnrollEnabled) {
      throw new ApiError(
        400,
        'Due to an organization policy, you are not allowed to withdraw from account recovery.',
      )
    }
    const now = Date.now()
    await batch(db, [
      db
        .update(schema.usersOrganizations)
        .set({ resetPasswordKey: key, updatedAt: now })
        .where(eq(schema.usersOrganizations.uuid, member.uuid)),
      eventStatement(db, c, {
        type: key
          ? EventType.OrganizationUserResetPasswordEnroll
          : EventType.OrganizationUserResetPasswordWithdraw,
        organizationUuid: orgUuid,
        organizationUserUuid: member.uuid,
        userUuid: user.uuid,
      }),
      db.update(schema.users).set({ updatedAt: now }).where(eq(schema.users.uuid, user.uuid)),
    ])
    return c.body(null, 200)
  },
)

// ----- administrator: recovery details -----

async function loadTarget(c: Ctx, db: Db, id: string) {
  const orgUuid = org(c)
  const actor = await requireRecoveryAdmin(db, c.var.user.uuid, orgUuid)
  await assertPolicyEnabled(db, orgUuid)
  const orgRow = await requireOrg(db, orgUuid)
  assertOrgKeys(orgRow)
  const target = await getTarget(db, orgUuid, id)
  assertCanRecover(actor, target)
  assertRecoverable(target)
  const [u] = await db.select().from(schema.users).where(eq(schema.users.uuid, target.userUuid))
  if (!u) throw new ApiError(404, 'User not found.')
  await assertNotUnrecoverable(db, target, u)
  // Instance admins and owners are never recoverable by an organisation admin.
  if (holdsInstanceRole(c.env, u)) {
    throw new ApiError(400, 'This member cannot be recovered.')
  }
  return { actor, orgRow, target, user: u }
}

accountRecovery.get(
  '/api/organizations/:orgId/users/:id/reset-password-details',
  rateLimit('org-recovery', 30),
  async (c) => {
    const db = createDb(c.env.DB)
    const { orgRow, target, user } = await loadTarget(c, db, c.req.param('id'))
    return c.json(recoveryDetailsJson(target, user, orgRow))
  },
)

accountRecovery.post(
  '/api/organizations/:orgId/users/account-recovery-details',
  rateLimit('org-recovery', 30),
  async (c) => {
    const { ids } = await parseBody(c, z.object({ ids: z.array(z.string()).max(500).default([]) }))
    const db = createDb(c.env.DB)
    const orgUuid = org(c)
    const actor = await requireRecoveryAdmin(db, c.var.user.uuid, orgUuid)
    await assertPolicyEnabled(db, orgUuid)
    const orgRow = await requireOrg(db, orgUuid)
    assertOrgKeys(orgRow)
    const rows = await enrolledMembers(db, orgUuid, [...new Set(ids)])
    const blocked = await unrecoverableMembers(db, rows)
    const data = rows.flatMap(({ m, u }) => {
      try {
        assertCanRecover(actor, m)
        assertRecoverable(m)
        if (blocked.has(m.uuid)) return []
        return [recoveryDetailsJson(m, u, orgRow)]
      } catch {
        return []
      }
    })
    return c.json({ object: 'list', data, continuationToken: null })
  },
)

// ----- administrator: reset -----

const legacyReset = z.object({
  newMasterPasswordHash: z.string().min(1),
  key: encString,
})
const recoverSchema = z.object({
  resetMasterPassword: z.boolean().nullish(),
  resetTwoFactor: z.boolean().nullish(),
  authenticationData: authenticationData.nullish(),
  unlockData: unlockData.nullish(),
  // Older clients send the flat shape on this path too.
  newMasterPasswordHash: z.string().min(1).nullish(),
  key: encString.nullish(),
})

interface NewPassword {
  hash: string
  key: string
  kdf: ReturnType<typeof checkNested> | null
}

type UserRow = typeof schema.users.$inferSelect

/**
 * Applies a recovery once the caller is authorised for the target. `newPassword` builds the new
 * credentials from the target account (null when only two-step login is reset).
 */
async function recover(
  c: Ctx,
  newPassword: (user: UserRow) => NewPassword | null,
  resetTwoFactor: boolean,
): Promise<Response> {
  const db = createDb(c.env.DB)
  const { orgRow, target, user } = await loadTarget(c, db, c.req.param('id') ?? '')
  const password = newPassword(user)
  if (!password && !resetTwoFactor) {
    throw new ApiError(400, 'Choose what to recover: the master password, two-step login or both.')
  }
  if (password && !hasMasterPassword(user)) {
    throw new ApiError(400, 'This account has no master password to reset.')
  }
  if (password?.kdf) {
    const problem = kdfProblem(password.kdf)
    if (problem) throw new ApiError(400, problem)
  }
  const base = {
    organizationUuid: orgRow.uuid,
    organizationUserUuid: target.uuid,
    userUuid: user.uuid,
  }
  await batch(db, [
    ...(password
      ? [
          db
            .update(schema.users)
            .set({
              ...(await hashMasterPassword(password.hash)),
              akey: password.key,
              passwordHint: null,
              forcePasswordReset: true,
              // Defence in depth: loadTarget already refuses instance admins.
              instanceRole: 'user',
              ...(password.kdf
                ? {
                    kdfType: password.kdf.kdf,
                    kdfIterations: password.kdf.kdfIterations,
                    kdfMemory: password.kdf.kdf === 1 ? (password.kdf.kdfMemory ?? null) : null,
                    kdfParallelism:
                      password.kdf.kdf === 1 ? (password.kdf.kdfParallelism ?? null) : null,
                  }
                : {}),
            })
            .where(eq(schema.users.uuid, user.uuid)),
          eventStatement(db, c, { type: EventType.OrganizationUserAdminResetPassword, ...base }),
        ]
      : []),
    ...(resetTwoFactor && !password
      ? [
          db
            .update(schema.users)
            .set({ instanceRole: 'user' })
            .where(eq(schema.users.uuid, user.uuid)),
        ]
      : []),
    ...(resetTwoFactor
      ? [
          db.delete(schema.twofactor).where(eq(schema.twofactor.userUuid, user.uuid)),
          db
            .update(schema.devices)
            .set({ twofactorRemember: null })
            .where(eq(schema.devices.userUuid, user.uuid)),
          eventStatement(db, c, { type: EventType.OrganizationUserAdminResetTwoFactor, ...base }),
        ]
      : []),
    // Requests made with the old credentials, answered or not, must not outlive the recovery.
    db.delete(schema.authRequests).where(eq(schema.authRequests.userUuid, user.uuid)),
    // Every session of the recovered account ends: its old credentials no longer apply.
    ...stampRotationStatements(db, user.uuid),
  ])
  defer(
    c,
    Promise.all([
      pushLogOut(c.env, user.uuid, null),
      notifyRecovered(c, user.email, orgRow.name, password !== null, resetTwoFactor),
    ]),
  )
  return c.body(null, 200)
}

async function notifyRecovered(
  c: Ctx,
  email: string,
  orgName: string,
  password: boolean,
  twoFactor: boolean,
) {
  const transport = createEmailTransport(c.env)
  if (!transport.configured) return
  const what = [password ? 'master password' : null, twoFactor ? 'two-step login' : null]
    .filter(Boolean)
    .join(' and ')
  const lines = [
    `An administrator of the organization ${orgName} recovered your account and reset your ${what}.`,
    ...(password
      ? [
          'Sign in with the temporary password the administrator gives you. You will then be asked to choose a new master password.',
        ]
      : []),
    'If you did not expect this, contact your organization administrator.',
  ]
  try {
    await transport.send({ to: email, ...genericEmail('Your account was recovered', lines) })
  } catch {
    // The reset is stored; the notice is best effort. Message content is never logged.
  }
}

accountRecovery.put(
  '/api/organizations/:orgId/users/:id/reset-password',
  rateLimit('org-recovery', 30),
  async (c) => {
    const body = await parseBody(c, legacyReset)
    return recover(c, () => ({ hash: body.newMasterPasswordHash, key: body.key, kdf: null }), false)
  },
)

accountRecovery.put(
  '/api/organizations/:orgId/users/:id/recover-account',
  rateLimit('org-recovery', 30),
  async (c) => {
    const body = await parseBody(c, recoverSchema)
    const auth = body.authenticationData
    const unlock = body.unlockData
    return recover(
      c,
      (user) => {
        if (body.resetMasterPassword === false) return null
        if (auth && unlock) {
          if (!encString.safeParse(unlock.masterKeyWrappedUserKey).success) {
            throw new ApiError(400, 'Invalid encrypted key.')
          }
          return {
            hash: auth.masterPasswordAuthenticationHash,
            key: unlock.masterKeyWrappedUserKey,
            // The salt must be the target's email, as for a password change.
            kdf: checkNested(auth, unlock, user.email),
          }
        }
        if (body.newMasterPasswordHash && body.key) {
          return { hash: body.newMasterPasswordHash, key: body.key, kdf: null }
        }
        if (body.resetMasterPassword === true) {
          throw new ApiError(400, 'The new master password is required.')
        }
        return null
      },
      body.resetTwoFactor === true,
    )
  },
)
