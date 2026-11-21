import { and, eq, inArray, sql } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import { ApiError } from '../errors'
import { isAdminRole, type Member } from './access'
import { PolicyType, Role, Status } from './constants'

export type PolicyRow = typeof schema.policies.$inferSelect

export const parseData = (s: string | null): Record<string, unknown> | null => {
  if (!s) return null
  try {
    const v = JSON.parse(s)
    return v && typeof v === 'object' ? (v as Record<string, unknown>) : null
  } catch {
    return null
  }
}

export const policyJson = (p: PolicyRow) => ({
  id: p.uuid,
  organizationId: p.organizationUuid,
  type: p.atype,
  data: parseData(p.data),
  enabled: p.enabled,
  canToggleState: true,
  revisionDate: new Date(p.updatedAt).toISOString(),
  object: 'policy',
})

/** The shape of `GET policies/{type}` when no row exists yet: disabled, no data. */
export const emptyPolicyJson = (orgUuid: string, type: number) => ({
  organizationId: orgUuid,
  type,
  data: null,
  enabled: false,
  canToggleState: true,
  object: 'policy',
})

/** Enabled policies of organisations the user belongs to as an active member. */
export async function listUserPolicies(db: Db, userUuid: string): Promise<PolicyRow[]> {
  const rows = await db
    .select({ p: schema.policies, m: schema.usersOrganizations })
    .from(schema.policies)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.organizationUuid, schema.policies.organizationUuid),
    )
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, userUuid),
        inArray(schema.usersOrganizations.status, [Status.Accepted, Status.Confirmed]),
        eq(schema.policies.enabled, true),
      ),
    )
  return rows.map((r) => r.p)
}

/** Policies enforced on a member: owners and admins are exempt from the restrictive types. */
export async function enforcedPolicies(db: Db, userUuid: string, type: number) {
  const rows = await db
    .select({ p: schema.policies, m: schema.usersOrganizations })
    .from(schema.policies)
    .innerJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.organizationUuid, schema.policies.organizationUuid),
    )
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, userUuid),
        inArray(schema.usersOrganizations.status, [Status.Accepted, Status.Confirmed]),
        eq(schema.policies.enabled, true),
        eq(schema.policies.atype, type),
      ),
    )
  return rows.filter((r) => !isAdminRole(r.m)).map((r) => r.p)
}

/** Rejects creation of a personal item while a PersonalOwnership policy applies to the user. */
export async function assertPersonalOwnershipAllowed(db: Db, userUuid: string) {
  if ((await enforcedPolicies(db, userUuid, PolicyType.PersonalOwnership)).length > 0) {
    throw new ApiError(
      400,
      'An organization policy is preventing you from saving items to your individual vault. Choose an organization to save this item to.',
    )
  }
}

/** True when the user has an enabled two-step login provider. */
export async function hasTwoFactor(db: Db, userUuid: string): Promise<boolean> {
  const [row] = await db
    .select({ id: schema.twofactor.uuid })
    .from(schema.twofactor)
    .where(and(eq(schema.twofactor.userUuid, userUuid), eq(schema.twofactor.enabled, true)))
    .limit(1)
  return row !== undefined
}

export async function twoFactorRequired(db: Db, orgUuid: string): Promise<boolean> {
  const [p] = await db
    .select({ enabled: schema.policies.enabled })
    .from(schema.policies)
    .where(
      and(
        eq(schema.policies.organizationUuid, orgUuid),
        eq(schema.policies.atype, PolicyType.TwoFactorAuthentication),
      ),
    )
    .limit(1)
  return p?.enabled === true
}

/** Throws when the organisation requires two-step login and the user has none. */
export async function assertTwoFactorCompliant(db: Db, userUuid: string, orgUuid: string) {
  if ((await twoFactorRequired(db, orgUuid)) && !(await hasTwoFactor(db, userUuid))) {
    throw new ApiError(
      400,
      'User does not have two-step login enabled, which this organization requires.',
    )
  }
}

/** Active non-owner members who have no two-step login. */
const nonCompliantWhere = (orgUuid: string) =>
  and(
    eq(schema.usersOrganizations.organizationUuid, orgUuid),
    inArray(schema.usersOrganizations.status, [Status.Accepted, Status.Confirmed]),
    sql`${schema.usersOrganizations.atype} != ${Role.Owner}`,
    sql`${schema.usersOrganizations.userUuid} not in (select ${schema.twofactor.userUuid} from ${schema.twofactor} where ${schema.twofactor.enabled} = 1)`,
  )

/** Statement that revokes active non-owner members who have no two-step login. */
export const revokeNonCompliantMembers = (db: Db, orgUuid: string, now: number) =>
  db
    .update(schema.usersOrganizations)
    .set({ status: Status.Revoked, updatedAt: now })
    .where(nonCompliantWhere(orgUuid))

/** A random version 4 identifier, made by SQLite so one statement can give every row its own. */
const sqlUuid = sql<string>`(lower(hex(randomblob(4))) || '-' || lower(hex(randomblob(2))) || '-4' || substr(lower(hex(randomblob(2))), 2) || '-' || substr('89ab', 1 + (abs(random()) % 4), 1) || substr(lower(hex(randomblob(2))), 2) || '-' || lower(hex(randomblob(6))))`

const nul = (name: string) => sql<null>`null`.as(name)

/**
 * One statement that records an event for every member `revokeNonCompliantMembers` would revoke:
 * `INSERT INTO events ... SELECT ... FROM users_organizations`. Put it before the update in the
 * same batch, because it reads the status the update changes.
 */
export const revocationEventsStatement = (
  db: Db,
  orgUuid: string,
  event: {
    type: number
    policyUuid: string
    actingUserUuid: string | null
    systemUser: number | null
    deviceType: number | null
    ipAddress: string | null
    date: number
  },
) => {
  const uo = schema.usersOrganizations
  return db.insert(schema.events).select(
    db
      .select({
        uuid: sqlUuid.as('uuid'),
        eventType: sql<number>`${event.type}`.as('eventType'),
        userUuid: sql<string | null>`${uo.userUuid}`.as('userUuid'),
        organizationUuid: sql<string>`${uo.organizationUuid}`.as('organizationUuid'),
        cipherUuid: nul('cipherUuid'),
        collectionUuid: nul('collectionUuid'),
        groupUuid: nul('groupUuid'),
        policyUuid: sql<string>`${event.policyUuid}`.as('policyUuid'),
        organizationUserUuid: sql<string>`${uo.uuid}`.as('organizationUserUuid'),
        actingUserUuid: sql<string | null>`${event.actingUserUuid}`.as('actingUserUuid'),
        secretUuid: nul('secretUuid'),
        projectUuid: nul('projectUuid'),
        serviceAccountUuid: nul('serviceAccountUuid'),
        grantedServiceAccountUuid: nul('grantedServiceAccountUuid'),
        sendUuid: nul('sendUuid'),
        systemUser: sql<number | null>`${event.systemUser}`.as('systemUser'),
        deviceType: sql<number | null>`${event.deviceType}`.as('deviceType'),
        ipAddress: sql<string | null>`${event.ipAddress}`.as('ipAddress'),
        eventDate: sql<number>`${event.date}`.as('eventDate'),
      })
      .from(uo)
      .where(nonCompliantWhere(orgUuid)),
  )
}

/** Master password requirements merged across every organisation that enforces them. */
export async function masterPasswordPolicyFor(db: Db, userUuid: string) {
  const rows = await enforcedPolicies(db, userUuid, PolicyType.MasterPassword)
  if (rows.length === 0) return null
  const merged = {
    minComplexity: 0,
    minLength: 0,
    requireUpper: false,
    requireLower: false,
    requireNumbers: false,
    requireSpecial: false,
    enforceOnLogin: false,
  }
  for (const row of rows) {
    const d = parseData(row.data) ?? {}
    merged.minComplexity = Math.max(merged.minComplexity, Number(d.minComplexity) || 0)
    merged.minLength = Math.max(merged.minLength, Number(d.minLength) || 0)
    merged.requireUpper ||= d.requireUpper === true
    merged.requireLower ||= d.requireLower === true
    merged.requireNumbers ||= d.requireNumbers === true
    merged.requireSpecial ||= d.requireSpecial === true
    merged.enforceOnLogin ||= d.enforceOnLogin === true
  }
  return merged
}

export const hasKey = (m: Member) => m.akey !== ''

/** The policy row of an organisation when it exists and is enabled. */
export async function enabledPolicy(db: Db, orgUuid: string, type: number) {
  const [p] = await db
    .select()
    .from(schema.policies)
    .where(
      and(
        eq(schema.policies.organizationUuid, orgUuid),
        eq(schema.policies.atype, type),
        eq(schema.policies.enabled, true),
      ),
    )
    .limit(1)
  return p
}

/**
 * Automatic confirmation needs an account that belongs to this organisation only, and it is
 * refused when another organisation of the account has the policy on (a member of two
 * organisations cannot have both confirm them blind). `email` is named in the message.
 */
export async function assertAutoConfirmEligible(
  db: Db,
  orgUuid: string,
  userUuid: string,
  email: string,
) {
  const others = await db
    .select({ orgUuid: schema.usersOrganizations.organizationUuid })
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, userUuid),
        inArray(schema.usersOrganizations.status, [Status.Accepted, Status.Confirmed]),
        sql`${schema.usersOrganizations.organizationUuid} != ${orgUuid}`,
      ),
    )
  if (
    others.length > 0 &&
    (await enabledPolicy(db, orgUuid, PolicyType.AutomaticUserConfirmation))
  ) {
    throw new ApiError(
      400,
      `Cannot confirm ${email} until they leave all other organization vaults.`,
    )
  }
  for (const o of others) {
    if (await enabledPolicy(db, o.orgUuid, PolicyType.AutomaticUserConfirmation)) {
      throw new ApiError(
        400,
        `Cannot confirm ${email} because they are a member of another organization which forbids it.`,
      )
    }
  }
}
