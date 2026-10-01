import { and, eq, inArray, sql } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import { ApiError } from '../errors'
import { chunk } from '../vault/ciphers'
import { type Access, can, isAdminRole, type Member, storedPermissions } from './access'
import { PERMISSION_KEYS, Role, Status } from './constants'

export const VALID_ROLES = [
  Role.Owner,
  Role.Admin,
  Role.User,
  Role.Manager,
  Role.Custom,
] as number[]

/** Serialised custom permissions for a role, or null for roles that carry none. */
export function permissionsColumn(
  type: number,
  input: Record<string, boolean | null> | null | undefined,
) {
  if (type !== Role.Custom) return null
  return JSON.stringify(Object.fromEntries(PERMISSION_KEYS.map((k) => [k, input?.[k] === true])))
}

/**
 * Whether `actor` may manage a member holding role `targetType`, or grant that role.
 * Owners manage everyone; admins everyone but owners; custom members only plain roles.
 */
export function assertCanAssign(actor: Member, targetType: number) {
  const ok =
    actor.atype === Role.Owner ||
    (actor.atype === Role.Admin && targetType !== Role.Owner) ||
    (actor.atype === Role.Custom &&
      can(actor, 'manageUsers') &&
      targetType !== Role.Owner &&
      targetType !== Role.Admin)
  if (!ok) throw new ApiError(403, 'You do not have permission to manage this member.')
}

/**
 * A custom member who may manage users can only hand out what they hold themselves:
 * blanket access and each permission key. Owners and admins are not limited.
 */
export function assertCanGrant(
  actor: Member,
  grant: { accessAll?: boolean | null; permissions?: Record<string, boolean | null> | null },
) {
  if (actor.atype !== Role.Custom) return
  const held = storedPermissions(actor)
  const exceeds =
    (grant.accessAll === true && !actor.accessAll) ||
    PERMISSION_KEYS.some((k) => grant.permissions?.[k] === true && !held[k])
  if (exceeds) throw new ApiError(403, 'You cannot grant access you do not hold.')
}

export async function getTarget(db: Db, orgUuid: string, id: string): Promise<Member> {
  const [m] = await db
    .select()
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.uuid, id),
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  if (!m) throw new ApiError(404, 'User not found.')
  return m
}

/** Throws unless another confirmed owner remains once `target` stops being one. */
export async function assertNotLastOwner(db: Db, orgUuid: string, target: Member) {
  if (target.atype !== Role.Owner || target.status !== Status.Confirmed) return
  const [row] = await db
    .select({ n: sql<number>`count(*)` })
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
        eq(schema.usersOrganizations.atype, Role.Owner),
        eq(schema.usersOrganizations.status, Status.Confirmed),
        sql`${schema.usersOrganizations.uuid} != ${target.uuid}`,
      ),
    )
  if (!row || row.n < 1)
    throw new ApiError(400, 'Organization must have at least one confirmed owner.')
}

/** Throws unless every id names a row of `table` in the organisation. */
export async function assertIdsInOrg(
  db: Db,
  kind: 'collection' | 'group' | 'member',
  orgUuid: string,
  ids: string[],
) {
  const unique = [...new Set(ids)]
  const t =
    kind === 'collection'
      ? {
          uuid: schema.collections.uuid,
          orgCol: schema.collections.organizationUuid,
          table: schema.collections,
        }
      : kind === 'group'
        ? { uuid: schema.groups.uuid, orgCol: schema.groups.organizationUuid, table: schema.groups }
        : {
            uuid: schema.usersOrganizations.uuid,
            orgCol: schema.usersOrganizations.organizationUuid,
            table: schema.usersOrganizations,
          }
  let found = 0
  for (const part of chunk(unique)) {
    const [row] = await db
      .select({ n: sql<number>`count(*)` })
      .from(t.table)
      .where(and(eq(t.orgCol, orgUuid), inArray(t.uuid, part)))
    found += row?.n ?? 0
  }
  if (found !== unique.length) {
    throw new ApiError(400, 'The request is invalid.', {
      [kind === 'member' ? 'users' : `${kind}s`]: [`One or more ${kind}s do not exist.`],
    })
  }
}

export interface Selection {
  id: string
  readOnly: boolean
  hidePasswords: boolean
  manage: boolean
}

/** Last occurrence wins when an id is repeated. */
export const dedupeSelections = (items: Selection[]) => [
  ...new Map(items.map((s) => [s.id, s])).values(),
]

export const accessOf = (s: Selection): Access => ({
  readOnly: s.readOnly,
  hidePasswords: s.hidePasswords,
  manage: s.manage,
})

export interface MemberLists {
  collections: Map<string, Selection[]>
  groups: Map<string, string[]>
  twoFactor: Set<string>
}

/** Collection grants, group ids and two-step status for every member of an organisation. */
export async function loadMemberLists(
  db: Db,
  orgUuid: string,
  want: { collections: boolean; groups: boolean },
): Promise<MemberLists> {
  const uo = schema.usersOrganizations
  const collections = new Map<string, Selection[]>()
  const groups = new Map<string, string[]>()
  if (want.collections) {
    const rows = await db
      .select({ m: schema.usersCollections.organizationUserUuid, c: schema.usersCollections })
      .from(schema.usersCollections)
      .innerJoin(uo, eq(uo.uuid, schema.usersCollections.organizationUserUuid))
      .where(eq(uo.organizationUuid, orgUuid))
    for (const { m, c } of rows) {
      const list = collections.get(m) ?? []
      list.push({
        id: c.collectionUuid,
        readOnly: c.readOnly,
        hidePasswords: c.hidePasswords,
        manage: c.manage,
      })
      collections.set(m, list)
    }
  }
  if (want.groups) {
    const rows = await db
      .select({ m: schema.groupsUsers.organizationUserUuid, g: schema.groupsUsers.groupUuid })
      .from(schema.groupsUsers)
      .innerJoin(uo, eq(uo.uuid, schema.groupsUsers.organizationUserUuid))
      .where(eq(uo.organizationUuid, orgUuid))
    for (const { m, g } of rows) groups.set(m, [...(groups.get(m) ?? []), g])
  }
  const tf = await db
    .select({ u: schema.twofactor.userUuid })
    .from(schema.twofactor)
    .innerJoin(uo, eq(uo.userUuid, schema.twofactor.userUuid))
    .where(and(eq(uo.organizationUuid, orgUuid), eq(schema.twofactor.enabled, true)))
  return { collections, groups, twoFactor: new Set(tf.map((r) => r.u)) }
}

type UserRow = typeof schema.users.$inferSelect

export function memberJson(
  m: Member,
  user: Pick<UserRow, 'name' | 'email'> | null,
  lists: MemberLists | null,
  detailed = false,
) {
  return {
    object: detailed ? 'organizationUserDetails' : 'organizationUserUserDetails',
    id: m.uuid,
    userId: m.userUuid,
    name: user?.name ?? null,
    email: user?.email ?? m.email ?? '',
    avatarColor: null,
    type: m.atype,
    status: m.status,
    accessAll: m.accessAll,
    permissions: storedPermissions(m),
    externalId: m.externalId,
    ssoExternalId: null,
    resetPasswordEnrolled: m.resetPasswordKey !== null,
    usesKeyConnector: false,
    hasMasterPassword: true,
    twoFactorEnabled: m.userUuid ? (lists?.twoFactor.has(m.userUuid) ?? false) : false,
    claimedByOrganization: false,
    accessSecretsManager: false,
    accessPam: false,
    revocationReason: null,
    ...(lists
      ? {
          collections: (lists.collections.get(m.uuid) ?? []).map((s) => ({ ...s })),
          groups: lists.groups.get(m.uuid) ?? [],
        }
      : {}),
  }
}

/** Roles that may list members: admins and custom members with a user, group or collection permission. */
export const canListMembers = (m: Member) =>
  isAdminRole(m) ||
  can(m, 'manageUsers') ||
  can(m, 'manageGroups') ||
  can(m, 'editAnyCollection') ||
  can(m, 'createNewCollections')

export const statusAfterRestore = (m: Member) =>
  m.akey === '' ? Status.Accepted : Status.Confirmed

/** Throws when deleting the account would leave an organisation without a confirmed owner. */
export async function assertNotSoleOwner(db: Db, userUuid: string) {
  const o = schema.usersOrganizations
  const rows = await db
    .select({ org: o.organizationUuid })
    .from(o)
    .where(
      and(
        eq(o.userUuid, userUuid),
        eq(o.atype, Role.Owner),
        eq(o.status, Status.Confirmed),
        sql`not exists (select 1 from users_organizations o2 where o2.organization_uuid = ${o.organizationUuid} and o2.atype = ${Role.Owner} and o2.status = ${Status.Confirmed} and o2.uuid != ${o.uuid})`,
      ),
    )
    .limit(1)
  if (rows.length > 0) {
    throw new ApiError(
      400,
      'You are the only owner of an organization. Transfer ownership or delete the organization first.',
    )
  }
}
