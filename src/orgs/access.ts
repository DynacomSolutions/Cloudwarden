import { and, eq, inArray, sql } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import { ApiError } from '../errors'
import { LeaseStatus } from '../pam/constants'
import { PERMISSION_KEYS, Role, Status } from './constants'

export type Member = typeof schema.usersOrganizations.$inferSelect
export type Permissions = Record<(typeof PERMISSION_KEYS)[number], boolean>

export const emptyPermissions = (): Permissions =>
  Object.fromEntries(PERMISSION_KEYS.map((k) => [k, false])) as Permissions

/** Stored custom permissions merged over an all-false base. */
export function storedPermissions(m: Member): Permissions {
  const out = emptyPermissions()
  if (m.atype !== Role.Custom || !m.permissions) return out
  try {
    const raw = JSON.parse(m.permissions) as Record<string, unknown>
    for (const k of PERMISSION_KEYS) out[k] = raw[k] === true
  } catch {
    // A corrupt value grants nothing.
  }
  return out
}

/** Owners and admins hold every permission; custom members hold what was stored. */
export function can(m: Member | undefined, perm: keyof Permissions): boolean {
  if (!m || m.status !== Status.Confirmed) return false
  if (m.atype === Role.Owner || m.atype === Role.Admin) return true
  return m.atype === Role.Custom && storedPermissions(m)[perm]
}

export const isAdminRole = (m: Member) => m.atype === Role.Owner || m.atype === Role.Admin

/** May read and change every item of the organisation through the admin endpoints. */
export const canManageAllCiphers = (m: Member | undefined) =>
  can(m, 'editAnyCollection') || can(m, 'manageCiphers')

/**
 * `canManageAllCiphers` that honours the organisation's "owners and admins can manage all
 * collections and items" setting (TASKS #231): when it is off, owners and admins only reach the
 * items of collections they are assigned; custom members keep their explicit permissions.
 */
export async function manageAll(db: Db, m: Member | undefined): Promise<boolean> {
  if (!canManageAllCiphers(m) || !m) return false
  if (!isAdminRole(m)) return true
  const [org] = await db
    .select({ allow: schema.organizations.allowAdminAccessToAllCollectionItems })
    .from(schema.organizations)
    .where(eq(schema.organizations.uuid, m.organizationUuid))
    .limit(1)
  return org?.allow ?? true
}

/** Whether the organisation limits item deletion to members with Manage access (TASKS #231). */
export async function limitsItemDeletion(db: Db, orgUuid: string): Promise<boolean> {
  const [org] = await db
    .select({ limit: schema.organizations.limitItemDeletion })
    .from(schema.organizations)
    .where(eq(schema.organizations.uuid, orgUuid))
    .limit(1)
  return org?.limit ?? false
}

export async function getMember(
  db: Db,
  userUuid: string,
  orgUuid: string,
): Promise<Member | undefined> {
  const [m] = await db
    .select()
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.userUuid, userUuid),
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  return m
}

/** The caller's confirmed membership; 404 when they are not a (confirmed) member. */
export async function requireMember(db: Db, userUuid: string, orgUuid: string): Promise<Member> {
  const m = await getMember(db, userUuid, orgUuid)
  if (!m || m.status !== Status.Confirmed) throw new ApiError(404, 'Organization not found.')
  return m
}

/** Requires a confirmed member holding `perm`; 404 for outsiders and 403 for members without it. */
export async function requirePermission(
  db: Db,
  userUuid: string,
  orgUuid: string,
  perm: keyof Permissions,
): Promise<Member> {
  const m = await requireMember(db, userUuid, orgUuid)
  if (!can(m, perm)) throw new ApiError(403, 'You do not have permission to do this.')
  return m
}

export async function requireOwner(db: Db, userUuid: string, orgUuid: string): Promise<Member> {
  const m = await requireMember(db, userUuid, orgUuid)
  if (m.atype !== Role.Owner) throw new ApiError(403, 'Only owners can do this.')
  return m
}

export async function requireOrg(db: Db, orgUuid: string) {
  const [org] = await db
    .select()
    .from(schema.organizations)
    .where(eq(schema.organizations.uuid, orgUuid))
    .limit(1)
  if (!org) throw new ApiError(404, 'Organization not found.')
  return org
}

export interface Access {
  readOnly: boolean
  hidePasswords: boolean
  manage: boolean
}

export const FULL_ACCESS: Access = { readOnly: false, hidePasswords: false, manage: true }

/** Combines two grants: the more permissive value wins for every flag. */
export const mergeAccess = (a: Access | undefined, b: Access): Access =>
  a
    ? {
        readOnly: a.readOnly && b.readOnly,
        hidePasswords: a.hidePasswords && b.hidePasswords,
        manage: a.manage || b.manage,
      }
    : b

export interface UserAccess {
  /** Confirmed memberships. */
  members: Member[]
  /** Organisations where the user (or one of their groups) can reach every collection. */
  accessAllOrgs: Set<string>
  /** Explicit per-collection grants from the user's own rows and their groups. */
  grants: Map<string, Access>
  /** Organisations that limit deleting and restoring items to members with Manage access. */
  limitDeletionOrgs: Set<string>
  /** Collections that an enabled access rule covers, in the user's organisations (PAM). */
  gatedCollections: Set<string>
  /** Items on which the user holds a live lease right now (PAM). */
  leasedCiphers: Set<string>
}

/**
 * Whether an item is restricted for the user: an enabled access rule covers one of its collections,
 * and the user is not an owner or admin of the organisation, holds no Manage access to a covered
 * collection (a decider), and holds no live lease on the item. A restricted item reaches the user
 * only as the reduced row of the official clients (name and login URIs, no secrets).
 */
export function leaseRestricted(
  ua: UserAccess,
  orgUuid: string,
  cipherUuid: string,
  linked: string[],
): boolean {
  const covered = linked.filter((id) => ua.gatedCollections.has(id))
  if (covered.length === 0) return false
  if (ua.members.some((m) => m.organizationUuid === orgUuid && isAdminRole(m))) return false
  if (covered.some((id) => collectionAccess(ua, orgUuid, id)?.manage === true)) return false
  return !ua.leasedCiphers.has(cipherUuid)
}

/** Everything that decides which collections a user can reach, in three queries. */
export async function loadUserAccess(
  db: Db,
  userUuid: string,
  now = Date.now(),
): Promise<UserAccess> {
  const uo = schema.usersOrganizations
  const confirmed = and(eq(uo.userUuid, userUuid), eq(uo.status, Status.Confirmed))
  const [members, direct, viaGroups, groupsAll, leased] = await Promise.all([
    db.select().from(uo).where(confirmed),
    db
      .select({ c: schema.usersCollections })
      .from(schema.usersCollections)
      .innerJoin(uo, eq(uo.uuid, schema.usersCollections.organizationUserUuid))
      .where(confirmed),
    db
      .select({ c: schema.collectionsGroups })
      .from(schema.collectionsGroups)
      .innerJoin(
        schema.groupsUsers,
        eq(schema.groupsUsers.groupUuid, schema.collectionsGroups.groupUuid),
      )
      .innerJoin(uo, eq(uo.uuid, schema.groupsUsers.organizationUserUuid))
      .where(confirmed),
    db
      .select({ orgUuid: schema.groups.organizationUuid })
      .from(schema.groups)
      .innerJoin(schema.groupsUsers, eq(schema.groupsUsers.groupUuid, schema.groups.uuid))
      .innerJoin(uo, eq(uo.uuid, schema.groupsUsers.organizationUserUuid))
      .where(and(confirmed, eq(schema.groups.accessAll, true))),
    // A lease is live between `notBefore` and `notAfter`; a revoke or expiry ends it at once.
    db
      .select({ id: schema.pamLeases.cipherUuid })
      .from(schema.pamLeases)
      .where(
        and(
          eq(schema.pamLeases.requesterUuid, userUuid),
          eq(schema.pamLeases.status, LeaseStatus.Active),
          sql`${schema.pamLeases.notBefore} <= ${now}`,
          sql`${schema.pamLeases.notAfter} > ${now}`,
        ),
      ),
  ])
  const accessAllOrgs = new Set<string>([
    ...members.filter((m) => m.accessAll).map((m) => m.organizationUuid),
    ...groupsAll.map((g) => g.orgUuid),
  ])
  const grants = new Map<string, Access>()
  for (const { c } of [...direct, ...viaGroups]) {
    grants.set(c.collectionUuid, mergeAccess(grants.get(c.collectionUuid), c))
  }
  const limited =
    members.length === 0
      ? []
      : await db
          .select({ uuid: schema.organizations.uuid })
          .from(schema.organizations)
          .where(
            and(
              inArray(
                schema.organizations.uuid,
                members.map((m) => m.organizationUuid),
              ),
              eq(schema.organizations.limitItemDeletion, true),
            ),
          )
  // Rules matter only in organisations where the user is not an owner or admin.
  const ruleOrgs = members.filter((m) => !isAdminRole(m)).map((m) => m.organizationUuid)
  const gatedCollections = new Set<string>()
  for (let i = 0; i < ruleOrgs.length; i += 80) {
    const rows = await db
      .select({ id: schema.pamRuleCollections.collectionUuid })
      .from(schema.pamRuleCollections)
      .innerJoin(
        schema.pamAccessRules,
        eq(schema.pamAccessRules.uuid, schema.pamRuleCollections.ruleUuid),
      )
      .where(
        and(
          inArray(schema.pamAccessRules.organizationUuid, ruleOrgs.slice(i, i + 80)),
          eq(schema.pamAccessRules.enabled, true),
        ),
      )
    for (const r of rows) gatedCollections.add(r.id)
  }
  return {
    members,
    accessAllOrgs,
    grants,
    limitDeletionOrgs: new Set(limited.map((o) => o.uuid)),
    gatedCollections,
    leasedCiphers: new Set(leased.map((l) => l.id)),
  }
}

/** Access a user has to one collection of `orgUuid`, or undefined for none. */
export function collectionAccess(
  ua: UserAccess,
  orgUuid: string,
  collectionUuid: string,
): Access | undefined {
  if (ua.accessAllOrgs.has(orgUuid)) return FULL_ACCESS
  return ua.grants.get(collectionUuid)
}

/** Collections of the user's organisations they can see, with their effective access. */
export async function listAccessibleCollections(db: Db, userUuid: string, ua?: UserAccess) {
  const access = ua ?? (await loadUserAccess(db, userUuid))
  const orgs = access.members.map((m) => m.organizationUuid)
  const rows: { collection: typeof schema.collections.$inferSelect; access: Access }[] = []
  for (let i = 0; i < orgs.length; i += 80) {
    const part = orgs.slice(i, i + 80)
    const found = await db
      .select()
      .from(schema.collections)
      .where(inArray(schema.collections.organizationUuid, part))
    for (const collection of found) {
      const a = collectionAccess(access, collection.organizationUuid, collection.uuid)
      if (a) rows.push({ collection, access: a })
    }
  }
  return rows
}

/** Bumps the account revision date of every active member so their clients resync. */
export const bumpOrgRevision = (db: Db, orgUuid: string, now: number) =>
  db
    .update(schema.users)
    .set({ updatedAt: now })
    .where(
      sql`${schema.users.uuid} in (select ${schema.usersOrganizations.userUuid} from ${schema.usersOrganizations} where ${schema.usersOrganizations.organizationUuid} = ${orgUuid} and ${schema.usersOrganizations.status} >= ${Status.Accepted})`,
    )
