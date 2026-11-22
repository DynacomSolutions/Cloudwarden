// One guard for every write that can give a member Manage access to a collection that an access
// rule covers (PAM). Manage access lifts the lease restriction (`leaseRestricted`), so anyone who
// can hand it out can undo a rule: for themselves, for a second account of theirs, or for a group.
//
// Rule: unless the grantor is an owner or admin of the organisation, a write may not
//   1. give a member (or a group) Manage access on a covered collection, or
//   2. add a member to a group that holds Manage access on a covered collection (or that is an
//      access-all group, which holds Manage access on every collection),
// unless the grantor holds Manage access to that collection themselves. Already held grants stay
// allowed (`kept`, `alreadyIn`): a rename or an unchanged re-save is not a new grant. The rule
// holds for every target, the grantor's own member row included.
//
// Audit of every writer of `users_collections`, `collections_groups` and `groups_users`:
//   routes/org-users.ts    invite (collections, groups)        guarded here
//                          update (collections, groups)        guarded here
//                          PUT users/:id/groups                guarded here
//                          restore (single, bulk, vnext)      guarded here: a revoke keeps the grants,
//                                                              so a restore turns them on again
//                          bulk routes (reinvite, confirm,     write no grants
//                          revoke, remove)
//   routes/groups.ts       create, update, PUT groups/:id/users guarded here (round 3 checks moved)
//   routes/collections.ts  PUT users, PUT/POST update, bulk-access: guarded here; they also need
//                          own Manage on the collection already (`requireManage`)
//                          create: the collection is new, so no rule covers it
//   scim/routes.ts        Groups POST, PUT, PATCH (`saveGroup`) guarded here, as `SCIM_GRANTOR`
//                          Users `active: true` (restore) guarded here, as `SCIM_GRANTOR`
//                          Users routes write no group rows
//   orgs/directory-import.ts (client import route)           guarded here, as the acting member
//                          (Public API and Directory Connector: owner authority, skipped)
//   federation/hosting.ts  inviteFederated                    guarded here
//                          createFederatedInvite from the share flow: grants only the shared
//                          collection, and the sharer needs Manage on it (`requireManage`)
//   federation/sharing.ts  upsertGrant: same collection manager check as above
//   routes/public-api.ts   organisation API key = owner authority: skipped
//   routes/organizations.ts, routes/org-settings.ts  first-collection and invite-link default
//                          collection: a new collection that no rule covers
import { and, eq, inArray } from 'drizzle-orm'
import { type Db, schema } from '../db'
import { ApiError } from '../errors'
import { collectionAccess, isAdminRole, loadUserAccess, type Member } from '../orgs/access'

/** Who writes the grant. `userUuid` is null when no account holds the authority (a SCIM key). */
export interface Grantor {
  admin: boolean
  userUuid: string | null
}

export const grantorOf = (m: Member): Grantor => ({
  admin: isAdminRole(m),
  userUuid: m.userUuid,
})

/**
 * A SCIM key: its holder can be an owner, or a custom member with `manageScim`
 * (`org-api-keys.ts`). The request does not tell which, so SCIM writes count as non-admin writes
 * by an account without Manage access. The identity provider cannot add members to a group that
 * holds Manage access on a covered collection: the call answers 403 in the SCIM error format.
 * Owners and admins change such groups in the web vault or with the Public API.
 */
export const SCIM_GRANTOR: Grantor = { admin: false, userUuid: null }

export const COVERED_MANAGE_DENIED =
  'An access rule covers this collection. You need Manage access to it.'

const BATCH = 80

/** Collections of the organisation that an enabled access rule covers. */
export async function coveredCollections(db: Db, orgUuid: string): Promise<Set<string>> {
  const rows = await db
    .select({ id: schema.pamRuleCollections.collectionUuid })
    .from(schema.pamRuleCollections)
    .innerJoin(
      schema.pamAccessRules,
      eq(schema.pamAccessRules.uuid, schema.pamRuleCollections.ruleUuid),
    )
    .where(
      and(
        eq(schema.pamAccessRules.organizationUuid, orgUuid),
        eq(schema.pamAccessRules.enabled, true),
      ),
    )
  return new Set(rows.map((r) => r.id))
}

/** Refuses when `ids` holds a covered collection that the grantor lacks Manage access to. */
async function assertOwnManage(db: Db, grantor: Grantor, orgUuid: string, ids: string[]) {
  if (ids.length === 0) return
  const covered = await coveredCollections(db, orgUuid)
  const hit = [...new Set(ids)].filter((id) => covered.has(id))
  if (hit.length === 0) return
  if (!grantor.userUuid) throw new ApiError(403, COVERED_MANAGE_DENIED)
  const ua = await loadUserAccess(db, grantor.userUuid)
  for (const id of hit) {
    if (collectionAccess(ua, orgUuid, id)?.manage !== true) {
      throw new ApiError(403, COVERED_MANAGE_DENIED)
    }
  }
}

/**
 * Manage grants on collections (to a member or a group). `kept` lists collections where the
 * receiver already holds Manage access, which stay allowed.
 */
export async function assertManageGrantsAllowed(
  db: Db,
  grantor: Grantor,
  orgUuid: string,
  grants: { id: string; manage: boolean }[],
  kept: Set<string> = new Set(),
) {
  if (grantor.admin) return
  await assertOwnManage(
    db,
    grantor,
    orgUuid,
    grants.filter((s) => s.manage && !kept.has(s.id)).map((s) => s.id),
  )
}

/**
 * Members that join groups, or groups that gain members: the Manage access of each group reaches
 * the new member. `alreadyIn` lists groups the member is in now, which stay allowed. To add
 * members to one group, pass `[groupUuid]` and call only when a member is new.
 */
export async function assertGroupJoinAllowed(
  db: Db,
  grantor: Grantor,
  orgUuid: string,
  groupIds: string[],
  alreadyIn: Set<string> = new Set(),
) {
  if (grantor.admin) return
  const fresh = [...new Set(groupIds)].filter((g) => !alreadyIn.has(g))
  if (fresh.length === 0) return
  const manage: string[] = []
  let accessAll = false
  for (let i = 0; i < fresh.length; i += BATCH) {
    const part = fresh.slice(i, i + BATCH)
    const rows = await db
      .select({ id: schema.collectionsGroups.collectionUuid })
      .from(schema.collectionsGroups)
      .where(
        and(
          inArray(schema.collectionsGroups.groupUuid, part),
          eq(schema.collectionsGroups.manage, true),
        ),
      )
    manage.push(...rows.map((r) => r.id))
    const all = await db
      .select({ id: schema.groups.uuid })
      .from(schema.groups)
      .where(and(inArray(schema.groups.uuid, part), eq(schema.groups.accessAll, true)))
    if (all.length) accessAll = true
  }
  // An access-all group holds Manage access on every collection of the organisation.
  const ids = accessAll ? [...(await coveredCollections(db, orgUuid))] : manage
  await assertOwnManage(db, grantor, orgUuid, ids)
}

/**
 * A restore turns the stored grants of a revoked member on again: their direct Manage grants, the
 * groups they belong to, and access to every collection (`accessAll`). The grantor needs the same
 * authority as for a new grant, so a non-admin cannot restore an account that an admin once gave
 * Manage access to a covered collection.
 */
export async function assertRestoreAllowed(db: Db, grantor: Grantor, member: Member) {
  if (grantor.admin) return
  const orgUuid = member.organizationUuid
  if (member.accessAll) {
    await assertOwnManage(db, grantor, orgUuid, [...(await coveredCollections(db, orgUuid))])
  }
  const held = await memberManageGrants(db, member.uuid)
  await assertManageGrantsAllowed(
    db,
    grantor,
    orgUuid,
    [...held].map((id) => ({ id, manage: true })),
  )
  await assertGroupJoinAllowed(db, grantor, orgUuid, [...(await memberGroups(db, member.uuid))])
}

/** Collections where a member holds a direct Manage grant now (the `kept` set of an update). */
export async function memberManageGrants(db: Db, memberUuid: string): Promise<Set<string>> {
  const rows = await db
    .select({ id: schema.usersCollections.collectionUuid })
    .from(schema.usersCollections)
    .where(
      and(
        eq(schema.usersCollections.organizationUserUuid, memberUuid),
        eq(schema.usersCollections.manage, true),
      ),
    )
  return new Set(rows.map((r) => r.id))
}

/** Groups a member belongs to now (the `alreadyIn` set of an update). */
export async function memberGroups(db: Db, memberUuid: string): Promise<Set<string>> {
  const rows = await db
    .select({ id: schema.groupsUsers.groupUuid })
    .from(schema.groupsUsers)
    .where(eq(schema.groupsUsers.organizationUserUuid, memberUuid))
  return new Set(rows.map((r) => r.id))
}

/** Members of a group now. */
export async function groupMemberSet(db: Db, groupUuid: string): Promise<Set<string>> {
  const rows = await db
    .select({ id: schema.groupsUsers.organizationUserUuid })
    .from(schema.groupsUsers)
    .where(eq(schema.groupsUsers.groupUuid, groupUuid))
  return new Set(rows.map((r) => r.id))
}
