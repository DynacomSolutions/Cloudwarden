// Member access and member cipher reports of Access Intelligence (TASKS #435). Both read the same
// grants as the vault does (direct member grants, group grants and access-all flags), so the
// report always matches what each member can open.
import { and, eq, isNull } from 'drizzle-orm'
import type { Db } from '../db'
import { schema } from '../db'
import { Status } from './constants'

export interface MemberAccessRow {
  userGuid: string | null
  userName: string | null
  email: string | null
  twoFactorEnabled: boolean
  accountRecoveryEnabled: boolean
  usesKeyConnector: boolean
  collectionId: string | null
  groupId: string | null
  groupName: string | null
  collectionName: string | null
  readOnly: boolean
  hidePasswords: boolean
  manage: boolean
  cipherIds: string[]
}

export interface MemberCipherRow {
  userGuid: string | null
  userName: string | null
  email: string | null
  usesKeyConnector: boolean
  cipherIds: string[]
}

interface Grant {
  collectionUuid: string
  groupUuid: string | null
  readOnly: boolean
  hidePasswords: boolean
  manage: boolean
}

/** Everything the two reports need for one organisation, loaded in a fixed number of queries. */
async function load(db: Db, orgUuid: string) {
  const uo = schema.usersOrganizations
  // Only confirmed members can open items (loadUserAccess), so only they hold access.
  const members = await db
    .select({
      member: uo,
      name: schema.users.name,
      userEmail: schema.users.email,
      keyConnector: schema.users.usesKeyConnector,
    })
    .from(uo)
    .innerJoin(schema.users, eq(schema.users.uuid, uo.userUuid))
    .where(and(eq(uo.organizationUuid, orgUuid), eq(uo.status, Status.Confirmed)))
  const [collections, groups, direct, groupMembers, groupGrants, links, withTwoFactor] =
    await Promise.all([
      db
        .select({ uuid: schema.collections.uuid, name: schema.collections.name })
        .from(schema.collections)
        .where(eq(schema.collections.organizationUuid, orgUuid)),
      db
        .select({
          uuid: schema.groups.uuid,
          name: schema.groups.name,
          accessAll: schema.groups.accessAll,
        })
        .from(schema.groups)
        .where(eq(schema.groups.organizationUuid, orgUuid)),
      db
        .select({
          member: schema.usersCollections.organizationUserUuid,
          collectionUuid: schema.usersCollections.collectionUuid,
          readOnly: schema.usersCollections.readOnly,
          hidePasswords: schema.usersCollections.hidePasswords,
          manage: schema.usersCollections.manage,
        })
        .from(schema.usersCollections)
        .innerJoin(uo, eq(uo.uuid, schema.usersCollections.organizationUserUuid))
        .where(eq(uo.organizationUuid, orgUuid)),
      db
        .select({
          member: schema.groupsUsers.organizationUserUuid,
          group: schema.groupsUsers.groupUuid,
        })
        .from(schema.groupsUsers)
        .innerJoin(schema.groups, eq(schema.groups.uuid, schema.groupsUsers.groupUuid))
        .where(eq(schema.groups.organizationUuid, orgUuid)),
      db
        .select({
          group: schema.collectionsGroups.groupUuid,
          collectionUuid: schema.collectionsGroups.collectionUuid,
          readOnly: schema.collectionsGroups.readOnly,
          hidePasswords: schema.collectionsGroups.hidePasswords,
          manage: schema.collectionsGroups.manage,
        })
        .from(schema.collectionsGroups)
        .innerJoin(schema.groups, eq(schema.groups.uuid, schema.collectionsGroups.groupUuid))
        .where(eq(schema.groups.organizationUuid, orgUuid)),
      db
        .select({
          cipher: schema.ciphersCollections.cipherUuid,
          collection: schema.ciphersCollections.collectionUuid,
        })
        .from(schema.ciphersCollections)
        .innerJoin(schema.ciphers, eq(schema.ciphers.uuid, schema.ciphersCollections.cipherUuid))
        .where(and(eq(schema.ciphers.organizationUuid, orgUuid), isNull(schema.ciphers.deletedAt))),
      db
        .selectDistinct({ user: schema.twofactor.userUuid })
        .from(schema.twofactor)
        .innerJoin(uo, eq(uo.userUuid, schema.twofactor.userUuid))
        .where(and(eq(uo.organizationUuid, orgUuid), eq(schema.twofactor.enabled, true))),
    ])
  // Items held by no collection are reachable only through an access-all grant.
  const orgCipherIds = (
    await db
      .select({ uuid: schema.ciphers.uuid })
      .from(schema.ciphers)
      .where(and(eq(schema.ciphers.organizationUuid, orgUuid), isNull(schema.ciphers.deletedAt)))
  ).map((r) => r.uuid)

  const ciphersOf = new Map<string, string[]>()
  for (const l of links) {
    const list = ciphersOf.get(l.collection) ?? []
    list.push(l.cipher)
    ciphersOf.set(l.collection, list)
  }
  const groupById = new Map(groups.map((g) => [g.uuid, g]))
  const groupsOf = new Map<string, string[]>()
  for (const g of groupMembers) {
    const list = groupsOf.get(g.member) ?? []
    list.push(g.group)
    groupsOf.set(g.member, list)
  }
  const directOf = new Map<string, Grant[]>()
  for (const d of direct) {
    const list = directOf.get(d.member) ?? []
    list.push({ ...d, groupUuid: null })
    directOf.set(d.member, list)
  }
  const viaGroup = new Map<string, Grant[]>()
  for (const g of groupGrants) {
    const list = viaGroup.get(g.group) ?? []
    list.push({ ...g, groupUuid: g.group })
    viaGroup.set(g.group, list)
  }
  return {
    members,
    collections,
    collectionName: new Map(collections.map((c) => [c.uuid, c.name])),
    groupById,
    groupsOf,
    directOf,
    viaGroup,
    ciphersOf,
    orgCipherIds,
    twoFactor: new Set(withTwoFactor.map((r) => r.user)),
  }
}

type Loaded = Awaited<ReturnType<typeof load>>
type Row = Loaded['members'][number]

/** Grants of one member, one entry per source: access-all expands to every collection. */
function grantsOf(l: Loaded, row: Row): Grant[] {
  const full = (groupUuid: string | null): Grant[] =>
    l.collections.map((c) => ({
      collectionUuid: c.uuid,
      groupUuid,
      readOnly: false,
      hidePasswords: false,
      manage: true,
    }))
  if (row.member.accessAll) return full(null)
  const out: Grant[] = [...(l.directOf.get(row.member.uuid) ?? [])]
  for (const groupId of l.groupsOf.get(row.member.uuid) ?? []) {
    out.push(
      ...(l.groupById.get(groupId)?.accessAll ? full(groupId) : (l.viaGroup.get(groupId) ?? [])),
    )
  }
  return out
}

const hasAccessAll = (l: Loaded, row: Row) =>
  row.member.accessAll ||
  (l.groupsOf.get(row.member.uuid) ?? []).some((g) => l.groupById.get(g)?.accessAll)

/** One row per member and granted collection; a member without any grant still gets one row. */
export async function memberAccessReport(db: Db, orgUuid: string): Promise<MemberAccessRow[]> {
  const l = await load(db, orgUuid)
  const out: MemberAccessRow[] = []
  for (const row of l.members) {
    const who = {
      userGuid: row.member.userUuid,
      userName: row.name || null,
      email: row.userEmail,
      twoFactorEnabled: l.twoFactor.has(row.member.userUuid ?? ''),
      accountRecoveryEnabled: row.member.resetPasswordKey != null,
      usesKeyConnector: row.keyConnector,
    }
    const grants = grantsOf(l, row)
    if (grants.length === 0) {
      out.push({
        ...who,
        collectionId: null,
        groupId: null,
        groupName: null,
        collectionName: null,
        readOnly: false,
        hidePasswords: false,
        manage: false,
        cipherIds: [],
      })
      continue
    }
    for (const g of grants) {
      out.push({
        ...who,
        collectionId: g.collectionUuid,
        groupId: g.groupUuid,
        groupName: g.groupUuid ? (l.groupById.get(g.groupUuid)?.name ?? null) : null,
        collectionName: l.collectionName.get(g.collectionUuid) ?? null,
        readOnly: g.readOnly,
        hidePasswords: g.hidePasswords,
        manage: g.manage,
        cipherIds: l.ciphersOf.get(g.collectionUuid) ?? [],
      })
    }
  }
  return out
}

/** One row per member with every item id the member can reach. */
export async function memberCipherReport(db: Db, orgUuid: string): Promise<MemberCipherRow[]> {
  const l = await load(db, orgUuid)
  return l.members.map((row) => {
    const ids = hasAccessAll(l, row)
      ? l.orgCipherIds
      : [...new Set(grantsOf(l, row).flatMap((g) => l.ciphersOf.get(g.collectionUuid) ?? []))]
    return {
      userGuid: row.member.userUuid,
      userName: row.name || null,
      email: row.userEmail,
      usesKeyConnector: row.keyConnector,
      cipherIds: ids,
    }
  })
}
