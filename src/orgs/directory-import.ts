// Directory import (TASKS #272): `POST /public/organization/import`, the request the Bitwarden
// Directory Connector sends after reading users and groups from LDAP, Entra ID, Google, Okta or
// OneLogin. Members are matched by external id, then by email; new ones are invited. Groups are
// matched by external id and their membership replaced. With `overwriteExisting`, members and
// groups that carry an external id absent from the import are removed. Owners are never removed;
// admins and custom members only with `removePrivilegedMembers`.
import { eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { z } from 'zod'
import { normalizeEmail } from '../auth/users'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { sendInvite } from '../routes/org-users'
import { chunk } from '../vault/ciphers'
import { bumpOrgRevision, type Member, requireOrg } from './access'
import { dropMemberStateFor } from './ciphers'
import { EventType, Role } from './constants'
import { eventStatement } from './events'
import { assertCanAssign } from './members'
import { insertMemberStatements, invitedMember } from './provisioning'
import { batch } from './util'

export const MAX_IMPORT = 10_000
/** Group membership pairs across all groups of one call. */
export const MAX_MEMBERSHIPS = 50_000
/** New members invited by one call (each gets an email). */
export const MAX_INVITES = 500

export const importSchema = z.object({
  groups: z
    .array(
      z.object({
        name: z.string().min(1).max(100),
        externalId: z.string().min(1).max(300),
        memberExternalIds: z.array(z.string()).nullish(),
      }),
    )
    .max(MAX_IMPORT)
    .nullish(),
  members: z
    .array(
      z.object({
        email: z.string().max(256).nullish(),
        externalId: z.string().min(1).max(300),
        deleted: z.boolean().nullish(),
      }),
    )
    .max(MAX_IMPORT)
    .nullish(),
  overwriteExisting: z.boolean().nullish(),
  largeImport: z.boolean().nullish(),
  inviteUsersAfterProvisioning: z.boolean().nullish(),
  /**
   * Cloudwarden extension, not sent by the Directory Connector: also remove admins and custom
   * members that the import deletes or leaves out under `overwriteExisting`.
   */
  removePrivilegedMembers: z.boolean().nullish(),
})
export type ImportRequest = z.infer<typeof importSchema>

/**
 * Body of `POST /api/organizations/{orgId}/import` as the clients send it: `members` and group
 * `memberExternalIds` (the API model) or `users` on both levels (the client's directory model).
 */
export const clientImportSchema = importSchema
  .omit({ groups: true, removePrivilegedMembers: true })
  .extend({
    groups: z
      .array(
        z.object({
          name: z.string().min(1).max(100),
          externalId: z.string().min(1).max(300),
          memberExternalIds: z.array(z.string()).nullish(),
          users: z.array(z.string()).nullish(),
        }),
      )
      .max(MAX_IMPORT)
      .nullish(),
    users: importSchema.shape.members,
  })
  .transform(
    ({ users, groups, members, ...rest }): ImportRequest => ({
      ...rest,
      members: [...(members ?? []), ...(users ?? [])],
      groups: (groups ?? []).map(({ users: u, memberExternalIds, ...g }) => ({
        ...g,
        memberExternalIds: [...(memberExternalIds ?? []), ...(u ?? [])],
      })),
    }),
  )

export interface ImportResult {
  invited: number
  linked: number
  removed: number
  groupsCreated: number
  groupsUpdated: number
  groupsDeleted: number
}

/** Runs statements in slices so a large directory never exceeds a D1 batch. */
async function runSliced(db: Db, statements: unknown[]) {
  for (const part of chunk(statements, 200)) await batch(db, part)
}

export async function importDirectory(
  c: Context<Env>,
  orgUuid: string,
  body: ImportRequest,
  systemUser: number | null,
  /** The member acting through a user token; null for the organisation API key. */
  actor: Member | null = null,
): Promise<ImportResult> {
  const memberships = (body.groups ?? []).reduce(
    (n, g) => n + (g.memberExternalIds?.length ?? 0),
    0,
  )
  if (memberships > MAX_MEMBERSHIPS) {
    throw new ApiError(400, `An import takes at most ${MAX_MEMBERSHIPS} group memberships.`)
  }
  const outranks = (m: Member) => {
    if (!actor) return false
    try {
      assertCanAssign(actor, m.atype)
      return false
    } catch {
      return true
    }
  }
  const db = createDb(c.env.DB)
  const org = await requireOrg(db, orgUuid)
  const now = Date.now()
  const ev = (e: Parameters<typeof eventStatement>[2]) =>
    eventStatement(db, c, { ...e, organizationUuid: orgUuid, systemUser })
  const result: ImportResult = {
    invited: 0,
    linked: 0,
    removed: 0,
    groupsCreated: 0,
    groupsUpdated: 0,
    groupsDeleted: 0,
  }

  const rows = await db
    .select({ m: schema.usersOrganizations, email: schema.users.email })
    .from(schema.usersOrganizations)
    .leftJoin(schema.users, eq(schema.users.uuid, schema.usersOrganizations.userUuid))
    .where(eq(schema.usersOrganizations.organizationUuid, orgUuid))
  const byExternal = new Map<string, Member>()
  const byEmail = new Map<string, Member>()
  for (const r of rows) {
    if (r.m.externalId) byExternal.set(r.m.externalId, r.m)
    const email = r.email ?? r.m.email
    if (email) byEmail.set(normalizeEmail(email), r.m)
  }

  const statements: unknown[] = []
  const invited: Member[] = []
  const removed = new Set<string>()
  const remove = (m: Member) => {
    // Owners are never removed; admins and custom members only on explicit request.
    const privileged = m.atype === Role.Owner || m.atype === Role.Admin || m.atype === Role.Custom
    if (removed.has(m.uuid) || m.atype === Role.Owner || outranks(m)) return
    if (privileged && body.removePrivilegedMembers !== true) return
    removed.add(m.uuid)
    statements.push(
      ...(m.userUuid ? dropMemberStateFor(db, m.userUuid, orgUuid) : []),
      db.delete(schema.usersOrganizations).where(eq(schema.usersOrganizations.uuid, m.uuid)),
      ev({
        type: EventType.OrganizationUserRemoved,
        organizationUserUuid: m.uuid,
        userUuid: m.userUuid,
      }),
    )
  }

  // ----- members -----
  const importedExternal = new Set<string>()
  for (const entry of body.members ?? []) {
    const existing = byExternal.get(entry.externalId)
    if (entry.deleted) {
      if (existing) remove(existing)
      continue
    }
    importedExternal.add(entry.externalId)
    if (existing) continue
    const email = entry.email ? normalizeEmail(entry.email) : ''
    if (!email.includes('@')) continue
    const byMail = byEmail.get(email)
    if (byMail) {
      // Linking re-keys a member: not for anyone ranked above the actor.
      if (byMail.externalId !== entry.externalId && !outranks(byMail)) {
        statements.push(
          db
            .update(schema.usersOrganizations)
            .set({ externalId: entry.externalId, updatedAt: now })
            .where(eq(schema.usersOrganizations.uuid, byMail.uuid)),
        )
        if (byMail.externalId) byExternal.delete(byMail.externalId)
        byMail.externalId = entry.externalId
        byExternal.set(entry.externalId, byMail)
        result.linked++
      }
      continue
    }
    if (invited.length >= MAX_INVITES) {
      throw new ApiError(400, `An import invites at most ${MAX_INVITES} new members at a time.`)
    }
    const m = await invitedMember(db, orgUuid, { email, externalId: entry.externalId })
    byEmail.set(email, m)
    byExternal.set(entry.externalId, m)
    invited.push(m)
    statements.push(
      ...insertMemberStatements(db, m, `organization:${orgUuid}`),
      ev({
        type: EventType.OrganizationUserInvited,
        organizationUserUuid: m.uuid,
        userUuid: m.userUuid,
      }),
    )
  }
  if (body.overwriteExisting) {
    for (const r of rows) {
      if (r.m.externalId && !importedExternal.has(r.m.externalId)) remove(r.m)
    }
  }
  result.invited = invited.length
  result.removed = removed.size

  // ----- groups -----
  const groups = await db
    .select()
    .from(schema.groups)
    .where(eq(schema.groups.organizationUuid, orgUuid))
  const groupsByExternal = new Map(groups.filter((g) => g.externalId).map((g) => [g.externalId, g]))
  const importedGroups = new Set<string>()
  for (const g of body.groups ?? []) {
    importedGroups.add(g.externalId)
    const memberUuids = [
      ...new Set(
        (g.memberExternalIds ?? [])
          .map((x) => byExternal.get(x))
          .filter((m): m is Member => !!m && !removed.has(m.uuid))
          .map((m) => m.uuid),
      ),
    ]
    const existing = groupsByExternal.get(g.externalId)
    const groupUuid = existing?.uuid ?? crypto.randomUUID()
    if (existing) {
      statements.push(
        db
          .update(schema.groups)
          .set({ name: g.name, updatedAt: now })
          .where(eq(schema.groups.uuid, groupUuid)),
        db.delete(schema.groupsUsers).where(eq(schema.groupsUsers.groupUuid, groupUuid)),
        ev({ type: EventType.GroupUpdated, groupUuid }),
      )
      result.groupsUpdated++
    } else {
      statements.push(
        db.insert(schema.groups).values({
          uuid: groupUuid,
          organizationUuid: orgUuid,
          name: g.name,
          accessAll: false,
          externalId: g.externalId,
          createdAt: now,
          updatedAt: now,
        }),
        ev({ type: EventType.GroupCreated, groupUuid }),
      )
      result.groupsCreated++
    }
    for (const m of memberUuids) {
      statements.push(db.insert(schema.groupsUsers).values({ groupUuid, organizationUserUuid: m }))
    }
  }
  if (body.overwriteExisting) {
    for (const g of groups) {
      if (g.externalId && !importedGroups.has(g.externalId)) {
        statements.push(
          db.delete(schema.groups).where(eq(schema.groups.uuid, g.uuid)),
          ev({ type: EventType.GroupDeleted, groupUuid: g.uuid }),
        )
        result.groupsDeleted++
      }
    }
  }

  if (statements.length === 0) return result
  // Revision bump first: removed members must resync too.
  // Slices commit one by one, so a failure part way leaves some changes in place. Members match
  // by external id or email and groups by external id, so repeating the same call finishes the
  // job. The revision is bumped before the first slice and after the last.
  await runSliced(db, [bumpOrgRevision(db, orgUuid, now), ...statements])
  await batch(db, [bumpOrgRevision(db, orgUuid, Date.now())])
  if (body.inviteUsersAfterProvisioning !== false) {
    for (const m of invited) await sendInvite(c, org, m)
  }
  return result
}
