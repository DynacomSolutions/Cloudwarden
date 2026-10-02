// Directory import (TASKS #272): `POST /public/organization/import`, the request the Bitwarden
// Directory Connector sends after reading users and groups from LDAP, Entra ID, Google, Okta or
// OneLogin. Members are matched by external id, then by email; new ones are invited. Groups are
// matched by external id and their membership replaced. With `overwriteExisting`, members and
// groups that carry an external id absent from the import are removed. Owners are never removed.
import { eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { z } from 'zod'
import { normalizeEmail } from '../auth/users'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { sendInvite } from '../routes/org-users'
import { chunk } from '../vault/ciphers'
import { bumpOrgRevision, type Member, requireOrg } from './access'
import { EventType, Role } from './constants'
import { eventStatement } from './events'
import { insertMemberStatements, invitedMember } from './provisioning'
import { batch } from './util'

export const MAX_IMPORT = 10_000

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
})
export type ImportRequest = z.infer<typeof importSchema>

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
): Promise<ImportResult> {
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
    if (m.atype === Role.Owner || removed.has(m.uuid)) return
    removed.add(m.uuid)
    statements.push(
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
      if (byMail.externalId !== entry.externalId) {
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
  await runSliced(db, [bumpOrgRevision(db, orgUuid, now), ...statements])
  if (body.inviteUsersAfterProvisioning !== false) {
    for (const m of invited) await sendInvite(c, org, m)
  }
  return result
}
