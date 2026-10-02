// Shared member provisioning for the Public API, directory import and SCIM (TASKS #271 to #273).
import { and, eq } from 'drizzle-orm'
import { normalizeEmail } from '../auth/users'
import { type Db, schema } from '../db'
import type { Member } from './access'
import { Role, Status } from './constants'

export interface NewMember {
  email: string
  type?: number
  accessAll?: boolean
  externalId?: string | null
  permissions?: string | null
}

/** An invited member row for `email`, linked to the account when one exists. */
export async function invitedMember(db: Db, orgUuid: string, input: NewMember): Promise<Member> {
  const email = normalizeEmail(input.email)
  const [account] = await db
    .select({ uuid: schema.users.uuid })
    .from(schema.users)
    .where(eq(schema.users.email, email))
    .limit(1)
  const now = Date.now()
  return {
    uuid: crypto.randomUUID(),
    userUuid: account?.uuid ?? null,
    organizationUuid: orgUuid,
    email,
    permissions: input.permissions ?? null,
    accessAll: input.accessAll === true,
    akey: '',
    status: Status.Invited,
    atype: input.type ?? Role.User,
    resetPasswordKey: null,
    externalId: input.externalId ?? null,
    accessSecretsManager: false,
    accessPam: false,
    createdAt: now,
    updatedAt: now,
  }
}

/** Statements that store an invited member (and let an address without an account register). */
export function insertMemberStatements(db: Db, m: Member, invitedBy: string) {
  return [
    db.insert(schema.usersOrganizations).values(m),
    ...(m.userUuid
      ? []
      : [
          db
            .insert(schema.invitations)
            .values({
              uuid: crypto.randomUUID(),
              email: m.email as string,
              invitedBy,
              createdAt: m.createdAt,
            })
            .onConflictDoNothing(),
        ]),
  ]
}

/** The member of `orgUuid` with this email, if any. */
export async function memberByEmail(db: Db, orgUuid: string, email: string) {
  const [m] = await db
    .select()
    .from(schema.usersOrganizations)
    .where(
      and(
        eq(schema.usersOrganizations.organizationUuid, orgUuid),
        eq(schema.usersOrganizations.email, normalizeEmail(email)),
      ),
    )
    .limit(1)
  return m
}

/** Status a revoked member returns to: invited, accepted or confirmed depending on progress. */
export const statusOnRestore = (m: Member) =>
  !m.userUuid ? Status.Invited : m.akey === '' ? Status.Accepted : Status.Confirmed

/** A stand-in actor with admin authority for API-driven changes (never assigns owners). */
export const systemActor = (orgUuid: string): Member => ({
  uuid: '00000000-0000-0000-0000-000000000000',
  userUuid: null,
  organizationUuid: orgUuid,
  email: null,
  permissions: null,
  accessAll: true,
  akey: '',
  status: Status.Confirmed,
  atype: Role.Admin,
  resetPasswordKey: null,
  externalId: null,
  accessSecretsManager: false,
  accessPam: false,
  createdAt: 0,
  updatedAt: 0,
})
