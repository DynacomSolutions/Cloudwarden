// Secrets Manager access decisions (TASKS #220). See docs/secrets-manager.md for the model.
import { and, eq, inArray, or, type SQL } from 'drizzle-orm'
import type { Context } from 'hono'
import { type Db, schema } from '../db'
import type { Env, SmActor } from '../env'
import { ApiError } from '../errors'
import { Role, Status } from '../orgs/constants'

export interface Rw {
  read: boolean
  write: boolean
}
export const NONE: Rw = { read: false, write: false }
const FULL: Rw = { read: true, write: true }
const merge = (a: Rw | undefined, b: Rw): Rw => ({
  read: (a?.read ?? false) || b.read || b.write,
  write: (a?.write ?? false) || b.write,
})

export type Policy = typeof schema.smAccessPolicies.$inferSelect

/** The caller inside one organisation, with every access policy that names them. */
export interface SmContext {
  orgUuid: string
  actor: SmActor
  /** Owners and admins with Secrets Manager access see and change everything. */
  admin: boolean
  /** The caller's membership (users only). */
  memberUuid: string | null
  groupUuids: string[]
  serviceAccountUuid: string | null
  projects: Map<string, Rw>
  secrets: Map<string, Rw>
  serviceAccounts: Map<string, Rw>
}

export const notFound = (what = 'Resource') => new ApiError(404, `${what} not found.`)
export const forbidden = () => new ApiError(403, 'You do not have permission to do this.')

export const actorOf = (c: Context<Env>): SmActor => {
  const a = c.var.sm
  if (!a) throw new ApiError(401, 'Unauthorized')
  return a
}

/** Throws 404 unless the caller is a member (users only); machine accounts are refused. */
export function requireUser(ctx: SmContext) {
  if (ctx.actor.kind !== 'user') throw notFound()
}

/**
 * Loads the caller's context in `orgUuid`. Users must be confirmed members with
 * `accessSecretsManager`; machine accounts only reach their own organisation. Anything else is a
 * 404 so organisations stay invisible to outsiders.
 */
export async function loadContext(db: Db, actor: SmActor, orgUuid: string): Promise<SmContext> {
  const ctx: SmContext = {
    orgUuid,
    actor,
    admin: false,
    memberUuid: null,
    groupUuids: [],
    serviceAccountUuid: null,
    projects: new Map(),
    secrets: new Map(),
    serviceAccounts: new Map(),
  }
  const grantees: SQL[] = []
  if (actor.kind === 'machine') {
    if (actor.organizationUuid !== orgUuid) throw notFound('Organization')
    ctx.serviceAccountUuid = actor.serviceAccountUuid
    grantees.push(eq(schema.smAccessPolicies.serviceAccountUuid, actor.serviceAccountUuid))
  } else {
    const uo = schema.usersOrganizations
    const [m] = await db
      .select()
      .from(uo)
      .where(and(eq(uo.userUuid, actor.user.uuid), eq(uo.organizationUuid, orgUuid)))
      .limit(1)
    if (!m || m.status !== Status.Confirmed || !m.accessSecretsManager) {
      throw notFound('Organization')
    }
    ctx.memberUuid = m.uuid
    ctx.admin = m.atype === Role.Owner || m.atype === Role.Admin
    const groups = await db
      .select({ g: schema.groupsUsers.groupUuid })
      .from(schema.groupsUsers)
      .where(eq(schema.groupsUsers.organizationUserUuid, m.uuid))
    ctx.groupUuids = groups.map((g) => g.g)
    grantees.push(eq(schema.smAccessPolicies.organizationUserUuid, m.uuid))
    if (ctx.groupUuids.length) {
      grantees.push(inArray(schema.smAccessPolicies.groupUuid, ctx.groupUuids))
    }
  }
  if (ctx.admin) return ctx
  const rows = await db
    .select()
    .from(schema.smAccessPolicies)
    .where(and(eq(schema.smAccessPolicies.organizationUuid, orgUuid), or(...grantees)))
  for (const p of rows) {
    const rw = { read: p.read, write: p.write }
    if (p.grantedProjectUuid) {
      ctx.projects.set(p.grantedProjectUuid, merge(ctx.projects.get(p.grantedProjectUuid), rw))
    }
    if (p.grantedSecretUuid) {
      ctx.secrets.set(p.grantedSecretUuid, merge(ctx.secrets.get(p.grantedSecretUuid), rw))
    }
    if (p.grantedServiceAccountUuid) {
      const k = p.grantedServiceAccountUuid
      ctx.serviceAccounts.set(k, merge(ctx.serviceAccounts.get(k), rw))
    }
  }
  return ctx
}

export const projectAccess = (ctx: SmContext, projectUuid: string): Rw =>
  ctx.admin ? FULL : (ctx.projects.get(projectUuid) ?? NONE)

/** A secret is reachable through a direct policy or through any project it belongs to. */
export function secretAccess(ctx: SmContext, secretUuid: string, projectUuids: string[]): Rw {
  if (ctx.admin) return FULL
  let rw = ctx.secrets.get(secretUuid) ?? NONE
  for (const p of projectUuids) rw = merge(rw, projectAccess(ctx, p))
  return rw
}

/** Machine accounts never manage machine accounts. */
export const serviceAccountAccess = (ctx: SmContext, saUuid: string): Rw =>
  ctx.actor.kind !== 'user' ? NONE : ctx.admin ? FULL : (ctx.serviceAccounts.get(saUuid) ?? NONE)

/** Policy granting the caller full access to something it just created (non-admins only). */
export function creatorPolicy(
  db: Db,
  ctx: SmContext,
  granted: { project?: string; serviceAccount?: string },
  now: number,
) {
  if (ctx.admin) return []
  return [
    db.insert(schema.smAccessPolicies).values({
      uuid: crypto.randomUUID(),
      organizationUuid: ctx.orgUuid,
      organizationUserUuid: ctx.memberUuid,
      serviceAccountUuid: ctx.memberUuid ? null : ctx.serviceAccountUuid,
      grantedProjectUuid: granted.project ?? null,
      grantedServiceAccountUuid: granted.serviceAccount ?? null,
      read: true,
      write: true,
      createdAt: now,
      updatedAt: now,
    }),
  ]
}

/** Marks Secrets Manager data of the organisation as changed (drives `secrets/sync`). */
export const bumpSecretsRevision = (db: Db, orgUuid: string, now: number) =>
  db
    .update(schema.organizations)
    .set({ secretsRevisionDate: now })
    .where(eq(schema.organizations.uuid, orgUuid))

/** Event fields naming the caller: acting user, or acting machine account. */
export const actorEventFields = (ctx: SmContext) =>
  ctx.actor.kind === 'machine'
    ? { actingUserUuid: null, serviceAccountUuid: ctx.actor.serviceAccountUuid }
    : {}
