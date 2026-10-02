// Secrets Manager API (TASKS #220): projects, secrets, machine accounts, access tokens, access
// policies, counts and events. Paths and shapes are documented under the `secrets-manager` tag in
// docs/api/openapi.yaml; the access model is in docs/secrets-manager.md.
import { and, desc, eq, inArray, isNotNull, isNull, or, sql } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { sha256B64u } from '../auth/crypto'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { EventType, Status } from '../orgs/constants'
import { eventStatement, listEvents } from '../orgs/events'
import { batch } from '../orgs/util'
import {
  actorEventFields,
  actorOf,
  bumpSecretsRevision,
  creatorPolicy,
  forbidden,
  loadContext,
  notFound,
  type Policy,
  projectAccess,
  type Rw,
  requireUser,
  type SmContext,
  secretAccess,
  serviceAccountAccess,
} from '../sm/access'
import { isUuid, newClientSecret, requireSmAuth } from '../sm/auth'
import {
  accessTokenJson,
  baseSecretJson,
  findProject,
  findSecret,
  findServiceAccount,
  inChunks,
  list,
  type ProjectRef,
  projectJson,
  projectsOfSecrets,
  type Secret,
  secretJson,
  secretListJson,
  serviceAccountJson,
} from '../sm/data'
import { parseBody } from '../validation'

export const secretsManager = new Hono<Env>()
type Ctx = Context<Env>

for (const path of [
  '/api/organizations/:orgId/projects',
  '/api/organizations/:orgId/secrets',
  '/api/organizations/:orgId/secrets/*',
  '/api/organizations/:orgId/service-accounts',
  '/api/organizations/:orgId/sm-counts',
  '/api/organizations/:orgId/access-policies/*',
  '/api/organization/:orgId/*',
  '/api/projects/*',
  '/api/secrets/*',
  '/api/secret-versions/*',
  '/api/service-accounts/*',
  '/api/sm/*',
]) {
  secretsManager.use(path, requireSmAuth)
}

const MAX_BULK = 500
const enc = (max: number) => z.string().min(1).max(max)
const nameSchema = z.object({ name: enc(1000) })
const idList = z.array(z.string()).min(1).max(MAX_BULK)
const policyRequest = z.object({ granteeId: z.string(), read: z.boolean(), write: z.boolean() })
const policyList = z.array(policyRequest).max(MAX_BULK).nullish()

const db_ = (c: Ctx) => createDb(c.env.DB)
const param = (c: Ctx, name: string) => {
  const v = c.req.param(name) ?? ''
  if (!isUuid(v)) throw notFound()
  return v.toLowerCase()
}
// Membership, SM access and policies decide access, so they are always read from the primary
// (docs/d1-sessions.md), whatever handle the route uses for its own reads.
const ctxFor = (c: Ctx, _db: Db, orgUuid: string) =>
  loadContext(createDb(c.env.DB_PRIMARY ?? c.env.DB), actorOf(c), orgUuid)

/** Read access or 404; write access or 403 (the caller can see it but not change it). */
function check(rw: Rw, need: 'read' | 'write', what: string) {
  if (!rw.read && !rw.write) throw notFound(what)
  if (need === 'write' && !rw.write) throw forbidden()
}

// ----- projects -----

secretsManager.post('/api/organizations/:orgId/projects', async (c) => {
  const body = await parseBody(c, nameSchema)
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  const now = Date.now()
  const uuid = crypto.randomUUID()
  await batch(db, [
    db.insert(schema.smProjects).values({
      uuid,
      organizationUuid: ctx.orgUuid,
      name: body.name,
      createdAt: now,
      updatedAt: now,
    }),
    ...creatorPolicy(db, ctx, { project: uuid }, now),
    bumpSecretsRevision(db, ctx.orgUuid, now),
    eventStatement(db, c, {
      type: EventType.ProjectCreated,
      organizationUuid: ctx.orgUuid,
      projectUuid: uuid,
      ...actorEventFields(ctx),
    }),
  ])
  return c.json(projectJson(await findProject(db, uuid), { read: true, write: true }))
})

secretsManager.get('/api/organizations/:orgId/projects', async (c) => {
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  const rows = await db
    .select()
    .from(schema.smProjects)
    .where(eq(schema.smProjects.organizationUuid, ctx.orgUuid))
  return c.json(
    list(
      rows
        .map((p) => ({ p, rw: projectAccess(ctx, p.uuid) }))
        .filter((x) => x.rw.read)
        .map((x) => projectJson(x.p, x.rw)),
    ),
  )
})

secretsManager.get('/api/projects/:id', async (c) => {
  const db = db_(c)
  const p = await findProject(db, param(c, 'id'))
  const ctx = await ctxFor(c, db, p.organizationUuid)
  const rw = projectAccess(ctx, p.uuid)
  check(rw, 'read', 'Project')
  return c.json(projectJson(p, rw))
})

secretsManager.put('/api/projects/:id', async (c) => {
  const body = await parseBody(c, nameSchema)
  const db = db_(c)
  const p = await findProject(db, param(c, 'id'))
  const ctx = await ctxFor(c, db, p.organizationUuid)
  check(projectAccess(ctx, p.uuid), 'write', 'Project')
  const now = Date.now()
  await batch(db, [
    db
      .update(schema.smProjects)
      .set({ name: body.name, updatedAt: now })
      .where(eq(schema.smProjects.uuid, p.uuid)),
    bumpSecretsRevision(db, ctx.orgUuid, now),
    eventStatement(db, c, {
      type: EventType.ProjectEdited,
      organizationUuid: ctx.orgUuid,
      projectUuid: p.uuid,
      ...actorEventFields(ctx),
    }),
  ])
  return c.json(projectJson(await findProject(db, p.uuid), projectAccess(ctx, p.uuid)))
})

type Deletable = { uuid: string; organizationUuid: string }

/**
 * Shared bulk delete: every id gets a `bulkDeleteResponse` row, with `error` set when it does not
 * exist or the caller may not delete it. Allowed rows are deleted in one batch.
 */
async function bulkDelete<T extends Deletable>(
  c: Ctx,
  ids: string[],
  load: (db: Db, uuids: string[]) => Promise<T[]>,
  allowed: (ctx: SmContext, row: T) => Promise<boolean> | boolean,
  statements: (db: Db, ctx: SmContext, rows: T[], now: number) => unknown[],
) {
  const db = db_(c)
  const uuids = [...new Set(ids.filter(isUuid).map((s) => s.toLowerCase()))]
  const rows = new Map((await load(db, uuids)).map((r) => [r.uuid, r]))
  const contexts = new Map<string, SmContext | null>()
  const ok = new Map<string, T[]>()
  const out: { object: string; id: string; error: string | null }[] = []
  for (const id of ids) {
    const row = rows.get(id.toLowerCase())
    let ctx: SmContext | null = null
    if (row) {
      if (!contexts.has(row.organizationUuid)) {
        contexts.set(
          row.organizationUuid,
          await ctxFor(c, db, row.organizationUuid).catch((e) => {
            if (e instanceof ApiError) return null
            throw e
          }),
        )
      }
      ctx = contexts.get(row.organizationUuid) ?? null
    }
    const permitted = row && ctx ? await allowed(ctx, row) : false
    if (row && permitted && !(ok.get(row.organizationUuid) ?? []).includes(row)) {
      ok.set(row.organizationUuid, [...(ok.get(row.organizationUuid) ?? []), row])
    }
    out.push({ object: 'bulkDeleteResponse', id, error: permitted ? null : 'access denied' })
  }
  const now = Date.now()
  const all: unknown[] = []
  for (const [org, list_] of ok) {
    const ctx = contexts.get(org) as SmContext
    all.push(...statements(db, ctx, list_, now), bumpSecretsRevision(db, org, now))
  }
  await batch(db, all)
  return c.json(list(out))
}

secretsManager.post('/api/projects/delete', async (c) =>
  bulkDelete(
    c,
    await parseBody(c, idList),
    (db, ids) =>
      inChunks(ids, (part) =>
        db.select().from(schema.smProjects).where(inArray(schema.smProjects.uuid, part)),
      ),
    (ctx, p) => projectAccess(ctx, p.uuid).write,
    (db, ctx, rows) =>
      rows.flatMap((p) => [
        db.delete(schema.smProjects).where(eq(schema.smProjects.uuid, p.uuid)),
        eventStatement(db, c, {
          type: EventType.ProjectDeleted,
          organizationUuid: ctx.orgUuid,
          projectUuid: p.uuid,
          ...actorEventFields(ctx),
        }),
      ]),
  ),
)

// ----- secrets -----

const accessPoliciesRequests = z
  .object({
    userAccessPolicyRequests: policyList,
    groupAccessPolicyRequests: policyList,
    serviceAccountAccessPolicyRequests: policyList,
  })
  .nullish()

const secretSchema = z.object({
  key: enc(10_000),
  value: enc(100_000),
  note: z.string().max(100_000).nullish(),
  projectIds: z.array(z.string()).max(1, 'A secret can belong to one project.').nullish(),
  accessPoliciesRequests,
  valueChanged: z.boolean().nullish(),
})

/** Validates that each project exists in the organisation and the caller may write to it. */
async function writableProjects(db: Db, ctx: SmContext, ids: string[]) {
  const uuids = [...new Set(ids.map((s) => s.toLowerCase()))]
  if (!uuids.every(isUuid)) throw new ApiError(400, 'Invalid project id.')
  const rows = uuids.length
    ? await db.select().from(schema.smProjects).where(inArray(schema.smProjects.uuid, uuids))
    : []
  if (rows.length !== uuids.length || rows.some((p) => p.organizationUuid !== ctx.orgUuid)) {
    throw notFound('Project')
  }
  for (const p of rows) check(projectAccess(ctx, p.uuid), 'write', 'Project')
  // Only owners and admins may keep secrets outside any project.
  if (uuids.length === 0 && !ctx.admin) throw forbidden()
  return uuids
}

type Grantee = 'user' | 'group' | 'serviceAccount'

/** Checks every grantee belongs to the organisation (members need Secrets Manager access). */
async function validateGrantees(db: Db, ctx: SmContext, kind: Grantee, ids: string[]) {
  const uuids = [...new Set(ids.map((s) => s.toLowerCase()))]
  if (uuids.length === 0) return uuids
  if (!uuids.every(isUuid)) throw new ApiError(400, `Invalid ${kind} id.`)
  let found: { uuid: string }[]
  if (kind === 'user') {
    const uo = schema.usersOrganizations
    found = await db
      .select({ uuid: uo.uuid })
      .from(uo)
      .where(
        and(
          inArray(uo.uuid, uuids),
          eq(uo.organizationUuid, ctx.orgUuid),
          eq(uo.accessSecretsManager, true),
          eq(uo.status, Status.Confirmed),
        ),
      )
  } else if (kind === 'group') {
    found = await db
      .select({ uuid: schema.groups.uuid })
      .from(schema.groups)
      .where(
        and(inArray(schema.groups.uuid, uuids), eq(schema.groups.organizationUuid, ctx.orgUuid)),
      )
  } else {
    found = await db
      .select({ uuid: schema.smServiceAccounts.uuid })
      .from(schema.smServiceAccounts)
      .where(
        and(
          inArray(schema.smServiceAccounts.uuid, uuids),
          eq(schema.smServiceAccounts.organizationUuid, ctx.orgUuid),
        ),
      )
    // Granting a machine account access needs access to that machine account.
    for (const id of uuids)
      if (!serviceAccountAccess(ctx, id).read) throw notFound('Service account')
  }
  if (found.length !== uuids.length) throw new ApiError(400, `Unknown ${kind} in access policies.`)
  return uuids
}

type Granted = { project?: string; secret?: string; serviceAccount?: string }
const grantedColumn = (g: Granted) =>
  g.project
    ? eq(schema.smAccessPolicies.grantedProjectUuid, g.project)
    : g.secret
      ? eq(schema.smAccessPolicies.grantedSecretUuid, g.secret)
      : eq(schema.smAccessPolicies.grantedServiceAccountUuid, g.serviceAccount ?? '')

/** Statements replacing the policies of `kind` on one granted object. */
async function replacePolicies(
  db: Db,
  ctx: SmContext,
  granted: Granted,
  kind: Grantee,
  requests: z.infer<typeof policyRequest>[],
  now: number,
) {
  const byId = new Map(requests.map((r) => [r.granteeId.toLowerCase(), r]))
  const ids = await validateGrantees(db, ctx, kind, [...byId.keys()])
  const granteeOf = (p: Policy) =>
    kind === 'user' ? p.organizationUserUuid : kind === 'group' ? p.groupUuid : p.serviceAccountUuid
  const before = (
    await db
      .select()
      .from(schema.smAccessPolicies)
      .where(and(grantedColumn(granted), eq(schema.smAccessPolicies.organizationUuid, ctx.orgUuid)))
  ).filter((p) => granteeOf(p) !== null)
  const statements: unknown[] = before.length
    ? [
        db.delete(schema.smAccessPolicies).where(
          inArray(
            schema.smAccessPolicies.uuid,
            before.map((p) => p.uuid),
          ),
        ),
      ]
    : []
  for (const id of ids) {
    const r = byId.get(id) as z.infer<typeof policyRequest>
    if (!r.read && !r.write) continue
    statements.push(
      db.insert(schema.smAccessPolicies).values({
        uuid: crypto.randomUUID(),
        organizationUuid: ctx.orgUuid,
        organizationUserUuid: kind === 'user' ? id : null,
        groupUuid: kind === 'group' ? id : null,
        serviceAccountUuid: kind === 'serviceAccount' ? id : null,
        grantedProjectUuid: granted.project ?? null,
        grantedSecretUuid: granted.secret ?? null,
        grantedServiceAccountUuid: granted.serviceAccount ?? null,
        read: r.read || r.write,
        write: r.write,
        createdAt: now,
        updatedAt: now,
      }),
    )
  }
  const beforeIds = new Set(before.map(granteeOf))
  const afterIds = new Set(ids.filter((id) => byId.get(id)?.read || byId.get(id)?.write))
  return {
    statements,
    added: [...afterIds].filter((id) => !beforeIds.has(id)),
    removed: [...beforeIds].filter((id): id is string => id !== null && !afterIds.has(id)),
  }
}

async function secretPolicyStatements(
  db: Db,
  ctx: SmContext,
  secretUuid: string,
  req: z.infer<typeof accessPoliciesRequests>,
  now: number,
) {
  if (!req) return []
  if (ctx.actor.kind !== 'user') throw forbidden()
  const out: unknown[] = []
  const parts: [Grantee, z.infer<typeof policyList>][] = [
    ['user', req.userAccessPolicyRequests],
    ['group', req.groupAccessPolicyRequests],
    ['serviceAccount', req.serviceAccountAccessPolicyRequests],
  ]
  for (const [kind, requests] of parts) {
    if (requests == null) continue
    out.push(
      ...(await replacePolicies(db, ctx, { secret: secretUuid }, kind, requests, now)).statements,
    )
  }
  return out
}

const projectLinks = (db: Db, secretUuid: string, projectUuids: string[]) =>
  projectUuids.map((p) =>
    db.insert(schema.smSecretsProjects).values({ secretUuid, projectUuid: p }),
  )

secretsManager.post('/api/organizations/:orgId/secrets', async (c) => {
  const body = await parseBody(c, secretSchema)
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  const projects = await writableProjects(db, ctx, body.projectIds ?? [])
  const now = Date.now()
  const uuid = crypto.randomUUID()
  const policies = await secretPolicyStatements(db, ctx, uuid, body.accessPoliciesRequests, now)
  await batch(db, [
    db.insert(schema.smSecrets).values({
      uuid,
      organizationUuid: ctx.orgUuid,
      key: body.key,
      value: body.value,
      note: body.note ?? '',
      createdAt: now,
      updatedAt: now,
    }),
    ...projectLinks(db, uuid, projects),
    ...policies,
    bumpSecretsRevision(db, ctx.orgUuid, now),
    eventStatement(db, c, {
      type: EventType.SecretCreated,
      organizationUuid: ctx.orgUuid,
      secretUuid: uuid,
      ...actorEventFields(ctx),
    }),
  ])
  return c.json(await secretResponse(db, ctx, await findSecret(db, uuid)))
})

async function secretResponse(db: Db, ctx: SmContext, s: Secret) {
  const projects = (await projectsOfSecrets(db, [s.uuid])).get(s.uuid) ?? []
  return secretJson(
    s,
    projects,
    secretAccess(
      ctx,
      s.uuid,
      projects.map((p) => p.id),
    ),
  )
}

/** Secrets of the organisation the caller can read, each with its projects and access. */
async function readableSecrets(db: Db, ctx: SmContext, only?: string[]) {
  const rows = only
    ? await inChunks(only, (part) =>
        db.select().from(schema.smSecrets).where(inArray(schema.smSecrets.uuid, part)),
      )
    : await db
        .select()
        .from(schema.smSecrets)
        .where(eq(schema.smSecrets.organizationUuid, ctx.orgUuid))
  const projects = await projectsOfSecrets(
    db,
    rows.map((s) => s.uuid),
  )
  return rows
    .filter((s) => s.organizationUuid === ctx.orgUuid && s.deletedAt === null)
    .map((s) => {
      const p = projects.get(s.uuid) ?? []
      return {
        s,
        projects: p,
        rw: secretAccess(
          ctx,
          s.uuid,
          p.map((x) => x.id),
        ),
      }
    })
    .filter((x) => x.rw.read)
}

/** Machine accounts reading secret values are recorded (event 2100). */
async function recordRetrieval(c: Ctx, db: Db, ctx: SmContext, secrets: { uuid: string }[]) {
  if (ctx.actor.kind !== 'machine' || secrets.length === 0) return
  await batch(
    db,
    secrets.map((s) =>
      eventStatement(db, c, {
        type: EventType.SecretRetrieved,
        organizationUuid: ctx.orgUuid,
        secretUuid: s.uuid,
        ...actorEventFields(ctx),
      }),
    ),
  )
}

secretsManager.get('/api/organizations/:orgId/secrets/sync', async (c) => {
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  const [org] = await db
    .select()
    .from(schema.organizations)
    .where(eq(schema.organizations.uuid, ctx.orgUuid))
  const last = Date.parse(c.req.query('lastSyncedDate') ?? '')
  const revision = org?.secretsRevisionDate ?? org?.createdAt ?? 0
  if (Number.isFinite(last) && revision <= last) {
    return c.json({ object: 'secretsSync', hasChanges: false, secrets: null })
  }
  const rows = await readableSecrets(db, ctx)
  await recordRetrieval(
    c,
    db,
    ctx,
    rows.map((r) => r.s),
  )
  return c.json({
    object: 'secretsSync',
    hasChanges: true,
    secrets: list(rows.map((r) => baseSecretJson(r.s, r.projects))),
  })
})

/** `SecretWithProjectsListResponseModel`: secrets without values, plus the readable projects. */
async function secretsWithProjects(db: Db, ctx: SmContext, projectUuid?: string) {
  let rows = await readableSecrets(db, ctx)
  if (projectUuid) rows = rows.filter((r) => r.projects.some((p) => p.id === projectUuid))
  const projects = await db
    .select()
    .from(schema.smProjects)
    .where(eq(schema.smProjects.organizationUuid, ctx.orgUuid))
  return {
    object: 'SecretsWithProjectsList',
    secrets: rows.map((r) => secretListJson(r.s, r.projects, r.rw)),
    projects: projects
      .filter((p) => projectAccess(ctx, p.uuid).read)
      .map((p): ProjectRef => ({ id: p.uuid, name: p.name })),
  }
}

secretsManager.get('/api/organizations/:orgId/secrets', async (c) => {
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  return c.json(await secretsWithProjects(db, ctx))
})

secretsManager.get('/api/projects/:projectId/secrets', async (c) => {
  const db = db_(c)
  const p = await findProject(db, param(c, 'projectId'))
  const ctx = await ctxFor(c, db, p.organizationUuid)
  check(projectAccess(ctx, p.uuid), 'read', 'Project')
  return c.json(await secretsWithProjects(db, ctx, p.uuid))
})

secretsManager.post('/api/secrets/get-by-ids', async (c) => {
  const { ids } = await parseBody(c, z.object({ ids: idList }))
  const db = db_(c)
  const uuids = [...new Set(ids.map((s) => s.toLowerCase()))]
  if (!uuids.every(isUuid)) throw notFound('Secret')
  const rows = await inChunks(uuids, (part) =>
    db.select().from(schema.smSecrets).where(inArray(schema.smSecrets.uuid, part)),
  )
  const orgs = [...new Set(rows.map((s) => s.organizationUuid))]
  // One organisation per request, like the SDK sends; anything missing or unreadable is a 404.
  if (rows.length !== uuids.length || orgs.length !== 1) throw notFound('Secret')
  const ctx = await ctxFor(c, db, orgs[0] as string)
  const readable = await readableSecrets(db, ctx, uuids)
  if (readable.length !== uuids.length) throw notFound('Secret')
  await recordRetrieval(
    c,
    db,
    ctx,
    readable.map((r) => r.s),
  )
  return c.json(list(readable.map((r) => baseSecretJson(r.s, r.projects))))
})

secretsManager.post('/api/secrets/delete', async (c) =>
  bulkDelete(
    c,
    await parseBody(c, idList),
    (db, ids) =>
      inChunks(ids, (part) =>
        db
          .select()
          .from(schema.smSecrets)
          .where(and(inArray(schema.smSecrets.uuid, part), isNull(schema.smSecrets.deletedAt))),
      ),
    async (ctx, s) => {
      const projects = (await projectsOfSecrets(createDb(c.env.DB), [s.uuid])).get(s.uuid) ?? []
      return secretAccess(
        ctx,
        s.uuid,
        projects.map((p) => p.id),
      ).write
    },
    (db, ctx, rows, now) =>
      // Deleting moves the secret to the trash; emptying the trash removes it for good.
      rows.flatMap((s) => [
        db
          .update(schema.smSecrets)
          .set({ deletedAt: now, updatedAt: now })
          .where(eq(schema.smSecrets.uuid, s.uuid)),
        eventStatement(db, c, {
          type: EventType.SecretDeleted,
          organizationUuid: ctx.orgUuid,
          secretUuid: s.uuid,
          ...actorEventFields(ctx),
        }),
      ]),
  ),
)

secretsManager.get('/api/secrets/:id', async (c) => {
  const db = db_(c)
  const s = await findSecret(db, param(c, 'id'))
  const ctx = await ctxFor(c, db, s.organizationUuid)
  const out = await secretResponse(db, ctx, s)
  check(out, 'read', 'Secret')
  await recordRetrieval(c, db, ctx, [s])
  return c.json(out)
})

/** Versions kept per secret; older ones are dropped when a new one is recorded. */
const MAX_VERSIONS = 50

/**
 * Statements recording the value a change replaces, naming the editor. Nothing is recorded when
 * the value stays the same (the clients send `valueChanged`, but the stored value decides).
 */
function versionStatements(db: Db, ctx: SmContext, secret: Secret, newValue: string, now: number) {
  if (newValue === secret.value) return []
  return [
    db.insert(schema.smSecretVersions).values({
      uuid: crypto.randomUUID(),
      secretUuid: secret.uuid,
      value: secret.value,
      versionDate: now,
      editorServiceAccountUuid: ctx.actor.kind === 'machine' ? ctx.serviceAccountUuid : null,
      editorOrganizationUserUuid: ctx.actor.kind === 'user' ? ctx.memberUuid : null,
    }),
    db
      .delete(schema.smSecretVersions)
      .where(
        and(
          eq(schema.smSecretVersions.secretUuid, secret.uuid),
          sql`${schema.smSecretVersions.uuid} not in (select uuid from sm_secret_versions where secret_uuid = ${secret.uuid} order by version_date desc, rowid desc limit ${MAX_VERSIONS})`,
        ),
      ),
  ]
}

secretsManager.put('/api/secrets/:id', async (c) => {
  const body = await parseBody(c, secretSchema)
  const db = db_(c)
  const s = await findSecret(db, param(c, 'id'))
  const ctx = await ctxFor(c, db, s.organizationUuid)
  check(await secretResponse(db, ctx, s), 'write', 'Secret')
  const now = Date.now()
  const projects = body.projectIds == null ? null : await writableProjects(db, ctx, body.projectIds)
  const policies = await secretPolicyStatements(db, ctx, s.uuid, body.accessPoliciesRequests, now)
  await batch(db, [
    ...versionStatements(db, ctx, s, body.value, now),
    db
      .update(schema.smSecrets)
      .set({ key: body.key, value: body.value, note: body.note ?? '', updatedAt: now })
      .where(eq(schema.smSecrets.uuid, s.uuid)),
    ...(projects === null
      ? []
      : [
          db
            .delete(schema.smSecretsProjects)
            .where(eq(schema.smSecretsProjects.secretUuid, s.uuid)),
          ...projectLinks(db, s.uuid, projects),
        ]),
    ...policies,
    bumpSecretsRevision(db, ctx.orgUuid, now),
    eventStatement(db, c, {
      type: EventType.SecretEdited,
      organizationUuid: ctx.orgUuid,
      secretUuid: s.uuid,
      ...actorEventFields(ctx),
    }),
  ])
  return c.json(await secretResponse(db, ctx, await findSecret(db, s.uuid)))
})

// ----- machine accounts (service accounts) and access tokens -----

/** Number of secrets each machine account can read, through projects or direct grants. */
async function accessToSecrets(db: Db, orgUuid: string, saUuids: string[]) {
  const out = new Map<string, number>(saUuids.map((s) => [s, 0]))
  if (saUuids.length === 0) return out
  const policies = await db
    .select()
    .from(schema.smAccessPolicies)
    .where(
      and(
        eq(schema.smAccessPolicies.organizationUuid, orgUuid),
        inArray(schema.smAccessPolicies.serviceAccountUuid, saUuids),
      ),
    )
  const links = await db
    .select({ s: schema.smSecretsProjects.secretUuid, p: schema.smSecretsProjects.projectUuid })
    .from(schema.smSecretsProjects)
    .innerJoin(schema.smSecrets, eq(schema.smSecrets.uuid, schema.smSecretsProjects.secretUuid))
    .where(and(eq(schema.smSecrets.organizationUuid, orgUuid), isNull(schema.smSecrets.deletedAt)))
  for (const sa of saUuids) {
    const mine = policies.filter((p) => p.serviceAccountUuid === sa && p.read)
    const projects = new Set(
      mine.flatMap((p) => (p.grantedProjectUuid ? [p.grantedProjectUuid] : [])),
    )
    const secrets = new Set(mine.flatMap((p) => (p.grantedSecretUuid ? [p.grantedSecretUuid] : [])))
    for (const l of links) if (projects.has(l.p)) secrets.add(l.s)
    out.set(sa, secrets.size)
  }
  return out
}

secretsManager.post('/api/organizations/:orgId/service-accounts', async (c) => {
  const body = await parseBody(c, nameSchema)
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  requireUser(ctx)
  const now = Date.now()
  const uuid = crypto.randomUUID()
  await batch(db, [
    db.insert(schema.smServiceAccounts).values({
      uuid,
      organizationUuid: ctx.orgUuid,
      name: body.name,
      createdAt: now,
      updatedAt: now,
    }),
    ...creatorPolicy(db, ctx, { serviceAccount: uuid }, now),
    eventStatement(db, c, {
      type: EventType.ServiceAccountCreated,
      organizationUuid: ctx.orgUuid,
      grantedServiceAccountUuid: uuid,
    }),
  ])
  return c.json(serviceAccountJson(await findServiceAccount(db, uuid)))
})

secretsManager.get('/api/organizations/:orgId/service-accounts', async (c) => {
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  requireUser(ctx)
  const rows = (
    await db
      .select()
      .from(schema.smServiceAccounts)
      .where(eq(schema.smServiceAccounts.organizationUuid, ctx.orgUuid))
  ).filter((sa) => serviceAccountAccess(ctx, sa.uuid).read)
  const include = c.req.query('includeAccessToSecrets') === 'true'
  const counts = include
    ? await accessToSecrets(
        db,
        ctx.orgUuid,
        rows.map((r) => r.uuid),
      )
    : new Map<string, number>()
  return c.json(
    list(
      rows.map((sa) => ({
        ...serviceAccountJson(sa),
        object: 'serviceAccountSecretsDetails',
        accessToSecrets: counts.get(sa.uuid) ?? 0,
      })),
    ),
  )
})

/** Loads a machine account and checks the caller (a member) has `need` on it. */
async function serviceAccountFor(c: Ctx, db: Db, need: 'read' | 'write', name = 'id') {
  const sa = await findServiceAccount(db, param(c, name))
  const ctx = await ctxFor(c, db, sa.organizationUuid)
  requireUser(ctx)
  check(serviceAccountAccess(ctx, sa.uuid), need, 'Service account')
  return { sa, ctx }
}

secretsManager.post('/api/service-accounts/delete', async (c) =>
  bulkDelete(
    c,
    await parseBody(c, idList),
    (db, ids) =>
      inChunks(ids, (part) =>
        db
          .select()
          .from(schema.smServiceAccounts)
          .where(inArray(schema.smServiceAccounts.uuid, part)),
      ),
    (ctx, sa) => serviceAccountAccess(ctx, sa.uuid).write,
    (db, ctx, rows) =>
      rows.flatMap((sa) => [
        db.delete(schema.smServiceAccounts).where(eq(schema.smServiceAccounts.uuid, sa.uuid)),
        eventStatement(db, c, {
          type: EventType.ServiceAccountDeleted,
          organizationUuid: ctx.orgUuid,
          grantedServiceAccountUuid: sa.uuid,
        }),
      ]),
  ),
)

secretsManager.get('/api/service-accounts/:id', async (c) => {
  const { sa } = await serviceAccountFor(c, db_(c), 'read')
  return c.json(serviceAccountJson(sa))
})

secretsManager.put('/api/service-accounts/:id', async (c) => {
  const body = await parseBody(c, nameSchema)
  const db = db_(c)
  const { sa, ctx } = await serviceAccountFor(c, db, 'write')
  const now = Date.now()
  await batch(db, [
    db
      .update(schema.smServiceAccounts)
      .set({ name: body.name, updatedAt: now })
      .where(eq(schema.smServiceAccounts.uuid, sa.uuid)),
    bumpSecretsRevision(db, ctx.orgUuid, now),
  ])
  return c.json(serviceAccountJson(await findServiceAccount(db, sa.uuid)))
})

secretsManager.get('/api/service-accounts/:id/access-tokens', async (c) => {
  const db = db_(c)
  const { sa } = await serviceAccountFor(c, db, 'write')
  const rows = await db
    .select()
    .from(schema.smAccessTokens)
    .where(eq(schema.smAccessTokens.serviceAccountUuid, sa.uuid))
  return c.json(list(rows.map(accessTokenJson)))
})

/**
 * A token hands out everything the machine account can reach, so a non-admin may mint one only
 * when they can already read every project and secret granted to it (TASKS #220 review).
 */
async function assertCanReachEverything(db: Db, ctx: SmContext, saUuid: string) {
  if (ctx.admin) return
  const policies = await db
    .select()
    .from(schema.smAccessPolicies)
    .where(eq(schema.smAccessPolicies.serviceAccountUuid, saUuid))
  const secretIds = policies.flatMap((p) => (p.grantedSecretUuid ? [p.grantedSecretUuid] : []))
  const projectsOf = await projectsOfSecrets(db, secretIds)
  for (const p of policies) {
    const ok = p.grantedProjectUuid
      ? projectAccess(ctx, p.grantedProjectUuid).read
      : p.grantedSecretUuid
        ? secretAccess(
            ctx,
            p.grantedSecretUuid,
            (projectsOf.get(p.grantedSecretUuid) ?? []).map((x) => x.id),
          ).read
        : true
    if (!ok) throw forbidden()
  }
}

const tokenSchema = z.object({
  name: enc(1000),
  encryptedPayload: enc(10_000),
  key: enc(10_000),
  expireAt: z.string().nullish(),
})

secretsManager.post('/api/service-accounts/:id/access-tokens', async (c) => {
  const body = await parseBody(c, tokenSchema)
  const db = db_(c)
  const { sa, ctx } = await serviceAccountFor(c, db, 'write')
  await assertCanReachEverything(db, ctx, sa.uuid)
  let expiresAt: number | null = null
  if (body.expireAt) {
    expiresAt = Date.parse(body.expireAt)
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      throw new ApiError(400, 'The request is invalid.', {
        expireAt: ['Expiration must be in the future.'],
      })
    }
  }
  const now = Date.now()
  const uuid = crypto.randomUUID()
  const clientSecret = newClientSecret()
  await db.insert(schema.smAccessTokens).values({
    uuid,
    serviceAccountUuid: sa.uuid,
    name: body.name,
    clientSecretHash: await sha256B64u(clientSecret),
    encryptedPayload: body.encryptedPayload,
    key: body.key,
    expiresAt,
    createdAt: now,
    updatedAt: now,
  })
  const t = accessTokenJson({
    uuid,
    serviceAccountUuid: sa.uuid,
    name: body.name,
    clientSecretHash: '',
    encryptedPayload: '',
    key: '',
    expiresAt,
    createdAt: now,
    updatedAt: now,
  })
  // The client secret is shown once; only its hash is stored.
  return c.json({
    object: 'accessTokenCreation',
    id: t.id,
    name: t.name,
    clientSecret,
    expireAt: t.expireAt,
    creationDate: t.creationDate,
    revisionDate: t.revisionDate,
  })
})

secretsManager.post('/api/service-accounts/:id/access-tokens/revoke', async (c) => {
  const { ids } = await parseBody(c, z.object({ ids: idList }))
  const db = db_(c)
  const { sa } = await serviceAccountFor(c, db, 'write')
  const uuids = ids.filter(isUuid).map((s) => s.toLowerCase())
  if (uuids.length) {
    await db
      .delete(schema.smAccessTokens)
      .where(
        and(
          eq(schema.smAccessTokens.serviceAccountUuid, sa.uuid),
          inArray(schema.smAccessTokens.uuid, uuids),
        ),
      )
  }
  return c.body(null, 200)
})

// ----- access policies -----

async function memberNames(db: Db, orgUuid: string) {
  const uo = schema.usersOrganizations
  const rows = await db
    .select({ m: uo, name: schema.users.name, email: schema.users.email })
    .from(uo)
    .leftJoin(schema.users, eq(schema.users.uuid, uo.userUuid))
    .where(eq(uo.organizationUuid, orgUuid))
  return new Map(rows.map((r) => [r.m.uuid, { ...r, label: r.name || r.email || r.m.email || '' }]))
}

async function groupNames(db: Db, orgUuid: string) {
  const rows = await db
    .select()
    .from(schema.groups)
    .where(eq(schema.groups.organizationUuid, orgUuid))
  return new Map(rows.map((g) => [g.uuid, g.name]))
}

async function policiesOn(db: Db, orgUuid: string, granted: Granted) {
  return db
    .select()
    .from(schema.smAccessPolicies)
    .where(and(grantedColumn(granted), eq(schema.smAccessPolicies.organizationUuid, orgUuid)))
}

async function peoplePoliciesJson(db: Db, ctx: SmContext, policies: Policy[], object: string) {
  const members = await memberNames(db, ctx.orgUuid)
  const groups = await groupNames(db, ctx.orgUuid)
  return {
    object,
    userAccessPolicies: policies
      .filter((p) => p.organizationUserUuid)
      .map((p) => ({
        object: 'userAccessPolicy',
        read: p.read,
        write: p.write,
        organizationUserId: p.organizationUserUuid,
        organizationUserName: members.get(p.organizationUserUuid as string)?.label ?? null,
        currentUser: p.organizationUserUuid === ctx.memberUuid,
      })),
    groupAccessPolicies: policies
      .filter((p) => p.groupUuid)
      .map((p) => ({
        object: 'groupAccessPolicy',
        read: p.read,
        write: p.write,
        groupId: p.groupUuid,
        groupName: groups.get(p.groupUuid as string) ?? null,
        currentUserInGroup: ctx.groupUuids.includes(p.groupUuid as string),
      })),
  }
}

async function serviceAccountPoliciesJson(db: Db, ctx: SmContext, policies: Policy[]) {
  const sas = await db
    .select()
    .from(schema.smServiceAccounts)
    .where(eq(schema.smServiceAccounts.organizationUuid, ctx.orgUuid))
  const names = new Map(sas.map((s) => [s.uuid, s.name]))
  return policies
    .filter((p) => p.serviceAccountUuid)
    .map((p) => ({
      object: 'serviceAccountAccessPolicy',
      read: p.read,
      write: p.write,
      serviceAccountId: p.serviceAccountUuid,
      serviceAccountName: names.get(p.serviceAccountUuid as string) ?? null,
    }))
}

const peopleSchema = z.object({
  userAccessPolicyRequests: policyList,
  groupAccessPolicyRequests: policyList,
})

/** Loads a project for policy management: members only, read to view and write to change. */
async function projectFor(c: Ctx, db: Db, need: 'read' | 'write') {
  const p = await findProject(db, param(c, 'id'))
  const ctx = await ctxFor(c, db, p.organizationUuid)
  requireUser(ctx)
  check(projectAccess(ctx, p.uuid), need, 'Project')
  return { p, ctx }
}

secretsManager.get('/api/projects/:id/access-policies/people', async (c) => {
  const db = db_(c)
  const { p, ctx } = await projectFor(c, db, 'read')
  const policies = await policiesOn(db, ctx.orgUuid, { project: p.uuid })
  return c.json(await peoplePoliciesJson(db, ctx, policies, 'projectPeopleAccessPolicies'))
})

secretsManager.put('/api/projects/:id/access-policies/people', async (c) => {
  const body = await parseBody(c, peopleSchema)
  const db = db_(c)
  const { p, ctx } = await projectFor(c, db, 'write')
  const now = Date.now()
  const users = await replacePolicies(
    db,
    ctx,
    { project: p.uuid },
    'user',
    body.userAccessPolicyRequests ?? [],
    now,
  )
  const groups = await replacePolicies(
    db,
    ctx,
    { project: p.uuid },
    'group',
    body.groupAccessPolicyRequests ?? [],
    now,
  )
  await batch(db, [
    ...users.statements,
    ...groups.statements,
    bumpSecretsRevision(db, ctx.orgUuid, now),
  ])
  const policies = await policiesOn(db, ctx.orgUuid, { project: p.uuid })
  return c.json(await peoplePoliciesJson(db, ctx, policies, 'projectPeopleAccessPolicies'))
})

secretsManager.get('/api/projects/:id/access-policies/service-accounts', async (c) => {
  const db = db_(c)
  const { p, ctx } = await projectFor(c, db, 'read')
  const policies = await policiesOn(db, ctx.orgUuid, { project: p.uuid })
  return c.json({
    object: 'projectServiceAccountsAccessPolicies',
    serviceAccountAccessPolicies: await serviceAccountPoliciesJson(db, ctx, policies),
  })
})

secretsManager.put('/api/projects/:id/access-policies/service-accounts', async (c) => {
  const body = await parseBody(c, z.object({ serviceAccountAccessPolicyRequests: policyList }))
  const db = db_(c)
  const { p, ctx } = await projectFor(c, db, 'write')
  const now = Date.now()
  const r = await replacePolicies(
    db,
    ctx,
    { project: p.uuid },
    'serviceAccount',
    body.serviceAccountAccessPolicyRequests ?? [],
    now,
  )
  await batch(db, [...r.statements, bumpSecretsRevision(db, ctx.orgUuid, now)])
  const policies = await policiesOn(db, ctx.orgUuid, { project: p.uuid })
  return c.json({
    object: 'projectServiceAccountsAccessPolicies',
    serviceAccountAccessPolicies: await serviceAccountPoliciesJson(db, ctx, policies),
  })
})

secretsManager.get('/api/secrets/:secretId/access-policies', async (c) => {
  const db = db_(c)
  const s = await findSecret(db, param(c, 'secretId'))
  const ctx = await ctxFor(c, db, s.organizationUuid)
  requireUser(ctx)
  check(await secretResponse(db, ctx, s), 'read', 'Secret')
  const policies = await policiesOn(db, ctx.orgUuid, { secret: s.uuid })
  return c.json({
    ...(await peoplePoliciesJson(db, ctx, policies, 'secretAccessPolicies')),
    serviceAccountAccessPolicies: await serviceAccountPoliciesJson(db, ctx, policies),
  })
})

secretsManager.get('/api/service-accounts/:id/access-policies/people', async (c) => {
  const db = db_(c)
  const { sa, ctx } = await serviceAccountFor(c, db, 'read')
  const policies = await policiesOn(db, ctx.orgUuid, { serviceAccount: sa.uuid })
  return c.json(await peoplePoliciesJson(db, ctx, policies, 'serviceAccountPeopleAccessPolicies'))
})

secretsManager.put('/api/service-accounts/:id/access-policies/people', async (c) => {
  const body = await parseBody(c, peopleSchema)
  const db = db_(c)
  const { sa, ctx } = await serviceAccountFor(c, db, 'write')
  const now = Date.now()
  const users = await replacePolicies(
    db,
    ctx,
    { serviceAccount: sa.uuid },
    'user',
    body.userAccessPolicyRequests ?? [],
    now,
  )
  const groups = await replacePolicies(
    db,
    ctx,
    { serviceAccount: sa.uuid },
    'group',
    body.groupAccessPolicyRequests ?? [],
    now,
  )
  const ev = (type: number, field: 'organizationUserUuid' | 'groupUuid', id: string) =>
    eventStatement(db, c, {
      type,
      organizationUuid: ctx.orgUuid,
      grantedServiceAccountUuid: sa.uuid,
      [field]: id,
    })
  await batch(db, [
    ...users.statements,
    ...groups.statements,
    ...users.added.map((id) => ev(EventType.ServiceAccountUserAdded, 'organizationUserUuid', id)),
    ...users.removed.map((id) =>
      ev(EventType.ServiceAccountUserRemoved, 'organizationUserUuid', id),
    ),
    ...groups.added.map((id) => ev(EventType.ServiceAccountGroupAdded, 'groupUuid', id)),
    ...groups.removed.map((id) => ev(EventType.ServiceAccountGroupRemoved, 'groupUuid', id)),
  ])
  const policies = await policiesOn(db, ctx.orgUuid, { serviceAccount: sa.uuid })
  return c.json(await peoplePoliciesJson(db, ctx, policies, 'serviceAccountPeopleAccessPolicies'))
})

async function grantedPoliciesJson(db: Db, ctx: SmContext, saUuid: string) {
  const policies = await db
    .select({ p: schema.smAccessPolicies, name: schema.smProjects.name })
    .from(schema.smAccessPolicies)
    .innerJoin(
      schema.smProjects,
      eq(schema.smProjects.uuid, schema.smAccessPolicies.grantedProjectUuid),
    )
    .where(eq(schema.smAccessPolicies.serviceAccountUuid, saUuid))
  return {
    object: 'serviceAccountGrantedPoliciesPermissionDetails',
    grantedProjectPolicies: policies.map(({ p, name }) => ({
      object: 'grantedProjectAccessPolicyPermissionDetails',
      accessPolicy: {
        object: 'grantedProjectAccessPolicy',
        read: p.read,
        write: p.write,
        grantedProjectId: p.grantedProjectUuid,
        grantedProjectName: name,
      },
      hasPermission: projectAccess(ctx, p.grantedProjectUuid as string).write,
    })),
  }
}

secretsManager.get('/api/service-accounts/:id/granted-policies', async (c) => {
  const db = db_(c)
  const { sa, ctx } = await serviceAccountFor(c, db, 'read')
  return c.json(await grantedPoliciesJson(db, ctx, sa.uuid))
})

/**
 * Replaces the projects granted to a machine account. Only projects the caller can write may be
 * added, changed or removed; grants on other projects are kept as they are.
 */
secretsManager.put('/api/service-accounts/:id/granted-policies', async (c) => {
  const body = await parseBody(
    c,
    z.object({
      projectGrantedPolicyRequests: z
        .array(z.object({ grantedId: z.string(), read: z.boolean(), write: z.boolean() }))
        .max(MAX_BULK)
        .nullish(),
    }),
  )
  const db = db_(c)
  const { sa, ctx } = await serviceAccountFor(c, db, 'write')
  const requests = new Map(
    (body.projectGrantedPolicyRequests ?? []).map((r) => [r.grantedId.toLowerCase(), r]),
  )
  const ids = [...requests.keys()]
  if (!ids.every(isUuid)) throw new ApiError(400, 'Invalid project id.')
  const projects = ids.length
    ? await db.select().from(schema.smProjects).where(inArray(schema.smProjects.uuid, ids))
    : []
  if (projects.length !== ids.length || projects.some((p) => p.organizationUuid !== ctx.orgUuid)) {
    throw notFound('Project')
  }
  for (const p of projects) check(projectAccess(ctx, p.uuid), 'write', 'Project')
  const existing = await db
    .select()
    .from(schema.smAccessPolicies)
    .where(eq(schema.smAccessPolicies.serviceAccountUuid, sa.uuid))
  const now = Date.now()
  const statements: unknown[] = []
  for (const p of existing) {
    if (!p.grantedProjectUuid || !projectAccess(ctx, p.grantedProjectUuid).write) continue
    statements.push(
      db.delete(schema.smAccessPolicies).where(eq(schema.smAccessPolicies.uuid, p.uuid)),
    )
  }
  for (const [id, r] of requests) {
    if (!r.read && !r.write) continue
    statements.push(
      db.insert(schema.smAccessPolicies).values({
        uuid: crypto.randomUUID(),
        organizationUuid: ctx.orgUuid,
        serviceAccountUuid: sa.uuid,
        grantedProjectUuid: id,
        read: r.read || r.write,
        write: r.write,
        createdAt: now,
        updatedAt: now,
      }),
    )
  }
  await batch(db, [...statements, bumpSecretsRevision(db, ctx.orgUuid, now)])
  return c.json(await grantedPoliciesJson(db, ctx, sa.uuid))
})

// ----- potential grantees -----

const grantee = (
  id: string,
  name: string | null,
  type: string,
  extra: { email?: string | null; currentUser?: boolean; currentUserInGroup?: boolean } = {},
) => ({
  object: 'potentialGrantee',
  id,
  name,
  type,
  email: extra.email ?? null,
  currentUserInGroup: extra.currentUserInGroup ?? null,
  currentUser: extra.currentUser ?? null,
})

secretsManager.get(
  '/api/organizations/:orgId/access-policies/people/potential-grantees',
  async (c) => {
    const db = db_(c)
    const ctx = await ctxFor(c, db, param(c, 'orgId'))
    requireUser(ctx)
    const members = [...(await memberNames(db, ctx.orgUuid)).values()].filter(
      (r) => r.m.accessSecretsManager && r.m.status === Status.Confirmed,
    )
    const groups = await groupNames(db, ctx.orgUuid)
    return c.json(
      list([
        ...members.map((r) =>
          grantee(r.m.uuid, r.name ?? null, 'user', {
            email: r.email ?? r.m.email,
            currentUser: r.m.uuid === ctx.memberUuid,
          }),
        ),
        ...[...groups].map(([id, name]) =>
          grantee(id, name, 'group', { currentUserInGroup: ctx.groupUuids.includes(id) }),
        ),
      ]),
    )
  },
)

secretsManager.get(
  '/api/organizations/:orgId/access-policies/service-accounts/potential-grantees',
  async (c) => {
    const db = db_(c)
    const ctx = await ctxFor(c, db, param(c, 'orgId'))
    requireUser(ctx)
    const rows = await db
      .select()
      .from(schema.smServiceAccounts)
      .where(eq(schema.smServiceAccounts.organizationUuid, ctx.orgUuid))
    return c.json(
      list(
        rows
          .filter((sa) => serviceAccountAccess(ctx, sa.uuid).read)
          .map((sa) => grantee(sa.uuid, sa.name, 'serviceAccount')),
      ),
    )
  },
)

secretsManager.get(
  '/api/organizations/:orgId/access-policies/projects/potential-grantees',
  async (c) => {
    const db = db_(c)
    const ctx = await ctxFor(c, db, param(c, 'orgId'))
    requireUser(ctx)
    const rows = await db
      .select()
      .from(schema.smProjects)
      .where(eq(schema.smProjects.organizationUuid, ctx.orgUuid))
    return c.json(
      list(
        rows
          .filter((p) => projectAccess(ctx, p.uuid).write)
          .map((p) => grantee(p.uuid, p.name, 'project')),
      ),
    )
  },
)

// ----- counts -----

secretsManager.get('/api/organizations/:orgId/sm-counts', async (c) => {
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  requireUser(ctx)
  const projects = await db
    .select({ uuid: schema.smProjects.uuid })
    .from(schema.smProjects)
    .where(eq(schema.smProjects.organizationUuid, ctx.orgUuid))
  const sas = await db
    .select({ uuid: schema.smServiceAccounts.uuid })
    .from(schema.smServiceAccounts)
    .where(eq(schema.smServiceAccounts.organizationUuid, ctx.orgUuid))
  return c.json({
    object: 'organizationCounts',
    projects: projects.filter((p) => projectAccess(ctx, p.uuid).read).length,
    secrets: (await readableSecrets(db, ctx)).length,
    serviceAccounts: sas.filter((s) => serviceAccountAccess(ctx, s.uuid).read).length,
  })
})

secretsManager.get('/api/projects/:projectId/sm-counts', async (c) => {
  const db = db_(c)
  const p = await findProject(db, param(c, 'projectId'))
  const ctx = await ctxFor(c, db, p.organizationUuid)
  requireUser(ctx)
  check(projectAccess(ctx, p.uuid), 'read', 'Project')
  const policies = await policiesOn(db, ctx.orgUuid, { project: p.uuid })
  const secrets = (await readableSecrets(db, ctx)).filter((r) =>
    r.projects.some((x) => x.id === p.uuid),
  )
  return c.json({
    object: 'projectCounts',
    secrets: secrets.length,
    people: policies.filter((x) => x.organizationUserUuid || x.groupUuid).length,
    serviceAccounts: policies.filter((x) => x.serviceAccountUuid).length,
  })
})

secretsManager.get('/api/service-accounts/:serviceAccountId/sm-counts', async (c) => {
  const db = db_(c)
  const { sa, ctx } = await serviceAccountFor(c, db, 'read', 'serviceAccountId')
  const people = await policiesOn(db, ctx.orgUuid, { serviceAccount: sa.uuid })
  const granted = await db
    .select({ uuid: schema.smAccessPolicies.uuid })
    .from(schema.smAccessPolicies)
    .where(
      and(
        eq(schema.smAccessPolicies.serviceAccountUuid, sa.uuid),
        isNotNull(schema.smAccessPolicies.grantedProjectUuid),
      ),
    )
  const tokens = await db
    .select({ uuid: schema.smAccessTokens.uuid })
    .from(schema.smAccessTokens)
    .where(eq(schema.smAccessTokens.serviceAccountUuid, sa.uuid))
  return c.json({
    object: 'serviceAccountCounts',
    projects: granted.length,
    people: people.length,
    accessTokens: tokens.length,
  })
})

// ----- events -----

secretsManager.get('/api/sm/events/service-accounts/:serviceAccountId', async (c) => {
  const db = db_(c)
  const { sa } = await serviceAccountFor(c, db, 'read', 'serviceAccountId')
  return c.json(
    await listEvents(
      db,
      c,
      or(
        eq(schema.events.serviceAccountUuid, sa.uuid),
        eq(schema.events.grantedServiceAccountUuid, sa.uuid),
      ),
    ),
  )
})

/** Events of one Secrets Manager object, scoped to the organisation in the path. */
async function objectEvents(c: Ctx, orgUuid: string, where: ReturnType<typeof eq>) {
  return c.json(
    await listEvents(db_(c), c, and(eq(schema.events.organizationUuid, orgUuid), where)),
  )
}

secretsManager.get('/api/organization/:orgId/projects/:id/events', async (c) => {
  const { p, ctx } = await projectFor(c, db_(c), 'read')
  if (p.organizationUuid !== param(c, 'orgId')) throw notFound('Project')
  return objectEvents(c, ctx.orgUuid, eq(schema.events.projectUuid, p.uuid))
})

secretsManager.get('/api/organization/:orgId/secrets/:id/events', async (c) => {
  const db = db_(c)
  // Trashed secrets keep their history, so this looks the row up directly.
  const [s] = await db
    .select()
    .from(schema.smSecrets)
    .where(
      and(
        eq(schema.smSecrets.uuid, param(c, 'id')),
        eq(schema.smSecrets.organizationUuid, param(c, 'orgId')),
      ),
    )
  if (!s) throw notFound('Secret')
  const ctx = await ctxFor(c, db, s.organizationUuid)
  requireUser(ctx)
  const projects = (await projectsOfSecrets(db, [s.uuid])).get(s.uuid) ?? []
  check(
    secretAccess(
      ctx,
      s.uuid,
      projects.map((p) => p.id),
    ),
    'read',
    'Secret',
  )
  return objectEvents(c, ctx.orgUuid, eq(schema.events.secretUuid, s.uuid))
})

secretsManager.get('/api/organization/:orgId/service-account/:id/events', async (c) => {
  const { sa, ctx } = await serviceAccountFor(c, db_(c), 'read')
  if (sa.organizationUuid !== param(c, 'orgId')) throw notFound('Service account')
  return objectEvents(
    c,
    ctx.orgUuid,
    or(
      eq(schema.events.serviceAccountUuid, sa.uuid),
      eq(schema.events.grantedServiceAccountUuid, sa.uuid),
    ) as ReturnType<typeof eq>,
  )
})

// ----- trash -----

/** Trashed secrets of the organisation the caller may change, with their projects. Members only. */
async function trashedSecrets(db: Db, ctx: SmContext) {
  if (ctx.actor.kind !== 'user') throw forbidden()
  const rows = await db
    .select()
    .from(schema.smSecrets)
    .where(
      and(
        eq(schema.smSecrets.organizationUuid, ctx.orgUuid),
        isNotNull(schema.smSecrets.deletedAt),
      ),
    )
  const projects = await projectsOfSecrets(
    db,
    rows.map((s) => s.uuid),
  )
  return rows
    .map((s) => {
      const p = projects.get(s.uuid) ?? []
      return {
        s,
        projects: p,
        rw: secretAccess(
          ctx,
          s.uuid,
          p.map((x) => x.id),
        ),
      }
    })
    .filter((x) => x.rw.write)
}

secretsManager.get('/api/secrets/:orgId/trash', async (c) => {
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  const rows = await trashedSecrets(db, ctx)
  return c.json({
    object: 'SecretsWithProjectsList',
    secrets: rows.map((r) => secretListJson(r.s, r.projects, r.rw)),
    projects: [
      ...new Map(rows.flatMap((r) => r.projects).map((p) => [p.id, p] as const)).values(),
    ].filter((p) => projectAccess(ctx, p.id).read),
  })
})

/** Resolves the requested ids to trashed secrets the caller may change; anything else is a 404. */
async function trashSelection(c: Ctx) {
  const ids = await parseBody(c, idList)
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  const uuids = [...new Set(ids.map((s) => s.toLowerCase()))]
  const byId = new Map((await trashedSecrets(db, ctx)).map((r) => [r.s.uuid, r.s]))
  if (!uuids.every((id) => byId.has(id))) throw notFound('Secret')
  return { db, ctx, uuids }
}

secretsManager.post('/api/secrets/:orgId/trash/empty', async (c) => {
  const { db, ctx, uuids } = await trashSelection(c)
  const now = Date.now()
  await batch(db, [
    ...uuids.flatMap((id) => [
      db.delete(schema.smSecrets).where(eq(schema.smSecrets.uuid, id)),
      eventStatement(db, c, {
        type: EventType.SecretPermanentlyDeleted,
        organizationUuid: ctx.orgUuid,
        secretUuid: id,
        ...actorEventFields(ctx),
      }),
    ]),
    bumpSecretsRevision(db, ctx.orgUuid, now),
  ])
  return c.body(null, 200)
})

secretsManager.post('/api/secrets/:orgId/trash/restore', async (c) => {
  const { db, ctx, uuids } = await trashSelection(c)
  const now = Date.now()
  await batch(db, [
    ...uuids.flatMap((id) => [
      db
        .update(schema.smSecrets)
        .set({ deletedAt: null, updatedAt: now })
        .where(eq(schema.smSecrets.uuid, id)),
      eventStatement(db, c, {
        type: EventType.SecretRestored,
        organizationUuid: ctx.orgUuid,
        secretUuid: id,
        ...actorEventFields(ctx),
      }),
    ]),
    bumpSecretsRevision(db, ctx.orgUuid, now),
  ])
  return c.body(null, 200)
})

// ----- secret versions (TASKS #224) -----

/** Ids per get-by-ids call; each distinct secret costs an access check. */
const MAX_VERSION_IDS = 100

const versionRows = (db: Db, where: ReturnType<typeof eq>) =>
  db
    .select({
      v: schema.smSecretVersions,
      userName: schema.users.name,
      accountName: schema.smServiceAccounts.name,
    })
    .from(schema.smSecretVersions)
    .leftJoin(
      schema.usersOrganizations,
      eq(schema.usersOrganizations.uuid, schema.smSecretVersions.editorOrganizationUserUuid),
    )
    .leftJoin(schema.users, eq(schema.users.uuid, schema.usersOrganizations.userUuid))
    .leftJoin(
      schema.smServiceAccounts,
      eq(schema.smServiceAccounts.uuid, schema.smSecretVersions.editorServiceAccountUuid),
    )
    .where(where)
    .orderBy(desc(schema.smSecretVersions.versionDate), desc(sql`${schema.smSecretVersions}.rowid`))

type VersionRow = Awaited<ReturnType<typeof versionRows>>[number]

const versionJson = (r: VersionRow) => ({
  object: 'secretVersion',
  id: r.v.uuid,
  secretId: r.v.secretUuid,
  value: r.v.value,
  versionDate: new Date(r.v.versionDate).toISOString(),
  editorServiceAccountId: r.v.editorServiceAccountUuid,
  editorOrganizationUserId: r.v.editorOrganizationUserUuid,
  editorOrganizationUserName: r.userName ?? null,
  editorServiceAccountName: r.accountName ?? null,
})

/** The caller's context for the secret's organisation, with 404 unless they hold `need` on it. */
async function secretFor(c: Ctx, db: Db, secretUuid: string, need: 'read' | 'write') {
  const s = await findSecret(db, secretUuid)
  const ctx = await ctxFor(c, db, s.organizationUuid)
  const out = await secretResponse(db, ctx, s)
  check(out, need, 'Secret')
  return { s, ctx }
}

secretsManager.get('/api/secrets/:id/versions', async (c) => {
  const db = db_(c)
  const { s } = await secretFor(c, db, param(c, 'id'), 'read')
  const rows = await versionRows(db, eq(schema.smSecretVersions.secretUuid, s.uuid))
  return c.json(list(rows.map(versionJson)))
})

/** Loads versions by id; every one must exist and be readable (or writable) by the caller. */
async function versionsByIds(c: Ctx, db: Db, ids: string[], need: 'read' | 'write') {
  const uuids = [...new Set(ids.map((i) => i.toLowerCase()))]
  if (!uuids.every(isUuid)) throw notFound('Secret version')
  const rows = await inChunks(uuids, (part) =>
    versionRows(db, inArray(schema.smSecretVersions.uuid, part)),
  )
  if (rows.length !== uuids.length) throw notFound('Secret version')
  for (const secretUuid of new Set(rows.map((r) => r.v.secretUuid))) {
    await secretFor(c, db, secretUuid, need) // throws 404 or 403
  }
  return rows
}

secretsManager.post('/api/secret-versions/get-by-ids', async (c) => {
  const ids = await parseBody(c, z.array(z.string()).min(1).max(MAX_VERSION_IDS))
  const rows = await versionsByIds(c, db_(c), ids, 'read')
  return c.json(list(rows.map(versionJson)))
})

secretsManager.get('/api/secret-versions/:id', async (c) => {
  const [row] = await versionsByIds(c, db_(c), [param(c, 'id')], 'read')
  return c.json(versionJson(row as VersionRow))
})

secretsManager.post('/api/secret-versions/delete', async (c) => {
  const ids = await parseBody(c, idList)
  const db = db_(c)
  const rows = await versionsByIds(c, db, ids, 'write')
  await db.delete(schema.smSecretVersions).where(
    inArray(
      schema.smSecretVersions.uuid,
      rows.map((r) => r.v.uuid),
    ),
  )
  return c.body(null, 200)
})

secretsManager.put('/api/secrets/:id/versions/restore', async (c) => {
  const { versionId } = await parseBody(c, z.object({ versionId: z.string() }))
  const db = db_(c)
  const { s, ctx } = await secretFor(c, db, param(c, 'id'), 'write')
  if (!isUuid(versionId)) throw notFound('Secret version')
  const [row] = await versionRows(db, eq(schema.smSecretVersions.uuid, versionId.toLowerCase()))
  if (!row || row.v.secretUuid !== s.uuid) throw notFound('Secret version')
  const now = Date.now()
  await batch(db, [
    ...versionStatements(db, ctx, s, row.v.value, now),
    db
      .update(schema.smSecrets)
      .set({ value: row.v.value, updatedAt: now })
      .where(eq(schema.smSecrets.uuid, s.uuid)),
    bumpSecretsRevision(db, ctx.orgUuid, now),
    eventStatement(db, c, {
      type: EventType.SecretEdited,
      organizationUuid: ctx.orgUuid,
      secretUuid: s.uuid,
      ...actorEventFields(ctx),
    }),
  ])
  return c.json(await secretResponse(db, ctx, await findSecret(db, s.uuid)))
})

// ----- import and export (TASKS #224) -----

/** Export of everything the caller can read: projects and secrets with their encrypted fields. */
secretsManager.get('/api/sm/:orgId/export', async (c) => {
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  requireUser(ctx)
  const rows = await readableSecrets(db, ctx)
  const projects = (
    await db
      .select()
      .from(schema.smProjects)
      .where(eq(schema.smProjects.organizationUuid, ctx.orgUuid))
  ).filter((p) => projectAccess(ctx, p.uuid).read)
  return c.json({
    object: 'sm-export',
    projects: projects.map((p) => ({ id: p.uuid, name: p.name })),
    secrets: rows.map((r) => ({
      id: r.s.uuid,
      key: r.s.key,
      value: r.s.value,
      note: r.s.note,
      projectIds: r.projects.map((p) => p.id),
    })),
  })
})

const MAX_IMPORT_ITEMS = 5000
const IMPORT_CHUNK = 400
const importSchema = z.object({
  projects: z
    .array(z.object({ id: z.string(), name: enc(1000) }))
    .max(MAX_IMPORT_ITEMS)
    .nullish(),
  secrets: z
    .array(
      z.object({
        id: z.string(),
        key: enc(10_000),
        value: enc(100_000),
        note: z.string().max(100_000).nullish(),
        projectIds: z.array(z.string()).max(1, 'A secret can belong to one project.').nullish(),
      }),
    )
    .max(MAX_IMPORT_ITEMS)
    .nullish(),
})

/**
 * Creates the projects and secrets of an export under fresh ids (ids in the file only link secrets
 * to projects, so an import can never overwrite or claim existing data). Needs Secrets Manager
 * access; secrets without a project need an owner or admin, as everywhere else. Large imports are
 * written in several batches (D1 limit), projects first, never splitting a project from its
 * creator access policy. A failure part way keeps what was written (a partial import) and still
 * bumps the revision so clients resync.
 */
secretsManager.post('/api/sm/:orgId/import', async (c) => {
  const body = await parseBody(c, importSchema)
  const db = db_(c)
  const ctx = await ctxFor(c, db, param(c, 'orgId'))
  requireUser(ctx)
  const projects = body.projects ?? []
  const secrets = body.secrets ?? []
  const projectIds = new Map<string, string>()
  for (const p of projects) {
    if (!isUuid(p.id) || projectIds.has(p.id.toLowerCase())) {
      throw new ApiError(400, 'Invalid or repeated project id.')
    }
    projectIds.set(p.id.toLowerCase(), crypto.randomUUID())
  }
  const seen = new Set<string>()
  for (const s of secrets) {
    if (!isUuid(s.id) || seen.has(s.id.toLowerCase())) {
      throw new ApiError(400, 'Invalid or repeated secret id.')
    }
    seen.add(s.id.toLowerCase())
    const linked = s.projectIds ?? []
    if (linked.some((p) => !projectIds.has(p.toLowerCase()))) {
      throw new ApiError(400, 'A secret refers to a project that is not in the file.')
    }
    if (linked.length === 0 && !ctx.admin) throw forbidden()
  }
  const now = Date.now()
  // One group per project or secret, so an object and its access policy never split across batches.
  const groups: unknown[][] = []
  for (const p of projects) {
    const uuid = projectIds.get(p.id.toLowerCase()) as string
    groups.push([
      db.insert(schema.smProjects).values({
        uuid,
        organizationUuid: ctx.orgUuid,
        name: p.name,
        createdAt: now,
        updatedAt: now,
      }),
      ...creatorPolicy(db, ctx, { project: uuid }, now),
      eventStatement(db, c, {
        type: EventType.ProjectCreated,
        organizationUuid: ctx.orgUuid,
        projectUuid: uuid,
        ...actorEventFields(ctx),
      }),
    ])
  }
  for (const s of secrets) {
    const uuid = crypto.randomUUID()
    groups.push([
      db.insert(schema.smSecrets).values({
        uuid,
        organizationUuid: ctx.orgUuid,
        key: s.key,
        value: s.value,
        note: s.note ?? '',
        createdAt: now,
        updatedAt: now,
      }),
      ...projectLinks(
        db,
        uuid,
        (s.projectIds ?? []).map((p) => projectIds.get(p.toLowerCase()) as string),
      ),
      eventStatement(db, c, {
        type: EventType.SecretCreated,
        organizationUuid: ctx.orgUuid,
        secretUuid: uuid,
        ...actorEventFields(ctx),
      }),
    ])
  }
  // Written in batches (D1 limit) with whole groups only. A failure part way keeps the batches
  // already written, and the revision is bumped either way so clients resync what exists.
  let batchStatements: unknown[] = []
  let written = false
  try {
    for (const group of groups) {
      if (batchStatements.length + group.length > IMPORT_CHUNK) {
        await batch(db, batchStatements)
        written = true
        batchStatements = []
      }
      batchStatements.push(...group)
    }
    if (batchStatements.length > 0) {
      await batch(db, batchStatements)
      written = true
    }
  } finally {
    if (written) await batch(db, [bumpSecretsRevision(db, ctx.orgUuid, now)])
  }
  return c.body(null, 200)
})
