// SCIM 2.0 service provider (RFC 7643, RFC 7644) for one organisation (TASKS #263), at
// `/scim/v2/{organizationId}` (self-hosted layout) and `/v2/{organizationId}` (the path Bitwarden's
// cloud SCIM host uses). Identity providers such as Microsoft Entra ID and Okta authenticate with
// the organisation's SCIM API key as a Bearer token once SCIM is enabled in the Admin Console.
//
// Users map to organisation members: creating one invites the address, `active: false` revokes
// the member and `active: true` restores them, deleting removes them. Groups map to organisation
// groups and their `members` to group membership.
import { and, eq, inArray } from 'drizzle-orm'
import type { Context, MiddlewareHandler } from 'hono'
import { Hono } from 'hono'
import { normalizeEmail } from '../auth/users'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { errorKind, log } from '../log'
import { bumpOrgRevision, type Member, requireOrg } from '../orgs/access'
import { ApiKeyType, apiKeyMatches, loadApiKey } from '../orgs/api-keys'
import { EventSystemUser, EventType, Status } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { assertCanAssign, assertNotLastOwner } from '../orgs/members'
import {
  insertMemberStatements,
  invitedMember,
  memberByEmail,
  statusOnRestore,
  systemActor,
} from '../orgs/provisioning'
import { batch } from '../orgs/util'
import { sendInvite } from '../routes/org-users'
import { isUuid } from '../sm/auth'
import { matches, parseFilter, ScimError } from './filter'
import { applyPatch, PATCH_SCHEMA, type PatchOp, scimBool } from './patch'

type Ctx = Context<Env>
type Json = Record<string, unknown>

export const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User'
export const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group'
const LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse'
const ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error'
const SCIM_JSON = 'application/scim+json; charset=utf-8'
const MAX_COUNT = 1000

export const scim = new Hono<Env>()
const PREFIXES = ['/scim/v2/:orgId', '/v2/:orgId'] as const

const orgOf = (c: Ctx) => (c.req.param('orgId') ?? '').toLowerCase()

const respond = (c: Ctx, body: unknown, status = 200, headers: Record<string, string> = {}) =>
  c.body(JSON.stringify(body), status as 200, { 'Content-Type': SCIM_JSON, ...headers })

const scimError = (c: Ctx, status: number, detail: string, scimType?: string) =>
  respond(
    c,
    { schemas: [ERROR_SCHEMA], status: String(status), ...(scimType ? { scimType } : {}), detail },
    status,
  )

/** Base URL of this organisation's SCIM endpoint as the caller addressed it. */
function baseUrl(c: Ctx) {
  const url = new URL(c.req.url)
  const marker = `/v2/${c.req.param('orgId')}`
  const idx = url.pathname.indexOf(marker)
  return `${url.origin}${url.pathname.slice(0, idx + marker.length)}`
}

const iso = (ms: number) => new Date(ms).toISOString()

// ----- authentication -----

const requireScimAuth: MiddlewareHandler<Env> = async (c, next) => {
  const orgUuid = orgOf(c)
  const match = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')
  const fail = () => scimError(c, 401, 'Authorization failure.')
  if (!match?.[1] || !isUuid(orgUuid)) return fail()
  const db = createDb(c.env.DB_PRIMARY ?? c.env.DB)
  const [config] = await db
    .select()
    .from(schema.organizationScim)
    .where(eq(schema.organizationScim.organizationUuid, orgUuid))
    .limit(1)
  const key = await loadApiKey(db, orgUuid, ApiKeyType.Scim)
  const ok = await apiKeyMatches(c.env, key, match[1])
  if (!config?.enabled || !ok) return fail()
  return next()
}

// ----- representations -----

interface UserRow {
  m: Member
  u: { name: string; email: string } | null
}

const emailOf = (r: UserRow) => r.u?.email ?? r.m.email ?? ''

function userResource(c: Ctx, r: UserRow): Json {
  const email = emailOf(r)
  const name = r.u?.name ?? null
  return {
    schemas: [USER_SCHEMA],
    id: r.m.uuid,
    externalId: r.m.externalId,
    userName: email,
    displayName: name ?? email,
    ...(name ? { name: { formatted: name } } : {}),
    active: r.m.status !== Status.Revoked,
    emails: email ? [{ primary: true, value: email, type: 'work' }] : [],
    meta: {
      resourceType: 'User',
      created: iso(r.m.createdAt),
      lastModified: iso(r.m.updatedAt),
      location: `${baseUrl(c)}/Users/${r.m.uuid}`,
    },
  }
}

type GroupRow = typeof schema.groups.$inferSelect

function groupResource(c: Ctx, g: GroupRow, members: UserRow[]): Json {
  return {
    schemas: [GROUP_SCHEMA],
    id: g.uuid,
    externalId: g.externalId,
    displayName: g.name,
    members: members.map((r) => ({
      value: r.m.uuid,
      display: emailOf(r),
      $ref: `${baseUrl(c)}/Users/${r.m.uuid}`,
    })),
    meta: {
      resourceType: 'Group',
      created: iso(g.createdAt),
      lastModified: iso(g.updatedAt),
      location: `${baseUrl(c)}/Groups/${g.uuid}`,
    },
  }
}

async function loadUsers(db: Db, orgUuid: string, id?: string): Promise<UserRow[]> {
  const uo = schema.usersOrganizations
  return db
    .select({ m: uo, u: { name: schema.users.name, email: schema.users.email } })
    .from(uo)
    .leftJoin(schema.users, eq(schema.users.uuid, uo.userUuid))
    .where(
      id
        ? and(eq(uo.organizationUuid, orgUuid), eq(uo.uuid, id))
        : eq(uo.organizationUuid, orgUuid),
    )
}

async function loadUser(db: Db, orgUuid: string, id: string): Promise<UserRow> {
  const [r] = await loadUsers(db, orgUuid, id)
  if (!r) throw new ScimError(404, 'User not found.')
  return r
}

async function loadGroups(db: Db, orgUuid: string, id?: string) {
  const g = schema.groups
  const groups = await db
    .select()
    .from(g)
    .where(
      id ? and(eq(g.organizationUuid, orgUuid), eq(g.uuid, id)) : eq(g.organizationUuid, orgUuid),
    )
  const users = await loadUsers(db, orgUuid)
  const byId = new Map(users.map((u) => [u.m.uuid, u]))
  const links = groups.length
    ? await db
        .select()
        .from(schema.groupsUsers)
        .where(
          inArray(
            schema.groupsUsers.groupUuid,
            groups.map((x) => x.uuid),
          ),
        )
    : []
  return groups.map((group) => ({
    group,
    members: links
      .filter((l) => l.groupUuid === group.uuid)
      .map((l) => byId.get(l.organizationUserUuid))
      .filter((u): u is UserRow => !!u),
  }))
}

async function loadGroup(db: Db, orgUuid: string, id: string) {
  const [g] = await loadGroups(db, orgUuid, id)
  if (!g) throw new ScimError(404, 'Group not found.')
  return g
}

// ----- listing -----

/** Applies `attributes` / `excludedAttributes` (top-level names) to a resource. */
function project(c: Ctx, r: Json): Json {
  const split = (s: string | undefined) =>
    (s ?? '')
      .split(',')
      .map((x) => x.trim().split(':').pop()?.split('.')[0]?.toLowerCase() ?? '')
      .filter(Boolean)
  const include = split(c.req.query('attributes'))
  const exclude = split(c.req.query('excludedAttributes'))
  const always = new Set(['id', 'schemas', 'meta'])
  return Object.fromEntries(
    Object.entries(r).filter(([k]) => {
      const lk = k.toLowerCase()
      if (always.has(lk)) return true
      if (include.length) return include.includes(lk)
      return !exclude.includes(lk)
    }),
  )
}

function listResponse(c: Ctx, resources: Json[]) {
  const filterText = c.req.query('filter')
  const filter = filterText ? parseFilter(filterText) : null
  const all = filter ? resources.filter((r) => matches(r, filter)) : resources
  const start = Math.max(1, Number.parseInt(c.req.query('startIndex') ?? '1', 10) || 1)
  const countParam = c.req.query('count')
  const count = Math.min(
    MAX_COUNT,
    Math.max(0, countParam === undefined ? MAX_COUNT : Number.parseInt(countParam, 10) || 0),
  )
  const page = all.slice(start - 1, start - 1 + count)
  return respond(c, {
    schemas: [LIST_SCHEMA],
    totalResults: all.length,
    startIndex: start,
    itemsPerPage: page.length,
    Resources: page.map((r) => project(c, r)),
  })
}

async function readJson(c: Ctx): Promise<Json> {
  const raw = await c.req.json().catch(() => null)
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ScimError(400, 'The request body must be a JSON object.', 'invalidSyntax')
  }
  return raw as Json
}

function patchOperations(body: Json): PatchOp[] {
  const ops = Object.entries(body).find(([k]) => k.toLowerCase() === 'operations')?.[1]
  if (!Array.isArray(ops)) throw new ScimError(400, 'Operations are required.', 'invalidSyntax')
  const schemas = body.schemas
  if (Array.isArray(schemas) && schemas.length && !schemas.includes(PATCH_SCHEMA)) {
    throw new ScimError(400, 'Unsupported patch schema.', 'invalidSyntax')
  }
  return ops.map((o) => {
    const op = (o ?? {}) as Json
    const get = (k: string) => Object.entries(op).find(([x]) => x.toLowerCase() === k)?.[1]
    return {
      op: String(get('op') ?? ''),
      path: get('path') as string | undefined,
      value: get('value'),
    }
  })
}

const prop = (obj: Json, name: string) =>
  Object.entries(obj).find(([k]) => k.toLowerCase() === name.toLowerCase())?.[1]

/** Email of a user resource: the primary email, then any email, then `userName`. */
function emailFrom(resource: Json): string | null {
  const emails = prop(resource, 'emails')
  if (Array.isArray(emails)) {
    const list = emails as Json[]
    const primary = list.find((e) => scimBool(prop(e, 'primary')) === true) ?? list[0]
    const v = primary ? prop(primary, 'value') : undefined
    if (typeof v === 'string' && v.includes('@')) return normalizeEmail(v)
  }
  const userName = prop(resource, 'userName')
  return typeof userName === 'string' && userName.includes('@') ? normalizeEmail(userName) : null
}

const stringOrNull = (v: unknown) => (typeof v === 'string' && v !== '' ? v : null)

// ----- user changes -----

const ev = (db: Db, c: Ctx, e: Parameters<typeof eventStatement>[2]) =>
  eventStatement(db, c, { ...e, organizationUuid: orgOf(c), systemUser: EventSystemUser.Scim })

/** Applies the desired state of a user resource to the member. */
async function updateUser(c: Ctx, db: Db, current: UserRow, desired: Json) {
  const m = current.m
  const orgUuid = orgOf(c)
  const now = Date.now()
  const statements: unknown[] = []
  const set: Partial<Member> = {}
  if (prop(desired, 'externalId') !== undefined) {
    const externalId = stringOrNull(prop(desired, 'externalId'))
    if (externalId !== m.externalId) set.externalId = externalId
  }
  // The address of an invitation not yet linked to an account follows the directory.
  const email = emailFrom(desired)
  if (email && !m.userUuid && email !== m.email) {
    const clash = await memberByEmail(db, orgUuid, email)
    if (clash && clash.uuid !== m.uuid)
      throw new ScimError(409, 'User already exists.', 'uniqueness')
    set.email = email
  }
  const active = scimBool(prop(desired, 'active'))
  if (active === false && m.status !== Status.Revoked) {
    assertCanAssign(systemActor(orgUuid), m.atype)
    set.status = Status.Revoked
    statements.push(
      ev(db, c, {
        type: EventType.OrganizationUserRevoked,
        organizationUserUuid: m.uuid,
        userUuid: m.userUuid,
      }),
    )
  } else if (active === true && m.status === Status.Revoked) {
    assertCanAssign(systemActor(orgUuid), m.atype)
    set.status = statusOnRestore(m)
    statements.push(
      ev(db, c, {
        type: EventType.OrganizationUserRestored,
        organizationUserUuid: m.uuid,
        userUuid: m.userUuid,
      }),
    )
  }
  if (Object.keys(set).length === 0) return
  await batch(db, [
    db
      .update(schema.usersOrganizations)
      .set({ ...set, updatedAt: now })
      .where(eq(schema.usersOrganizations.uuid, m.uuid)),
    ...(statements.length
      ? statements
      : [
          ev(db, c, {
            type: EventType.OrganizationUserUpdated,
            organizationUserUuid: m.uuid,
            userUuid: m.userUuid,
          }),
        ]),
    bumpOrgRevision(db, orgUuid, now),
  ])
}

// ----- group changes -----

async function memberIdsFrom(
  db: Db,
  orgUuid: string,
  resource: Json,
): Promise<string[] | undefined> {
  const raw = prop(resource, 'members')
  if (raw === undefined) return undefined
  if (raw === null) return []
  if (!Array.isArray(raw)) throw new ScimError(400, 'members must be an array.', 'invalidValue')
  const ids = [
    ...new Set(
      (raw as Json[])
        .map((x) => String(prop(x ?? {}, 'value') ?? '').toLowerCase())
        .filter(Boolean),
    ),
  ]
  if (ids.length === 0) return ids
  const found = new Set<string>()
  for (let i = 0; i < ids.length; i += 80) {
    const rows = await db
      .select({ uuid: schema.usersOrganizations.uuid })
      .from(schema.usersOrganizations)
      .where(
        and(
          eq(schema.usersOrganizations.organizationUuid, orgUuid),
          inArray(schema.usersOrganizations.uuid, ids.slice(i, i + 80)),
        ),
      )
    for (const r of rows) found.add(r.uuid)
  }
  const missing = ids.filter((id) => !found.has(id))
  if (missing.length) {
    throw new ScimError(400, `Unknown member ${missing[0]}.`, 'invalidValue')
  }
  return ids
}

async function saveGroup(
  c: Ctx,
  db: Db,
  existing: GroupRow | null,
  desired: Json,
  replaceMembersWhenAbsent: boolean,
) {
  const orgUuid = orgOf(c)
  const name = stringOrNull(prop(desired, 'displayName'))
  if (!name) throw new ScimError(400, 'displayName is required.', 'invalidValue')
  if (name.length > 100) throw new ScimError(400, 'displayName is too long.', 'invalidValue')
  const externalId =
    prop(desired, 'externalId') === undefined
      ? (existing?.externalId ?? null)
      : stringOrNull(prop(desired, 'externalId'))
  let members = await memberIdsFrom(db, orgUuid, desired)
  if (members === undefined && replaceMembersWhenAbsent) members = []
  const now = Date.now()
  const uuid = existing?.uuid ?? crypto.randomUUID()
  await batch(db, [
    existing
      ? db
          .update(schema.groups)
          .set({ name, externalId, updatedAt: now })
          .where(eq(schema.groups.uuid, uuid))
      : db.insert(schema.groups).values({
          uuid,
          organizationUuid: orgUuid,
          name,
          accessAll: false,
          externalId,
          createdAt: now,
          updatedAt: now,
        }),
    ...(members === undefined
      ? []
      : [
          db.delete(schema.groupsUsers).where(eq(schema.groupsUsers.groupUuid, uuid)),
          ...members.map((m) =>
            db.insert(schema.groupsUsers).values({ groupUuid: uuid, organizationUserUuid: m }),
          ),
        ]),
    ev(db, c, {
      type: existing ? EventType.GroupUpdated : EventType.GroupCreated,
      groupUuid: uuid,
    }),
    bumpOrgRevision(db, orgUuid, now),
  ])
  return uuid
}

// ----- discovery -----

const attr = (name: string, extra: Json = {}): Json => ({
  name,
  type: 'string',
  multiValued: false,
  required: false,
  caseExact: false,
  mutability: 'readWrite',
  returned: 'default',
  uniqueness: 'none',
  ...extra,
})

const SCHEMAS: Json[] = [
  {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
    id: USER_SCHEMA,
    name: 'User',
    description: 'Organization member',
    attributes: [
      attr('userName', { required: true, uniqueness: 'server' }),
      attr('externalId', { caseExact: true }),
      attr('displayName'),
      attr('name', {
        type: 'complex',
        subAttributes: [attr('formatted'), attr('givenName'), attr('familyName')],
      }),
      attr('active', { type: 'boolean' }),
      attr('emails', {
        type: 'complex',
        multiValued: true,
        subAttributes: [attr('value'), attr('type'), attr('primary', { type: 'boolean' })],
      }),
    ],
    meta: { resourceType: 'Schema' },
  },
  {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
    id: GROUP_SCHEMA,
    name: 'Group',
    description: 'Organization group',
    attributes: [
      attr('displayName', { required: true }),
      attr('externalId', { caseExact: true }),
      attr('members', {
        type: 'complex',
        multiValued: true,
        subAttributes: [
          attr('value', { caseExact: true, mutability: 'immutable' }),
          attr('display', { mutability: 'readOnly' }),
          attr('$ref', { type: 'reference', referenceTypes: ['User'], mutability: 'immutable' }),
        ],
      }),
    ],
    meta: { resourceType: 'Schema' },
  },
]

function resourceTypes(c: Ctx): Json[] {
  return [
    { id: 'User', name: 'User', endpoint: '/Users', schema: USER_SCHEMA },
    { id: 'Group', name: 'Group', endpoint: '/Groups', schema: GROUP_SCHEMA },
  ].map((r) => ({
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
    ...r,
    description: `${r.name} resources`,
    meta: { resourceType: 'ResourceType', location: `${baseUrl(c)}/ResourceTypes/${r.id}` },
  }))
}

function serviceProviderConfig(c: Ctx): Json {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
    patch: { supported: true },
    bulk: { supported: false, maxOperations: 0, maxPayloadSize: 0 },
    filter: { supported: true, maxResults: MAX_COUNT },
    changePassword: { supported: false },
    sort: { supported: false },
    etag: { supported: false },
    authenticationSchemes: [
      {
        type: 'oauthbearertoken',
        name: 'OAuth Bearer Token',
        description: 'The organization SCIM API key sent as a Bearer token.',
        primary: true,
      },
    ],
    meta: {
      resourceType: 'ServiceProviderConfig',
      location: `${baseUrl(c)}/ServiceProviderConfig`,
    },
  }
}

// ----- routes -----

function register(p: string) {
  scim.get(`${p}/ServiceProviderConfig`, (c) => respond(c, serviceProviderConfig(c)))
  scim.get(`${p}/ResourceTypes`, (c) => {
    const all = resourceTypes(c)
    return respond(c, {
      schemas: [LIST_SCHEMA],
      totalResults: all.length,
      startIndex: 1,
      itemsPerPage: all.length,
      Resources: all,
    })
  })
  scim.get(`${p}/ResourceTypes/:id`, (c) => {
    const r = resourceTypes(c).find((x) => x.id === c.req.param('id'))
    return r ? respond(c, r) : scimError(c, 404, 'Resource type not found.')
  })
  scim.get(`${p}/Schemas`, (c) =>
    respond(c, {
      schemas: [LIST_SCHEMA],
      totalResults: SCHEMAS.length,
      startIndex: 1,
      itemsPerPage: SCHEMAS.length,
      Resources: SCHEMAS,
    }),
  )
  scim.get(`${p}/Schemas/:id`, (c) => {
    const s = SCHEMAS.find((x) => x.id === c.req.param('id'))
    return s ? respond(c, s) : scimError(c, 404, 'Schema not found.')
  })

  scim.use(`${p}/Users`, requireScimAuth)
  scim.use(`${p}/Users/*`, requireScimAuth)
  scim.use(`${p}/Groups`, requireScimAuth)
  scim.use(`${p}/Groups/*`, requireScimAuth)

  scim.get(`${p}/Users`, async (c) => {
    const rows = await loadUsers(createDb(c.env.DB), orgOf(c))
    return listResponse(
      c,
      rows.map((r) => userResource(c, r)),
    )
  })

  scim.get(`${p}/Users/:id`, async (c) => {
    const r = await loadUser(createDb(c.env.DB), orgOf(c), c.req.param('id'))
    return respond(c, project(c, userResource(c, r)))
  })

  scim.post(`${p}/Users`, async (c) => {
    const body = await readJson(c)
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const email = emailFrom(body)
    if (!email) throw new ScimError(400, 'An email address is required.', 'invalidValue')
    const externalId = stringOrNull(prop(body, 'externalId'))
    const rows = await loadUsers(db, orgUuid)
    if (
      rows.some(
        (r) => emailOf(r).toLowerCase() === email || (externalId && r.m.externalId === externalId),
      )
    ) {
      throw new ScimError(409, 'User already exists.', 'uniqueness')
    }
    const m = await invitedMember(db, orgUuid, { email, externalId })
    const active = scimBool(prop(body, 'active')) !== false
    if (!active) m.status = Status.Revoked
    await batch(db, [
      ...insertMemberStatements(db, m, `organization:${orgUuid}`),
      ev(db, c, {
        type: EventType.OrganizationUserInvited,
        organizationUserUuid: m.uuid,
        userUuid: m.userUuid,
      }),
      ...(active
        ? []
        : [
            ev(db, c, {
              type: EventType.OrganizationUserRevoked,
              organizationUserUuid: m.uuid,
              userUuid: m.userUuid,
            }),
          ]),
    ])
    if (active) await sendInvite(c, await requireOrg(db, orgUuid), m)
    const created = userResource(c, await loadUser(db, orgUuid, m.uuid))
    return respond(c, created, 201, { Location: String((created.meta as Json).location) })
  })

  scim.put(`${p}/Users/:id`, async (c) => {
    const body = await readJson(c)
    const db = createDb(c.env.DB)
    const current = await loadUser(db, orgOf(c), c.req.param('id'))
    await updateUser(c, db, current, body)
    return respond(c, userResource(c, await loadUser(db, orgOf(c), current.m.uuid)))
  })

  scim.patch(`${p}/Users/:id`, async (c) => {
    const ops = patchOperations(await readJson(c))
    const db = createDb(c.env.DB)
    const current = await loadUser(db, orgOf(c), c.req.param('id'))
    const desired = applyPatch(userResource(c, current), ops)
    await updateUser(c, db, current, desired)
    return respond(c, userResource(c, await loadUser(db, orgOf(c), current.m.uuid)))
  })

  scim.delete(`${p}/Users/:id`, async (c) => {
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const { m } = await loadUser(db, orgUuid, c.req.param('id'))
    assertCanAssign(systemActor(orgUuid), m.atype)
    await assertNotLastOwner(db, orgUuid, m)
    await batch(db, [
      bumpOrgRevision(db, orgUuid, Date.now()),
      db.delete(schema.usersOrganizations).where(eq(schema.usersOrganizations.uuid, m.uuid)),
      ev(db, c, {
        type: EventType.OrganizationUserRemoved,
        organizationUserUuid: m.uuid,
        userUuid: m.userUuid,
      }),
    ])
    return c.body(null, 204)
  })

  scim.get(`${p}/Groups`, async (c) => {
    const groups = await loadGroups(createDb(c.env.DB), orgOf(c))
    return listResponse(
      c,
      groups.map((g) => groupResource(c, g.group, g.members)),
    )
  })

  scim.get(`${p}/Groups/:id`, async (c) => {
    const g = await loadGroup(createDb(c.env.DB), orgOf(c), c.req.param('id'))
    return respond(c, project(c, groupResource(c, g.group, g.members)))
  })

  scim.post(`${p}/Groups`, async (c) => {
    const body = await readJson(c)
    const db = createDb(c.env.DB)
    const externalId = stringOrNull(prop(body, 'externalId'))
    const name = stringOrNull(prop(body, 'displayName'))
    const all = await loadGroups(db, orgOf(c))
    if (
      all.some(
        (g) =>
          (externalId && g.group.externalId === externalId) ||
          (!externalId && g.group.name === name),
      )
    ) {
      throw new ScimError(409, 'Group already exists.', 'uniqueness')
    }
    const uuid = await saveGroup(c, db, null, body, true)
    const g = await loadGroup(db, orgOf(c), uuid)
    const created = groupResource(c, g.group, g.members)
    return respond(c, created, 201, { Location: String((created.meta as Json).location) })
  })

  scim.put(`${p}/Groups/:id`, async (c) => {
    const body = await readJson(c)
    const db = createDb(c.env.DB)
    const current = await loadGroup(db, orgOf(c), c.req.param('id'))
    await saveGroup(c, db, current.group, body, false)
    const g = await loadGroup(db, orgOf(c), current.group.uuid)
    return respond(c, groupResource(c, g.group, g.members))
  })

  scim.patch(`${p}/Groups/:id`, async (c) => {
    const ops = patchOperations(await readJson(c))
    const db = createDb(c.env.DB)
    const current = await loadGroup(db, orgOf(c), c.req.param('id'))
    const desired = applyPatch(groupResource(c, current.group, current.members), ops)
    await saveGroup(c, db, current.group, desired, true)
    const g = await loadGroup(db, orgOf(c), current.group.uuid)
    // RFC 7644 allows 204 for PATCH; returning the resource helps Okta and Entra ID alike.
    return respond(c, groupResource(c, g.group, g.members))
  })

  scim.delete(`${p}/Groups/:id`, async (c) => {
    const db = createDb(c.env.DB)
    const orgUuid = orgOf(c)
    const { group } = await loadGroup(db, orgUuid, c.req.param('id'))
    await batch(db, [
      bumpOrgRevision(db, orgUuid, Date.now()),
      db.delete(schema.groups).where(eq(schema.groups.uuid, group.uuid)),
      ev(db, c, { type: EventType.GroupDeleted, groupUuid: group.uuid }),
    ])
    return c.body(null, 204)
  })
}

for (const p of PREFIXES) register(p)

scim.onError((err, c) => {
  if (err instanceof ScimError) return scimError(c, err.status, err.message, err.scimType)
  if (err instanceof ApiError) return scimError(c, err.status, err.message)
  log(
    'error',
    'unhandled',
    { errorKind: errorKind(err), method: c.req.method, route: c.req.routePath },
    c.env,
  )
  return scimError(c, 500, 'An error has occurred.')
})
