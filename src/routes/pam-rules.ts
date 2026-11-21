// Access rules (docs/privileged-access.md): which collections need a lease and on what terms.
// Owners and admins only. A collection belongs to at most one rule.
import { and, eq, inArray } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb, type Db, runBatch, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { isAdminRole, requireMember } from '../orgs/access'
import { authOnce } from '../orgs/util'
import { auditStatement } from '../pam/audit'
import { DEFAULT_LEASE_SECONDS, MAX_LEASE_SECONDS, RequestStatus } from '../pam/constants'
import { iso, list } from '../pam/views'
import { parseBody } from '../validation'

export const pamRules = new Hono<Env>()

type Ctx = Context<Env>

const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
const BASE = '/api/organizations/:orgId/access-rules'
for (const path of [BASE, `${BASE}/*`]) pamRules.use(path, authOnce)

const MAX_CONDITIONS = 4000
const MIN_LEASE_SECONDS = 60
const seconds = z.number().int().min(MIN_LEASE_SECONDS).max(MAX_LEASE_SECONDS)

const ruleSchema = z.object({
  name: z.string().trim().min(1).max(100),
  description: z.string().max(1000).nullish(),
  enabled: z.boolean().nullish(),
  conditions: z
    .unknown()
    .refine((v) => v == null || (typeof v === 'object' && !Array.isArray(v)), {
      message: 'Conditions must be an object.',
    })
    .refine((v) => (JSON.stringify(v ?? null) ?? '').length <= MAX_CONDITIONS, {
      message: 'Conditions are too large.',
    }),
  singleActiveLease: z.boolean().nullish(),
  defaultLeaseDurationSeconds: seconds.nullish(),
  maxLeaseDurationSeconds: seconds.nullish(),
  allowsExtensions: z.boolean().nullish(),
  maxExtensionDurationSeconds: seconds.nullish(),
  collections: z.array(z.string().uuid()).max(500),
})
type RuleBody = z.infer<typeof ruleSchema>

async function admin(c: Ctx, db: Db) {
  const orgUuid = c.req.param('orgId') ?? ''
  const m = await requireMember(db, c.var.user.uuid, orgUuid)
  if (!isAdminRole(m)) throw new ApiError(403, 'You do not have permission to do this.')
  return orgUuid
}

type RuleRow = typeof schema.pamAccessRules.$inferSelect

function ruleJson(r: RuleRow, collections: string[]) {
  let conditions: unknown = null
  try {
    conditions = r.conditions ? JSON.parse(r.conditions) : null
  } catch {
    conditions = null
  }
  return {
    object: 'accessRule',
    id: r.uuid,
    organizationId: r.organizationUuid,
    name: r.name,
    description: r.description,
    enabled: r.enabled,
    conditions,
    singleActiveLease: r.singleActiveLease,
    defaultLeaseDurationSeconds: r.defaultLeaseSeconds,
    maxLeaseDurationSeconds: r.maxLeaseSeconds,
    allowsExtensions: r.allowsExtensions,
    maxExtensionDurationSeconds: r.maxExtensionSeconds,
    collections,
    creationDate: iso(r.createdAt),
    revisionDate: iso(r.updatedAt),
  }
}

const collectionsOf = async (db: Db, ruleUuids: string[]) => {
  const map = new Map<string, string[]>()
  if (ruleUuids.length === 0) return map
  const rows = await db
    .select()
    .from(schema.pamRuleCollections)
    .where(inArray(schema.pamRuleCollections.ruleUuid, ruleUuids))
  for (const r of rows) map.set(r.ruleUuid, [...(map.get(r.ruleUuid) ?? []), r.collectionUuid])
  return map
}

async function ruleOf(db: Db, orgUuid: string, id: string) {
  const [row] = await db
    .select()
    .from(schema.pamAccessRules)
    .where(
      and(eq(schema.pamAccessRules.uuid, id), eq(schema.pamAccessRules.organizationUuid, orgUuid)),
    )
    .limit(1)
  if (!row) throw new ApiError(404, 'Access rule not found.')
  return row
}

/** Normalised column values, with the lease terms checked against each other. */
function terms(body: RuleBody) {
  const def = body.defaultLeaseDurationSeconds ?? DEFAULT_LEASE_SECONDS
  const max = body.maxLeaseDurationSeconds ?? Math.max(def, 24 * 3600)
  if (def > max) {
    throw new ApiError(400, 'The request is invalid.', {
      defaultLeaseDurationSeconds: ['The default duration must not exceed the maximum.'],
    })
  }
  const allows = body.allowsExtensions ?? false
  return {
    name: body.name,
    description: body.description ?? null,
    enabled: body.enabled ?? true,
    conditions: body.conditions == null ? null : JSON.stringify(body.conditions),
    singleActiveLease: body.singleActiveLease ?? false,
    defaultLeaseSeconds: def,
    maxLeaseSeconds: max,
    allowsExtensions: allows,
    maxExtensionSeconds: allows ? (body.maxExtensionDurationSeconds ?? def) : null,
  }
}

/** Collections must belong to the organisation and to no other rule. */
async function checkCollections(db: Db, orgUuid: string, ids: string[], ruleUuid: string | null) {
  const unique = [...new Set(ids)]
  if (unique.length === 0) return unique
  const found = await db
    .select({ id: schema.collections.uuid })
    .from(schema.collections)
    .where(
      and(
        eq(schema.collections.organizationUuid, orgUuid),
        inArray(schema.collections.uuid, unique),
      ),
    )
  if (found.length !== unique.length) {
    throw new ApiError(400, 'The request is invalid.', { collections: ['Unknown collection.'] })
  }
  const taken = await db
    .select({
      id: schema.pamRuleCollections.collectionUuid,
      rule: schema.pamRuleCollections.ruleUuid,
    })
    .from(schema.pamRuleCollections)
    .where(inArray(schema.pamRuleCollections.collectionUuid, unique))
  if (taken.some((t) => t.rule !== ruleUuid)) {
    throw new ApiError(409, 'A collection already belongs to another access rule.')
  }
  return unique
}

pamRules.get(BASE, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const rows = await db
    .select()
    .from(schema.pamAccessRules)
    .where(eq(schema.pamAccessRules.organizationUuid, orgUuid))
    .orderBy(schema.pamAccessRules.name)
  const cols = await collectionsOf(
    db,
    rows.map((r) => r.uuid),
  )
  return c.json(list(rows.map((r) => ruleJson(r, cols.get(r.uuid) ?? []))))
})

pamRules.post(BASE, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const body = await parseBody(c, ruleSchema)
  const values = terms(body)
  const cols = await checkCollections(db, orgUuid, body.collections, null)
  const now = Date.now()
  const row: RuleRow = {
    uuid: crypto.randomUUID(),
    organizationUuid: orgUuid,
    ...values,
    createdAt: now,
    updatedAt: now,
  }
  await runBatch(db, [
    db.insert(schema.pamAccessRules).values(row),
    ...cols.map((collectionUuid) =>
      db.insert(schema.pamRuleCollections).values({ ruleUuid: row.uuid, collectionUuid }),
    ),
    auditStatement(db, orgUuid, 'rule_created', c.var.user.uuid, row.uuid, null, now),
  ])
  return c.json(ruleJson(row, cols))
})

pamRules.get(`${BASE}/:id{${UUID}}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const row = await ruleOf(db, orgUuid, c.req.param('id'))
  return c.json(ruleJson(row, (await collectionsOf(db, [row.uuid])).get(row.uuid) ?? []))
})

pamRules.put(`${BASE}/:id{${UUID}}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const row = await ruleOf(db, orgUuid, c.req.param('id'))
  const body = await parseBody(c, ruleSchema)
  const values = terms(body)
  const cols = await checkCollections(db, orgUuid, body.collections, row.uuid)
  const now = Date.now()
  await runBatch(db, [
    db
      .update(schema.pamAccessRules)
      .set({ ...values, updatedAt: now })
      .where(eq(schema.pamAccessRules.uuid, row.uuid)),
    db.delete(schema.pamRuleCollections).where(eq(schema.pamRuleCollections.ruleUuid, row.uuid)),
    ...cols.map((collectionUuid) =>
      db.insert(schema.pamRuleCollections).values({ ruleUuid: row.uuid, collectionUuid }),
    ),
    auditStatement(db, orgUuid, 'rule_updated', c.var.user.uuid, row.uuid, null, now),
  ])
  return c.json(ruleJson({ ...row, ...values, updatedAt: now }, cols))
})

pamRules.delete(`${BASE}/:id{${UUID}}`, async (c) => {
  const db = createDb(c.env.DB)
  const orgUuid = await admin(c, db)
  const row = await ruleOf(db, orgUuid, c.req.param('id'))
  const now = Date.now()
  await runBatch(db, [
    // Requests still waiting on the rule can no longer be decided.
    db
      .update(schema.pamAccessRequests)
      .set({ status: RequestStatus.Cancelled, resolvedAt: now, updatedAt: now })
      .where(
        and(
          eq(schema.pamAccessRequests.ruleUuid, row.uuid),
          eq(schema.pamAccessRequests.status, RequestStatus.Pending),
        ),
      ),
    db.delete(schema.pamAccessRules).where(eq(schema.pamAccessRules.uuid, row.uuid)),
    auditStatement(db, orgUuid, 'rule_deleted', c.var.user.uuid, row.uuid, null, now),
  ])
  return c.body(null, 200)
})
