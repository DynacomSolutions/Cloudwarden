// Admin Console API for Cloudwarden's own SCIM settings and event integrations (TASKS #263,
// #264). These are Cloudwarden endpoints (the upstream screens for these features are not open
// source); the web client pages under `web/apps/web/src/app/cloudwarden/` call them.
import { and, eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import {
  type IntegrationRow,
  latestEventCursor,
  openSecrets,
  secretsPurpose,
  sendEvents,
} from '../integrations/deliver'
import {
  DESTINATIONS,
  DeliveryError,
  INTEGRATION_TYPES,
  type IntegrationType,
  newSigningSecret,
} from '../integrations/destinations'
import { isAdminRole, requireMember, requirePermission } from '../orgs/access'
import { ApiKeyType, loadApiKey } from '../orgs/api-keys'
import { seal } from '../orgs/sealed'
import { authOnce } from '../orgs/util'
import { parseBody } from '../validation'

export const orgIntegrations = new Hono<Env>()
orgIntegrations.use('/api/organizations/*', authOnce)

type Ctx = Context<Env>
const org = (c: Ctx) => c.req.param('orgId') ?? ''

// ----- SCIM settings -----

const scimUrl = (c: Ctx, orgUuid: string) =>
  `${c.env.DOMAIN.replace(/\/+$/, '')}/scim/v2/${orgUuid}`

async function scimJson(c: Ctx, db: Db, orgUuid: string) {
  const [row] = await db
    .select()
    .from(schema.organizationScim)
    .where(eq(schema.organizationScim.organizationUuid, orgUuid))
    .limit(1)
  const key = await loadApiKey(db, orgUuid, ApiKeyType.Scim)
  return {
    object: 'scimConfig',
    enabled: row?.enabled ?? false,
    provider: row?.provider ?? null,
    scimUrl: scimUrl(c, orgUuid),
    hasApiKey: Boolean(key),
    apiKeyRevisionDate: key ? new Date(key.revisionDate).toISOString() : null,
  }
}

orgIntegrations.get('/api/organizations/:orgId/scim-config', async (c) => {
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, org(c), 'manageScim')
  return c.json(await scimJson(c, db, org(c)))
})

orgIntegrations.put('/api/organizations/:orgId/scim-config', async (c) => {
  const body = await parseBody(
    c,
    z.object({ enabled: z.boolean(), provider: z.number().int().min(0).max(20).nullish() }),
  )
  const db = createDb(c.env.DB)
  await requirePermission(db, c.var.user.uuid, org(c), 'manageScim')
  const now = Date.now()
  await db
    .insert(schema.organizationScim)
    .values({
      organizationUuid: org(c),
      enabled: body.enabled,
      provider: body.provider ?? null,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: schema.organizationScim.organizationUuid,
      set: { enabled: body.enabled, provider: body.provider ?? null, updatedAt: now },
    })
  return c.json(await scimJson(c, db, org(c)))
})

// ----- event integrations -----

/** Owners and admins manage integrations: they hold credentials for outside systems. */
async function requireAdmin(c: Ctx) {
  const m = await requireMember(createDb(c.env.DB), c.var.user.uuid, org(c))
  if (!isAdminRole(m)) throw new ApiError(403, 'Only owners and admins can manage integrations.')
  return m
}

const iso = (ms: number | null) => (ms ? new Date(ms).toISOString() : null)

function integrationJson(row: IntegrationRow, revealed: Record<string, unknown> | null = null) {
  return {
    object: 'eventIntegration',
    id: row.uuid,
    type: row.atype,
    name: row.name,
    enabled: row.enabled,
    config: JSON.parse(row.config) as Record<string, unknown>,
    eventTypes: row.eventTypes ? (JSON.parse(row.eventTypes) as number[]) : null,
    status: {
      failureCount: row.failureCount,
      nextAttemptDate: iso(row.nextAttemptAt),
      lastError: row.lastError,
      lastSuccessDate: iso(row.lastSuccessAt),
    },
    // Only on creation or rotation: the webhook signing secret the receiver must hold.
    ...(revealed ? { signingSecret: revealed.signingSecret ?? null } : {}),
  }
}

const baseSchema = z.object({
  type: z.enum(INTEGRATION_TYPES),
  name: z.string().trim().min(1).max(100),
  enabled: z.boolean().nullish(),
  config: z.record(z.string(), z.unknown()),
  secrets: z.record(z.string(), z.unknown()).nullish(),
  eventTypes: z.array(z.number().int().min(1000).max(9999)).max(200).nullish(),
})

/** Validates settings and secrets for a type, giving field errors the web client shows. */
function validate(type: IntegrationType, config: unknown, secrets: unknown) {
  const dest = DESTINATIONS[type]
  const errors: Record<string, string[]> = {}
  const cfg = dest.config.safeParse(config)
  if (!cfg.success) {
    for (const i of cfg.error.issues) errors[`config.${i.path.join('.')}`] = [i.message]
  }
  const sec = dest.secrets.safeParse(secrets)
  if (!sec.success) {
    for (const i of sec.error.issues) errors[`secrets.${i.path.join('.')}`] = [i.message]
  }
  if (!cfg.success || !sec.success) throw new ApiError(400, 'The request is invalid.', errors)
  return {
    config: cfg.data as Record<string, unknown>,
    secrets: sec.data as Record<string, unknown>,
  }
}

/** Drops blank values so they do not overwrite stored secrets. */
const filled = (s: Record<string, unknown> | null | undefined) =>
  Object.fromEntries(Object.entries(s ?? {}).filter(([, v]) => v !== '' && v != null))

async function loadIntegration(db: Db, orgUuid: string, id: string) {
  const [row] = await db
    .select()
    .from(schema.orgIntegrations)
    .where(
      and(
        eq(schema.orgIntegrations.uuid, id),
        eq(schema.orgIntegrations.organizationUuid, orgUuid),
      ),
    )
    .limit(1)
  if (!row) throw new ApiError(404, 'Integration not found.')
  return row
}

orgIntegrations.get('/api/organizations/:orgId/event-integrations', async (c) => {
  await requireAdmin(c)
  const rows = await createDb(c.env.DB)
    .select()
    .from(schema.orgIntegrations)
    .where(eq(schema.orgIntegrations.organizationUuid, org(c)))
  return c.json({
    object: 'list',
    data: rows.map((r) => integrationJson(r)),
    continuationToken: null,
  })
})

orgIntegrations.post('/api/organizations/:orgId/event-integrations', async (c) => {
  const body = await parseBody(c, baseSchema)
  await requireAdmin(c)
  const db = createDb(c.env.DB)
  const given = filled(body.secrets)
  if (body.type === 'webhook' && !given.signingSecret) given.signingSecret = newSigningSecret()
  const { config, secrets } = validate(body.type, body.config, given)
  const uuid = crypto.randomUUID()
  const now = Date.now()
  await db.insert(schema.orgIntegrations).values({
    uuid,
    organizationUuid: org(c),
    atype: body.type,
    name: body.name,
    enabled: body.enabled !== false,
    config: JSON.stringify(config),
    sealedSecrets: await seal(c.env, secretsPurpose(uuid), JSON.stringify(secrets)),
    eventTypes: body.eventTypes?.length ? JSON.stringify(body.eventTypes) : null,
    // Starts with events written from now on; history is available through export.
    cursor: await latestEventCursor(db, org(c)),
    createdAt: now,
    updatedAt: now,
  })
  return c.json(integrationJson(await loadIntegration(db, org(c), uuid), secrets))
})

orgIntegrations.put('/api/organizations/:orgId/event-integrations/:id', async (c) => {
  const body = await parseBody(c, baseSchema.omit({ type: true }))
  await requireAdmin(c)
  const db = createDb(c.env.DB)
  const row = await loadIntegration(db, org(c), c.req.param('id'))
  const merged = { ...(await openSecrets(c.env, row)), ...filled(body.secrets) }
  const { config, secrets } = validate(row.atype as IntegrationType, body.config, merged)
  await db
    .update(schema.orgIntegrations)
    .set({
      name: body.name,
      enabled: body.enabled !== false,
      config: JSON.stringify(config),
      sealedSecrets: await seal(c.env, secretsPurpose(row.uuid), JSON.stringify(secrets)),
      eventTypes: body.eventTypes?.length ? JSON.stringify(body.eventTypes) : null,
      // A changed configuration is tried again straight away.
      failureCount: 0,
      nextAttemptAt: 0,
      lastError: null,
      updatedAt: Date.now(),
    })
    .where(eq(schema.orgIntegrations.uuid, row.uuid))
  return c.json(integrationJson(await loadIntegration(db, org(c), row.uuid)))
})

orgIntegrations.post(
  '/api/organizations/:orgId/event-integrations/:id/rotate-secret',
  async (c) => {
    await requireAdmin(c)
    const db = createDb(c.env.DB)
    const row = await loadIntegration(db, org(c), c.req.param('id'))
    if (row.atype !== 'webhook') throw new ApiError(400, 'Only webhooks have a signing secret.')
    const secrets = { ...(await openSecrets(c.env, row)), signingSecret: newSigningSecret() }
    await db
      .update(schema.orgIntegrations)
      .set({
        sealedSecrets: await seal(c.env, secretsPurpose(row.uuid), JSON.stringify(secrets)),
        updatedAt: Date.now(),
      })
      .where(eq(schema.orgIntegrations.uuid, row.uuid))
    return c.json(integrationJson(await loadIntegration(db, org(c), row.uuid), secrets))
  },
)

orgIntegrations.delete('/api/organizations/:orgId/event-integrations/:id', async (c) => {
  await requireAdmin(c)
  const db = createDb(c.env.DB)
  const row = await loadIntegration(db, org(c), c.req.param('id'))
  await db.delete(schema.orgIntegrations).where(eq(schema.orgIntegrations.uuid, row.uuid))
  return c.body(null, 200)
})

/** Sends one synthetic event (type 1600, organisation updated) to check the settings. */
orgIntegrations.post('/api/organizations/:orgId/event-integrations/:id/test', async (c) => {
  await requireAdmin(c)
  const db = createDb(c.env.DB)
  const row = await loadIntegration(db, org(c), c.req.param('id'))
  const now = Date.now()
  try {
    await sendEvents(
      c.env,
      row,
      [
        {
          id: crypto.randomUUID(),
          object: 'event',
          type: 1600,
          organizationId: row.organizationUuid,
          actingUserId: c.var.user.uuid,
          date: new Date(now).toISOString(),
          test: true,
        },
      ],
      (input, init) => fetch(input, init),
      now,
    )
    return c.json({ object: 'eventIntegrationTest', success: true, error: null })
  } catch (err) {
    const error =
      err instanceof DeliveryError ? err.message : 'The destination could not be reached.'
    return c.json({ object: 'eventIntegrationTest', success: false, error })
  }
})
