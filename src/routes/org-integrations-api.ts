// Client integrations API (TASKS #332): `/api/organizations/{orgId}/integrations` and its
// configurations, as the generated clients call them. They sit on the event integration storage
// behind `/event-integrations`: a Hec integration is a Splunk row, Datadog a Datadog row, Webhook
// a signed webhook row. Secrets (tokens, API keys) are sealed and never returned. Slack and Teams
// need OAuth apps this server does not have, so they answer 400. Templates and filters are stored
// and returned; delivery keeps the fixed formats and honours the event types.
import { and, eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { latestEventCursor, openSecrets, secretsPurpose } from '../integrations/deliver'
import {
  DATADOG_SITES,
  DESTINATIONS,
  type IntegrationType,
  newSigningSecret,
} from '../integrations/destinations'
import { EventType } from '../orgs/constants'
import { eventStatement } from '../orgs/events'
import { seal } from '../orgs/sealed'
import { authOnce, batch } from '../orgs/util'
import { parseBody } from '../validation'
import { filled, loadIntegration, requireAdmin, validate } from './org-integrations'

export const orgIntegrationsApi = new Hono<Env>()

type Ctx = Context<Env>
type Row = typeof schema.orgIntegrations.$inferSelect
type ConfigRow = typeof schema.orgIntegrationConfigurations.$inferSelect

const org = (c: Ctx) => c.req.param('orgId') ?? ''
const CLOUD_TYPES: Record<number, IntegrationType> = { 4: 'webhook', 5: 'splunk', 6: 'datadog' }
const CLOUD_NUMBER: Partial<Record<string, number>> = { webhook: 4, splunk: 5, datadog: 6 }
const LABEL: Record<string, string> = { webhook: 'Webhook', splunk: 'Splunk', datadog: 'Datadog' }

const noOAuth = (what: string) => () => {
  throw new ApiError(
    400,
    `${what} integrations are not available: this server has no ${what} app configured.`,
  )
}

const lowerFirst = (s: string) => s.charAt(0).toLowerCase() + s.slice(1)

/** The `configuration` string of a request as an object with lower-case first letters. */
function parseConfiguration(raw: string | null | undefined): Record<string, unknown> | null {
  if (raw == null || raw.trim() === '') return null
  let v: unknown
  try {
    v = JSON.parse(raw)
  } catch {
    throw new ApiError(400, 'The request is invalid.', {
      configuration: ['Configuration must be valid JSON.'],
    })
  }
  if (!v || typeof v !== 'object' || Array.isArray(v)) {
    throw new ApiError(400, 'The request is invalid.', {
      configuration: ['Configuration must be a JSON object.'],
    })
  }
  return Object.fromEntries(Object.entries(v).map(([k, x]) => [lowerFirst(k), x]))
}

const str = (v: unknown) => (typeof v === 'string' && v !== '' ? v : undefined)

const integrationBody = z.object({
  type: z.number().int(),
  configuration: z.string().max(8192).nullish(),
})
const configurationBody = z.object({
  configuration: z.string().max(8192).nullish(),
  eventType: z.number().int().min(1000).max(9999).nullish(),
  filters: z.string().max(8192).nullish(),
  template: z.string().max(16384).nullish(),
})

/** Integration-level settings and secrets from the request, per type. */
function integrationSettings(type: IntegrationType, raw: string | null | undefined) {
  const cfg = parseConfiguration(raw)
  if (type === 'webhook') {
    if (cfg) {
      throw new ApiError(400, 'The request is invalid.', {
        configuration: ['Webhook settings belong to the configuration.'],
      })
    }
    return { config: {}, secrets: {} }
  }
  if (!cfg) {
    throw new ApiError(400, 'The request is invalid.', {
      configuration: ['Configuration is required.'],
    })
  }
  if (type === 'splunk') {
    return {
      config: { url: str(cfg.uri), source: str(cfg.service) },
      secrets: { token: str(cfg.token) },
    }
  }
  const host = (() => {
    try {
      return new URL(String(cfg.uri)).hostname
    } catch {
      return ''
    }
  })()
  const site = DATADOG_SITES.find((s) => host === `http-intake.logs.${s}`)
  if (!site) {
    throw new ApiError(400, 'The request is invalid.', {
      'configuration.uri': ['Enter a Datadog log intake address.'],
    })
  }
  return { config: { site }, secrets: { apiKey: str(cfg.apiKey) } }
}

/** What clients may see of a row's settings: never a token or key. */
function publicConfiguration(row: Row): string | null {
  const cfg = JSON.parse(row.config) as Record<string, unknown>
  if (row.atype === 'splunk' && cfg.url) {
    return JSON.stringify({ uri: cfg.url, scheme: 'Splunk', service: cfg.source ?? null })
  }
  if (row.atype === 'datadog' && cfg.site) {
    return JSON.stringify({ uri: `https://http-intake.logs.${cfg.site}/api/v2/logs` })
  }
  return null
}

const integrationJson = (row: Row) => ({
  object: 'organizationIntegration',
  id: row.uuid,
  type: CLOUD_NUMBER[row.atype] ?? 0,
  configuration: publicConfiguration(row),
  status: 0,
})

const iso = (ms: number) => new Date(ms).toISOString()

function configurationJson(row: Row, cfg: ConfigRow) {
  return {
    object: 'organizationIntegrationConfiguration',
    id: cfg.uuid,
    configuration: row.atype === 'webhook' ? cfg.config : null,
    filters: cfg.filters,
    creationDate: iso(cfg.createdAt),
    eventType: cfg.eventType,
    template: cfg.template,
  }
}

async function cloudIntegration(c: Ctx, db: Db) {
  await requireAdmin(c)
  const row = await loadIntegration(db, org(c), c.req.param('integrationId') ?? '')
  if (!CLOUD_NUMBER[row.atype]) throw new ApiError(404, 'Integration not found.')
  return row
}

const configsOf = (db: Db, integrationUuid: string) =>
  db
    .select()
    .from(schema.orgIntegrationConfigurations)
    .where(eq(schema.orgIntegrationConfigurations.integrationUuid, integrationUuid))
    .orderBy(schema.orgIntegrationConfigurations.createdAt)

/**
 * Delivery follows the configurations: none means off, a null event type means every type. The
 * returned update goes into the same batch as the configuration change it reflects.
 */
function deliveryStatement(
  db: Db,
  row: Row,
  configs: { eventType: number | null }[],
  restartAt: number | null,
  valid: boolean,
  extra: Partial<Row> = {},
) {
  const types = configs.some((x) => x.eventType == null)
    ? null
    : [...new Set(configs.map((x) => x.eventType as number))]
  return db
    .update(schema.orgIntegrations)
    .set({
      enabled: configs.length > 0 && valid,
      eventTypes: types?.length ? JSON.stringify(types) : null,
      // Starting fresh must not replay the whole history.
      ...(restartAt !== null && configs.length > 0 ? { cursor: restartAt } : {}),
      failureCount: 0,
      nextAttemptAt: 0,
      lastError: null,
      updatedAt: Date.now(),
      ...extra,
    })
    .where(eq(schema.orgIntegrations.uuid, row.uuid))
}

const audit = (c: Ctx, db: Db) =>
  eventStatement(db, c, { type: EventType.OrganizationUpdated, organizationUuid: org(c) })

// ----- integrations -----

orgIntegrationsApi.get('/api/organizations/:orgId/integrations', authOnce, async (c) => {
  await requireAdmin(c)
  const rows = await createDb(c.env.DB)
    .select()
    .from(schema.orgIntegrations)
    .where(eq(schema.orgIntegrations.organizationUuid, org(c)))
  return c.json(rows.filter((r) => CLOUD_NUMBER[r.atype]).map(integrationJson))
})

orgIntegrationsApi.post('/api/organizations/:orgId/integrations', authOnce, async (c) => {
  const body = await parseBody(c, integrationBody)
  await requireAdmin(c)
  if (body.type === 3 || body.type === 7) {
    return noOAuth(body.type === 3 ? 'Slack' : 'Teams')()
  }
  const type = CLOUD_TYPES[body.type]
  if (!type) throw new ApiError(400, 'This integration type is not supported on this server.')
  const { config, secrets } = integrationSettings(type, body.configuration)
  const valid = type !== 'webhook' ? validate(type, config, secrets) : { config, secrets }
  const db = createDb(c.env.DB)
  const uuid = crypto.randomUUID()
  const now = Date.now()
  await batch(db, [
    db.insert(schema.orgIntegrations).values({
      uuid,
      organizationUuid: org(c),
      atype: type,
      name: LABEL[type] ?? type,
      // Nothing is delivered until a configuration exists.
      enabled: false,
      config: JSON.stringify(valid.config),
      sealedSecrets: await seal(c.env, secretsPurpose(uuid), JSON.stringify(valid.secrets)),
      cursor: await latestEventCursor(db, org(c)),
      createdAt: now,
      updatedAt: now,
    }),
    audit(c, db),
  ])
  return c.json(integrationJson(await loadIntegration(db, org(c), uuid)))
})

orgIntegrationsApi.put(
  '/api/organizations/:orgId/integrations/:integrationId',
  authOnce,
  async (c) => {
    const body = await parseBody(c, integrationBody)
    const db = createDb(c.env.DB)
    const row = await cloudIntegration(c, db)
    if (CLOUD_NUMBER[row.atype] !== body.type) {
      throw new ApiError(400, 'The integration type cannot be changed.')
    }
    const type = row.atype as IntegrationType
    const { config, secrets } = integrationSettings(type, body.configuration)
    if (type !== 'webhook') {
      const dest = DESTINATIONS[type]
      const stored = await openSecrets(c.env, row)
      const old = JSON.parse(row.config) as Record<string, unknown>
      const next = dest.config.safeParse({ ...old, ...config })
      // A new destination takes no stored secret along: it must be sent again.
      const retargeted =
        next.success && dest.target(next.data) !== dest.target(dest.config.parse(old))
      const merged = { ...(retargeted ? {} : stored), ...filled(secrets) }
      const valid = validate(type, { ...old, ...config }, merged)
      await batch(db, [
        db
          .update(schema.orgIntegrations)
          .set({
            config: JSON.stringify(valid.config),
            sealedSecrets: await seal(
              c.env,
              secretsPurpose(row.uuid),
              JSON.stringify(valid.secrets),
            ),
            failureCount: 0,
            nextAttemptAt: 0,
            lastError: null,
            updatedAt: Date.now(),
          })
          .where(eq(schema.orgIntegrations.uuid, row.uuid)),
        audit(c, db),
      ])
    }
    return c.json(integrationJson(await loadIntegration(db, org(c), row.uuid)))
  },
)

orgIntegrationsApi.delete(
  '/api/organizations/:orgId/integrations/:integrationId',
  authOnce,
  async (c) => {
    const db = createDb(c.env.DB)
    const row = await cloudIntegration(c, db)
    await batch(db, [
      db.delete(schema.orgIntegrations).where(eq(schema.orgIntegrations.uuid, row.uuid)),
      audit(c, db),
    ])
    return c.body(null, 204)
  },
)

// ----- configurations -----

orgIntegrationsApi.get(
  '/api/organizations/:orgId/integrations/:integrationId/configurations',
  authOnce,
  async (c) => {
    const db = createDb(c.env.DB)
    const row = await cloudIntegration(c, db)
    return c.json((await configsOf(db, row.uuid)).map((x) => configurationJson(row, x)))
  },
)

const SCHEME = /^[A-Za-z0-9._~+-]{1,32}$/
const TOKEN = /^[\x21-\x7e]{1,4096}$/

/** Webhook destination from a configuration: the row's new settings and the non-secret form. */
async function webhookSettings(c: Ctx, row: Row, raw: string | null | undefined) {
  const cfg = parseConfiguration(raw)
  if (!cfg || !str(cfg.uri)) {
    throw new ApiError(400, 'The request is invalid.', {
      'configuration.uri': ['Uri is required.'],
    })
  }
  const token = str(cfg.token)
  const scheme = str(cfg.scheme)
  // Both end up in an Authorization header: no whitespace or control characters.
  if (scheme && !SCHEME.test(scheme)) {
    throw new ApiError(400, 'The request is invalid.', {
      'configuration.scheme': ['Use letters, digits and . _ ~ + - only.'],
    })
  }
  if (token && !TOKEN.test(token)) {
    throw new ApiError(400, 'The request is invalid.', {
      'configuration.token': ['Use printable ASCII characters without spaces.'],
    })
  }
  const stored = await openSecrets(c.env, row)
  const old = JSON.parse(row.config) as Record<string, unknown>
  const config = {
    url: cfg.uri,
    ...(token ? { headerName: 'Authorization' } : {}),
    ...(old.omitIpAddress ? { omitIpAddress: true } : {}),
  }
  // Without a new token, the stored one stays only while the address is unchanged.
  const keepHeader = !token && old.url === cfg.uri && old.headerName
  const secrets = {
    signingSecret: str(stored.signingSecret) ?? newSigningSecret(),
    ...(token ? { headerValue: scheme ? `${scheme} ${token}` : token } : {}),
    ...(keepHeader ? { headerValue: stored.headerValue } : {}),
  }
  if (keepHeader) Object.assign(config, { headerName: old.headerName })
  const valid = validate('webhook', config, secrets)
  return {
    shown: JSON.stringify({ uri: cfg.uri, scheme: scheme ?? null }),
    row: {
      config: JSON.stringify(valid.config),
      sealedSecrets: await seal(c.env, secretsPurpose(row.uuid), JSON.stringify(valid.secrets)),
    },
  }
}

async function writeConfiguration(c: Ctx, existingId: string | null) {
  const body = await parseBody(c, configurationBody)
  const db = createDb(c.env.DB)
  const row = await cloudIntegration(c, db)
  const configs = await configsOf(db, row.uuid)
  const current = existingId ? configs.find((x) => x.uuid === existingId) : undefined
  if (existingId && !current) throw new ApiError(404, 'Configuration not found.')
  let shown: string | null = null
  let rowSet: Partial<Row> = {}
  if (row.atype === 'webhook') {
    if (!existingId && configs.length > 0) {
      throw new ApiError(400, 'A webhook integration takes one configuration.')
    }
    const w = await webhookSettings(c, row, body.configuration)
    shown = w.shown
    rowSet = w.row
  } else if (parseConfiguration(body.configuration)) {
    throw new ApiError(400, 'The request is invalid.', {
      configuration: ['This integration type takes no configuration settings.'],
    })
  }
  const now = Date.now()
  const values = {
    eventType: body.eventType ?? null,
    filters: body.filters ?? null,
    template: body.template ?? null,
    config: shown,
    updatedAt: now,
  }
  const uuid = existingId ?? crypto.randomUUID()
  const next = existingId
    ? configs.map((x) => (x.uuid === existingId ? { ...x, ...values } : x))
    : [...configs, { eventType: values.eventType }]
  const valid = row.atype !== 'webhook' || 'config' in rowSet
  // The configuration, the integration's delivery settings and the audit event commit together.
  await batch(db, [
    existingId
      ? db
          .update(schema.orgIntegrationConfigurations)
          .set(values)
          .where(eq(schema.orgIntegrationConfigurations.uuid, uuid))
      : db
          .insert(schema.orgIntegrationConfigurations)
          .values({ uuid, integrationUuid: row.uuid, createdAt: now, ...values }),
    deliveryStatement(
      db,
      row,
      next,
      configs.length === 0 ? await latestEventCursor(db, org(c)) : null,
      valid,
      rowSet,
    ),
    audit(c, db),
  ])
  const fresh = await loadIntegration(db, org(c), row.uuid)
  const [saved] = await db
    .select()
    .from(schema.orgIntegrationConfigurations)
    .where(eq(schema.orgIntegrationConfigurations.uuid, uuid))
  return c.json(configurationJson(fresh, saved as ConfigRow))
}

orgIntegrationsApi.post(
  '/api/organizations/:orgId/integrations/:integrationId/configurations',
  authOnce,
  (c) => writeConfiguration(c, null),
)
orgIntegrationsApi.put(
  '/api/organizations/:orgId/integrations/:integrationId/configurations/:configurationId',
  authOnce,
  (c) => writeConfiguration(c, c.req.param('configurationId') ?? ''),
)
orgIntegrationsApi.delete(
  '/api/organizations/:orgId/integrations/:integrationId/configurations/:configurationId',
  authOnce,
  async (c) => {
    const db = createDb(c.env.DB)
    const row = await cloudIntegration(c, db)
    const configs = await configsOf(db, row.uuid)
    const id = c.req.param('configurationId') ?? ''
    if (!configs.some((x) => x.uuid === id)) throw new ApiError(404, 'Configuration not found.')
    await batch(db, [
      db
        .delete(schema.orgIntegrationConfigurations)
        .where(
          and(
            eq(schema.orgIntegrationConfigurations.uuid, id),
            eq(schema.orgIntegrationConfigurations.integrationUuid, row.uuid),
          ),
        ),
      deliveryStatement(
        db,
        row,
        configs.filter((x) => x.uuid !== id),
        null,
        true,
      ),
      audit(c, db),
    ])
    return c.body(null, 204)
  },
)

// ----- Slack and Teams: no OAuth app on this server -----

const slack = noOAuth('Slack')
const teams = noOAuth('Teams')
orgIntegrationsApi.get('/api/organizations/:orgId/integrations/slack/redirect', authOnce, slack)
orgIntegrationsApi.get('/api/organizations/:orgId/integrations/teams/redirect', authOnce, teams)
orgIntegrationsApi.get(
  '/api/organizations/:orgId/integrations/:integrationId/teams/channels',
  authOnce,
  teams,
)
orgIntegrationsApi.get('/api/organizations/integrations/slack/create', slack)
orgIntegrationsApi.get('/api/organizations/integrations/teams/create', teams)
orgIntegrationsApi.post('/api/organizations/integrations/teams/incoming', teams)
