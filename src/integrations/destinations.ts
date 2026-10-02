// Event integration destinations (TASKS #264): signed webhooks, Splunk HTTP Event Collector,
// Datadog log intake and Microsoft Sentinel (Azure Monitor Logs Ingestion API). Each destination
// validates its settings and turns a batch of organisation events into HTTP requests. Formats come
// from the public documentation of each product.
import { z } from 'zod'
import { toB64u, utf8 } from '../auth/crypto'
import { validateHost } from '../icons/ssrf'

export type Fetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

/** One organisation event as delivered: the web client's event object plus its id. */
export type EventPayload = Record<string, unknown> & { id: string; type: number; date: string }

export const INTEGRATION_TYPES = ['webhook', 'splunk', 'datadog', 'sentinel'] as const
export type IntegrationType = (typeof INTEGRATION_TYPES)[number]

/** Settings are kept apart from secrets: secrets are sealed and never returned. */
export interface Destination<C, S> {
  config: z.ZodType<C>
  secrets: z.ZodType<S>
  /** Secret fields; the update form leaves blank ones unchanged. */
  secretKeys: (keyof S & string)[]
  /** Events sent per request (1 for webhooks: one signed POST per event). */
  batchSize: number
  send(
    fetcher: Fetcher,
    cfg: C,
    secrets: S,
    events: EventPayload[],
    ctx: SendContext,
  ): Promise<void>
}

export interface SendContext {
  /** Host name of this server, for `host` fields. */
  host: string
  now: number
}

export class DeliveryError extends Error {}

/** HTTPS URL to a public DNS name (no IP literals, credentials or reserved names). */
export const httpsUrl = z
  .string()
  .max(2048)
  .refine((s) => {
    try {
      const u = new URL(s)
      return u.protocol === 'https:' && !u.username && !u.password && validateHost(u.hostname).ok
    } catch {
      return false
    }
  }, 'Enter an https URL on a public host name.')

async function check(res: Response, what: string) {
  if (res.ok) return
  // The response body is not recorded: receivers may echo request content.
  throw new DeliveryError(`${what} answered HTTP ${res.status}.`)
}

const hex = (buf: ArrayBuffer) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')

/** `v1=` HMAC-SHA256 over `<timestamp>.<body>`, hex encoded. */
export async function webhookSignature(secret: string, timestamp: string, body: string) {
  const key = await crypto.subtle.importKey(
    'raw',
    utf8(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  return `v1=${hex(await crypto.subtle.sign('HMAC', key, utf8(`${timestamp}.${body}`)))}`
}

const webhookConfig = z.object({
  url: httpsUrl,
  /** Optional extra header for receivers that want their own credential, e.g. `Authorization`. */
  headerName: z
    .string()
    .regex(/^[A-Za-z0-9-]{1,64}$/)
    .nullish(),
})
const webhookSecrets = z.object({
  signingSecret: z.string().min(16).max(256),
  headerValue: z.string().max(4096).nullish(),
})

export const webhook: Destination<z.infer<typeof webhookConfig>, z.infer<typeof webhookSecrets>> = {
  config: webhookConfig,
  secrets: webhookSecrets,
  secretKeys: ['signingSecret', 'headerValue'],
  batchSize: 1,
  async send(fetcher, cfg, secrets, events, ctx) {
    for (const e of events) {
      const body = JSON.stringify(e)
      const timestamp = String(Math.floor(ctx.now / 1000))
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'User-Agent': 'Cloudwarden-Webhook/1',
        'X-Cloudwarden-Event-Id': e.id,
        'X-Cloudwarden-Timestamp': timestamp,
        'X-Cloudwarden-Signature': await webhookSignature(secrets.signingSecret, timestamp, body),
      }
      if (cfg.headerName && secrets.headerValue) headers[cfg.headerName] = secrets.headerValue
      await check(
        await fetcher(cfg.url, { method: 'POST', headers, body, redirect: 'manual' }),
        'The webhook receiver',
      )
    }
  },
}

const splunkConfig = z.object({
  /** HEC base URL, for example `https://splunk.example.com:8088`. */
  url: httpsUrl,
  index: z.string().max(80).nullish(),
  source: z.string().max(200).nullish(),
  sourcetype: z.string().max(200).nullish(),
})
const splunkSecrets = z.object({ token: z.string().min(1).max(256) })

export function splunkEndpoint(url: string) {
  const u = new URL(url)
  if (!/\/services\/collector(\/event)?\/?$/.test(u.pathname)) {
    u.pathname = `${u.pathname.replace(/\/+$/, '')}/services/collector/event`
  }
  return u.toString()
}

export const splunk: Destination<z.infer<typeof splunkConfig>, z.infer<typeof splunkSecrets>> = {
  config: splunkConfig,
  secrets: splunkSecrets,
  secretKeys: ['token'],
  batchSize: 100,
  async send(fetcher, cfg, secrets, events, ctx) {
    // HEC accepts several event objects concatenated in one body.
    const body = events
      .map((e) =>
        JSON.stringify({
          time: Date.parse(e.date) / 1000,
          host: ctx.host,
          source: cfg.source || 'cloudwarden',
          sourcetype: cfg.sourcetype || '_json',
          ...(cfg.index ? { index: cfg.index } : {}),
          event: e,
        }),
      )
      .join('\n')
    await check(
      await fetcher(splunkEndpoint(cfg.url), {
        method: 'POST',
        headers: { Authorization: `Splunk ${secrets.token}`, 'Content-Type': 'application/json' },
        body,
        redirect: 'manual',
      }),
      'Splunk',
    )
  },
}

/** Datadog sites, from Datadog's site documentation. */
export const DATADOG_SITES = [
  'datadoghq.com',
  'us3.datadoghq.com',
  'us5.datadoghq.com',
  'datadoghq.eu',
  'ap1.datadoghq.com',
  'ap2.datadoghq.com',
  'ddog-gov.com',
] as const

const datadogConfig = z.object({
  site: z.enum(DATADOG_SITES),
  service: z.string().max(100).nullish(),
  tags: z.string().max(1000).nullish(),
})
const datadogSecrets = z.object({ apiKey: z.string().min(1).max(256) })

export const datadog: Destination<z.infer<typeof datadogConfig>, z.infer<typeof datadogSecrets>> = {
  config: datadogConfig,
  secrets: datadogSecrets,
  secretKeys: ['apiKey'],
  batchSize: 100,
  async send(fetcher, cfg, secrets, events, ctx) {
    const body = JSON.stringify(
      events.map((e) => ({
        ddsource: 'cloudwarden',
        service: cfg.service || 'cloudwarden',
        hostname: ctx.host,
        ...(cfg.tags ? { ddtags: cfg.tags } : {}),
        message: JSON.stringify(e),
        cloudwarden: e,
      })),
    )
    await check(
      await fetcher(`https://http-intake.logs.${cfg.site}/api/v2/logs`, {
        method: 'POST',
        headers: { 'DD-API-KEY': secrets.apiKey, 'Content-Type': 'application/json' },
        body,
        redirect: 'manual',
      }),
      'Datadog',
    )
  },
}

const guid = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
const sentinelConfig = z.object({
  tenantId: guid,
  clientId: guid,
  /** Data collection endpoint (logs ingestion) URI. */
  endpoint: httpsUrl,
  /** Immutable id of the data collection rule, `dcr-...`. */
  ruleId: z.string().regex(/^dcr-[0-9a-f]{32}$/i),
  /** Stream declared in the rule, for example `Custom-CloudwardenEvents_CL`. */
  streamName: z.string().regex(/^Custom-[A-Za-z0-9_]{1,100}$/),
})
const sentinelSecrets = z.object({ clientSecret: z.string().min(1).max(512) })

export const sentinel: Destination<
  z.infer<typeof sentinelConfig>,
  z.infer<typeof sentinelSecrets>
> = {
  config: sentinelConfig,
  secrets: sentinelSecrets,
  secretKeys: ['clientSecret'],
  batchSize: 100,
  async send(fetcher, cfg, secrets, events) {
    const tokenRes = await fetcher(
      `https://login.microsoftonline.com/${cfg.tenantId}/oauth2/v2.0/token`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: cfg.clientId,
          client_secret: secrets.clientSecret,
          scope: 'https://monitor.azure.com/.default',
          grant_type: 'client_credentials',
        }).toString(),
        redirect: 'manual',
      },
    )
    await check(tokenRes, 'Microsoft Entra ID')
    const token = ((await tokenRes.json()) as { access_token?: string }).access_token
    if (!token) throw new DeliveryError('Microsoft Entra ID returned no access token.')
    const url = `${cfg.endpoint.replace(/\/+$/, '')}/dataCollectionRules/${cfg.ruleId}/streams/${cfg.streamName}?api-version=2023-01-01`
    const body = JSON.stringify(
      events.map((e) => ({
        TimeGenerated: e.date,
        EventId: e.id,
        EventType: e.type,
        Event: e,
      })),
    )
    await check(
      await fetcher(url, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body,
        redirect: 'manual',
      }),
      'Azure Monitor',
    )
  },
}

// biome-ignore lint/suspicious/noExplicitAny: heterogeneous registry, each entry validates its own shapes
export const DESTINATIONS: Record<IntegrationType, Destination<any, any>> = {
  webhook,
  splunk,
  datadog,
  sentinel,
}

/** A random webhook signing secret (shown to the admin once). */
export const newSigningSecret = () => `whsec_${toB64u(crypto.getRandomValues(new Uint8Array(32)))}`
