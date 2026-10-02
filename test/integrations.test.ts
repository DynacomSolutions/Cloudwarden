// Event integrations (TASKS #274): configuration API, sealed secrets, signed webhook delivery in
// order with retries and back-off, and the Splunk HEC, Datadog and Microsoft Sentinel payloads.
import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it } from 'vitest'
import { backoffMs, deliverIntegrations } from '../src/integrations/deliver'
import { splunkEndpoint, webhookSignature } from '../src/integrations/destinations'
import { seal, unseal } from '../src/orgs/sealed'
import { type Actor, actor, addMember, createOrg } from './org-helpers'

interface Sent {
  url: string
  init: RequestInit
}

/** A fake network: records requests and answers with the next queued status (default 200). */
function fakeFetch(statuses: number[] = []) {
  const sent: Sent[] = []
  const fetcher = async (input: RequestInfo | URL, init?: RequestInit) => {
    sent.push({ url: String(input), init: init ?? {} })
    if (String(input).startsWith('https://login.microsoftonline.com/')) {
      return Response.json({ access_token: 'entra-token', token_type: 'Bearer', expires_in: 3599 })
    }
    return new Response('ok', { status: statuses.shift() ?? 200 })
  }
  return { sent, fetcher }
}

let owner: Actor
let orgId: string
const base = () => `/api/organizations/${orgId}/event-integrations`

/** Writes `n` organisation events through the API (group create). */
async function makeEvents(n: number) {
  const ids: string[] = []
  for (let i = 0; i < n; i++) {
    ids.push((await owner.json(`/api/organizations/${orgId}/groups`, 'POST', { name: `G${i}` })).id)
  }
  return ids
}

beforeAll(async () => {
  owner = await actor('int-owner@example.com')
  orgId = (await createOrg(owner, 'Integrations Org')).id
})

describe('sealed secrets', () => {
  it('round-trips, binds the purpose and opens values sealed before DATA_ENCRYPTION_KEY was set', async () => {
    const s = await seal(env, 'p1', 'top secret')
    expect(s).toMatch(/^v1\.j\./)
    expect(await unseal(env, 'p1', s)).toBe('top secret')
    await expect(unseal(env, 'p2', s)).rejects.toThrow()
    const withKey = { ...env, DATA_ENCRYPTION_KEY: 'k'.repeat(40) }
    const d = await seal(withKey, 'p1', 'x')
    expect(d).toMatch(/^v1\.d\./)
    expect(await unseal(withKey, 'p1', d)).toBe('x')
    expect(await unseal(withKey, 'p1', s)).toBe('top secret')
    await expect(unseal(env, 'p1', d)).rejects.toThrow()
  })
})

describe('integration settings API', () => {
  it('is for owners and admins, validates settings and never returns secrets', async () => {
    const user = await actor('int-user@example.com')
    await addMember(owner, orgId, user, { type: 2 })
    expect((await user.call(base())).status).toBe(403)

    const bad = await owner.call(base(), 'POST', {
      type: 'webhook',
      name: 'Bad',
      config: { url: 'http://127.0.0.1/hook' },
    })
    expect(bad.status).toBe(400)
    expect(((await bad.json()) as any).validationErrors).toHaveProperty('config.url')
    const local = await owner.call(base(), 'POST', {
      type: 'splunk',
      name: 'Local',
      config: { url: 'https://splunk.localhost:8088' },
      secrets: { token: 't' },
    })
    expect(local.status).toBe(400)
    const missing = await owner.call(base(), 'POST', {
      type: 'datadog',
      name: 'DD',
      config: { site: 'datadoghq.eu' },
    })
    expect(((await missing.json()) as any).validationErrors).toHaveProperty('secrets.apiKey')

    const created = await owner.json(base(), 'POST', {
      type: 'datadog',
      name: 'DD',
      config: { site: 'datadoghq.eu', service: 'vault' },
      secrets: { apiKey: 'dd-secret-key' },
    })
    expect(created).toMatchObject({ object: 'eventIntegration', type: 'datadog', enabled: true })
    expect(JSON.stringify(created)).not.toContain('dd-secret-key')
    const listed = await owner.json(base())
    expect(JSON.stringify(listed)).not.toContain('dd-secret-key')
    const row = await env.DB.prepare('select sealed_secrets from org_integrations where uuid = ?')
      .bind(created.id)
      .first<{ sealed_secrets: string }>()
    expect(row?.sealed_secrets).not.toContain('dd-secret-key')

    // A blank secret on update keeps the stored one.
    const upd = await owner.json(`${base()}/${created.id}`, 'PUT', {
      name: 'Datadog EU',
      config: { site: 'datadoghq.eu' },
      secrets: { apiKey: '' },
    })
    expect(upd.name).toBe('Datadog EU')
    const { sent, fetcher } = fakeFetch()
    await makeEvents(1)
    await deliverIntegrations(env, { fetcher })
    expect(sent.find((s) => s.url.includes('datadoghq.eu'))?.init.headers).toMatchObject({
      'DD-API-KEY': 'dd-secret-key',
    })
    expect((await owner.call(`${base()}/${created.id}`, 'DELETE')).status).toBe(200)
  })
})

describe('webhook delivery', () => {
  it('signs each event, delivers in order, retries with back-off and resumes', async () => {
    const hook = await owner.json(base(), 'POST', {
      type: 'webhook',
      name: 'Receiver',
      config: { url: 'https://hooks.example.com/cloudwarden', headerName: 'Authorization' },
      secrets: { headerValue: 'Bearer receiver-token' },
    })
    expect(hook.signingSecret).toMatch(/^whsec_/)
    const secret = hook.signingSecret as string
    // Earlier events are not replayed: delivery starts at creation.
    const now = Date.now()
    const groups = await makeEvents(3)

    // The second request fails: the first event is delivered, the rest wait.
    const net = fakeFetch([200, 503])
    await deliverIntegrations(env, { fetcher: net.fetcher, now })
    const toHook = () => net.sent.filter((s) => s.url === 'https://hooks.example.com/cloudwarden')
    expect(toHook()).toHaveLength(2)
    const first = toHook()[0] as Sent
    const headers = first.init.headers as Record<string, string>
    const body = String(first.init.body)
    expect(headers['X-Cloudwarden-Signature']).toBe(
      await webhookSignature(secret, headers['X-Cloudwarden-Timestamp'] as string, body),
    )
    expect(headers.Authorization).toBe('Bearer receiver-token')
    const payload = JSON.parse(body)
    expect(payload).toMatchObject({
      type: 1400,
      groupId: groups[0],
      organizationId: orgId,
      object: 'event',
    })
    expect(headers['X-Cloudwarden-Event-Id']).toBe(payload.id)

    let status = (await owner.json(base())).data.find((i: any) => i.id === hook.id).status
    expect(status.failureCount).toBe(1)
    expect(status.lastError).toBe('The webhook receiver answered HTTP 503.')
    expect(Date.parse(status.nextAttemptDate)).toBe(now + backoffMs(1))

    // Not due yet: nothing is sent.
    const early = fakeFetch()
    await deliverIntegrations(env, { fetcher: early.fetcher, now: now + 1000 })
    expect(early.sent.filter((s) => s.url.includes('hooks.example.com'))).toHaveLength(0)

    // Network errors count as failures too, and the back-off doubles.
    const down = fakeFetch()
    await deliverIntegrations(env, {
      fetcher: async (i, init) => {
        if (String(i).includes('hooks.example.com')) throw new TypeError('connect failed')
        return down.fetcher(i, init)
      },
      now: now + backoffMs(1),
    })
    status = (await owner.json(base())).data.find((i: any) => i.id === hook.id).status
    expect(status.failureCount).toBe(2)
    expect(Date.parse(status.nextAttemptDate)).toBe(now + backoffMs(1) + backoffMs(2))

    // Recovery: the remaining two events go out, in order, then the integration is healthy.
    const ok = fakeFetch()
    await deliverIntegrations(env, { fetcher: ok.fetcher, now: now + backoffMs(1) + backoffMs(2) })
    const delivered = ok.sent
      .filter((s) => s.url.includes('hooks.example.com'))
      .map((s) => JSON.parse(String(s.init.body)).groupId)
    expect(delivered).toEqual([groups[1], groups[2]])
    status = (await owner.json(base())).data.find((i: any) => i.id === hook.id).status
    expect(status).toMatchObject({ failureCount: 0, lastError: null })
    expect(status.lastSuccessDate).not.toBeNull()

    // Nothing new: nothing sent.
    const idle = fakeFetch()
    await deliverIntegrations(env, { fetcher: idle.fetcher })
    expect(idle.sent.filter((s) => s.url.includes('hooks.example.com'))).toHaveLength(0)

    // Event type filter and secret rotation.
    await owner.json(`${base()}/${hook.id}`, 'PUT', {
      name: 'Receiver',
      config: { url: 'https://hooks.example.com/cloudwarden' },
      eventTypes: [1402],
    })
    const rotated = await owner.json(`${base()}/${hook.id}/rotate-secret`, 'POST')
    expect(rotated.signingSecret).not.toBe(secret)
    await makeEvents(1)
    await owner.call(`/api/organizations/${orgId}/groups/${groups[0]}`, 'DELETE')
    const filtered = fakeFetch()
    await deliverIntegrations(env, { fetcher: filtered.fetcher })
    const only = filtered.sent.filter((s) => s.url.includes('hooks.example.com'))
    expect(only.map((s) => JSON.parse(String(s.init.body)).type)).toEqual([1402])
    const h = only[0]?.init.headers as Record<string, string>
    expect(h['X-Cloudwarden-Signature']).toBe(
      await webhookSignature(
        rotated.signingSecret,
        h['X-Cloudwarden-Timestamp'] as string,
        String(only[0]?.init.body),
      ),
    )
    await owner.call(`${base()}/${hook.id}`, 'DELETE')
  })

  it('does not double-send when two runs overlap', async () => {
    const hook = await owner.json(base(), 'POST', {
      type: 'webhook',
      name: 'Lease',
      config: { url: 'https://lease.example.com/hook' },
    })
    await makeEvents(1)
    const net = fakeFetch()
    await Promise.all([
      deliverIntegrations(env, { fetcher: net.fetcher }),
      deliverIntegrations(env, { fetcher: net.fetcher }),
    ])
    expect(net.sent.filter((s) => s.url.includes('lease.example.com'))).toHaveLength(1)
    await owner.call(`${base()}/${hook.id}`, 'DELETE')
  })
})

describe('log destinations', () => {
  it('sends Splunk HEC, Datadog and Sentinel payloads in the documented formats', async () => {
    expect(splunkEndpoint('https://splunk.example.com:8088')).toBe(
      'https://splunk.example.com:8088/services/collector/event',
    )
    expect(splunkEndpoint('https://splunk.example.com/services/collector')).toBe(
      'https://splunk.example.com/services/collector',
    )
    const ids: string[] = []
    for (const [type, config, secrets] of [
      [
        'splunk',
        { url: 'https://splunk.example.com:8088', index: 'audit' },
        { token: 'hec-token' },
      ],
      ['datadog', { site: 'us5.datadoghq.com', tags: 'env:prod' }, { apiKey: 'dd-key' }],
      [
        'sentinel',
        {
          tenantId: '00000000-0000-4000-8000-000000000001',
          clientId: '00000000-0000-4000-8000-000000000002',
          endpoint: 'https://dce-1.westeurope-1.ingest.monitor.azure.com',
          ruleId: 'dcr-00000000000000000000000000000000',
          streamName: 'Custom-CloudwardenEvents_CL',
        },
        { clientSecret: 'entra-secret' },
      ],
    ] as const) {
      ids.push((await owner.json(base(), 'POST', { type, name: type, config, secrets })).id)
    }
    const [g] = await makeEvents(2)
    const net = fakeFetch()
    await deliverIntegrations(env, { fetcher: net.fetcher })

    const hec = net.sent.find((s) => s.url.startsWith('https://splunk.example.com'))
    expect(hec?.url).toBe('https://splunk.example.com:8088/services/collector/event')
    expect(((hec as Sent).init.headers as Record<string, string>).Authorization).toBe(
      'Splunk hec-token',
    )
    const lines = String(hec?.init.body)
      .split('\n')
      .map((l) => JSON.parse(l))
    expect(lines).toHaveLength(2)
    expect(lines[0]).toMatchObject({
      host: 'vault.example.com',
      index: 'audit',
      sourcetype: '_json',
      event: { type: 1400, groupId: g },
    })
    expect(typeof lines[0].time).toBe('number')

    const dd = net.sent.find((s) => s.url.includes('datadoghq'))
    expect(dd?.url).toBe('https://http-intake.logs.us5.datadoghq.com/api/v2/logs')
    const logs = JSON.parse(String(dd?.init.body))
    expect(logs).toHaveLength(2)
    expect(logs[0]).toMatchObject({
      ddsource: 'cloudwarden',
      ddtags: 'env:prod',
      hostname: 'vault.example.com',
    })
    expect(JSON.parse(logs[0].message).groupId).toBe(g)

    const token = net.sent.find((s) => s.url.startsWith('https://login.microsoftonline.com/'))
    expect(token?.url).toBe(
      'https://login.microsoftonline.com/00000000-0000-4000-8000-000000000001/oauth2/v2.0/token',
    )
    const form = new URLSearchParams(String(token?.init.body))
    expect(Object.fromEntries(form)).toMatchObject({
      grant_type: 'client_credentials',
      scope: 'https://monitor.azure.com/.default',
      client_secret: 'entra-secret',
    })
    const ingest = net.sent.find((s) => s.url.includes('ingest.monitor.azure.com'))
    expect(ingest?.url).toBe(
      'https://dce-1.westeurope-1.ingest.monitor.azure.com/dataCollectionRules/dcr-00000000000000000000000000000000/streams/Custom-CloudwardenEvents_CL?api-version=2023-01-01',
    )
    expect(((ingest as Sent).init.headers as Record<string, string>).Authorization).toBe(
      'Bearer entra-token',
    )
    const records = JSON.parse(String(ingest?.init.body))
    expect(records[0]).toMatchObject({ EventType: 1400 })
    expect(records[0].TimeGenerated).toMatch(/Z$/)
    for (const id of ids) await owner.call(`${base()}/${id}`, 'DELETE')
  })
})
