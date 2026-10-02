// Contract tests (TASKS #180): exercise a curated set of implemented operations through the Worker
// and validate each response against the response schema in docs/api/openapi.yaml.
import { Validator } from '@cfworker/json-schema'
import { beforeAll, describe, expect, it } from 'vitest'
import { parse } from 'yaml'
import raw from '../docs/api/openapi.yaml?raw'
import { authed, BASE, createSession, form, json } from './helpers'

type Json = any
const spec = parse(raw) as Json

// Schemas reference each other as `#/components/...`; rewrite to an absolute URI so inline schemas
// from an operation can be validated on their own.
const SPEC_URI = 'https://spec.example.com/openapi'
const absolute = (node: Json): Json => {
  if (Array.isArray(node)) return node.map(absolute)
  if (node && typeof node === 'object') {
    return Object.fromEntries(
      Object.entries(node).map(([k, v]) => [
        k,
        k === '$ref' && typeof v === 'string' && v.startsWith('#/') ? SPEC_URI + v : absolute(v),
      ]),
    )
  }
  return node
}
const specDoc = { $id: SPEC_URI, components: absolute(spec.components) }

const resolve = (node: Json): Json => {
  if (node?.$ref?.startsWith('#/')) {
    return node.$ref
      .slice(2)
      .split('/')
      .reduce((acc: Json, key: string) => acc[key], spec)
  }
  return node
}

/** Validates `body` against the documented response for `op` and `status`. */
function validateResponse(op: string, status: number, body: unknown) {
  const [method, path] = op.split(' ') as [string, string]
  const operation = spec.paths[path]?.[method.toLowerCase()]
  expect(operation, `${op} is not in the spec`).toBeDefined()
  const response = resolve(operation.responses[String(status)] ?? operation.responses.default)
  expect(response, `${op} documents no ${status} response`).toBeDefined()
  const schema = response.content?.['application/json']?.schema
  if (!schema) return
  const validator = new Validator(absolute(schema), '2020-12', false)
  validator.addSchema(specDoc)
  const result = validator.validate(body)
  const detail = result.errors
    .slice(0, 5)
    .map((e) => `${e.instanceLocation}: ${e.error}`)
    .join('\n')
  expect(result.valid, `${op} ${status} does not match its schema:\n${detail}`).toBe(true)
}

const enc = (label: string) =>
  `2.${btoa(`${label}-iv`)}|${btoa(`${label}-ct`)}|${btoa(`${label}-mac`)}`

interface State {
  token: string
  email: string
  folderId: string
  cipherId: string
  sendId: string
  passwordHash: string
}
const state = {} as State
const call = (path: string, method = 'GET', body?: unknown) =>
  authed(path, state.token, method, body)

interface Case {
  /** Spec key: `METHOD /path` exactly as written in docs/api/openapi.yaml. */
  op: string
  status: number
  run: () => Promise<Response>
}

/** Secrets Manager fixtures (TASKS #220), created in `beforeAll`. */
const sm = {} as {
  orgId: string
  projectId: string
  secretId: string
  saId: string
  tokenId: string
  clientSecret: string
  machine: string
}
const machine = (path: string, method = 'GET', body?: unknown) =>
  authed(path, sm.machine, method, body)

const smCases: Case[] = [
  {
    op: 'POST /identity/connect/token',
    status: 200,
    run: () =>
      form('/identity/connect/token', {
        grant_type: 'client_credentials',
        scope: 'api.secrets',
        client_id: sm.tokenId,
        client_secret: sm.clientSecret,
      }),
  },
  {
    op: 'POST /api/organizations/{organizationId}/projects',
    status: 200,
    run: () => call(`/api/organizations/${sm.orgId}/projects`, 'POST', { name: enc('p2') }),
  },
  {
    op: 'GET /api/organizations/{organizationId}/projects',
    status: 200,
    run: () => machine(`/api/organizations/${sm.orgId}/projects`),
  },
  { op: 'GET /api/projects/{id}', status: 200, run: () => call(`/api/projects/${sm.projectId}`) },
  {
    op: 'PUT /api/projects/{id}',
    status: 200,
    run: () => call(`/api/projects/${sm.projectId}`, 'PUT', { name: enc('p') }),
  },
  {
    op: 'GET /api/projects/{id}',
    status: 404,
    run: () => call('/api/projects/00000000-0000-4000-8000-000000000000'),
  },
  {
    op: 'POST /api/organizations/{organizationId}/secrets',
    status: 200,
    run: () =>
      call(`/api/organizations/${sm.orgId}/secrets`, 'POST', {
        key: enc('k2'),
        value: enc('v2'),
        note: '',
        projectIds: [sm.projectId],
      }),
  },
  {
    op: 'GET /api/organizations/{organizationId}/secrets',
    status: 200,
    run: () => machine(`/api/organizations/${sm.orgId}/secrets`),
  },
  {
    op: 'GET /api/organizations/{organizationId}/secrets/sync',
    status: 200,
    run: () => machine(`/api/organizations/${sm.orgId}/secrets/sync`),
  },
  {
    op: 'GET /api/organizations/{organizationId}/secrets/sync',
    status: 200,
    run: () =>
      machine(`/api/organizations/${sm.orgId}/secrets/sync?lastSyncedDate=2999-01-01T00:00:00Z`),
  },
  {
    op: 'GET /api/projects/{projectId}/secrets',
    status: 200,
    run: () => call(`/api/projects/${sm.projectId}/secrets`),
  },
  { op: 'GET /api/secrets/{id}', status: 200, run: () => machine(`/api/secrets/${sm.secretId}`) },
  {
    op: 'PUT /api/secrets/{id}',
    status: 200,
    run: () =>
      call(`/api/secrets/${sm.secretId}`, 'PUT', { key: enc('k'), value: enc('v'), note: '' }),
  },
  {
    op: 'POST /api/secrets/get-by-ids',
    status: 200,
    run: () => machine('/api/secrets/get-by-ids', 'POST', { ids: [sm.secretId] }),
  },
  {
    op: 'POST /api/secrets/delete',
    status: 200,
    run: () => call('/api/secrets/delete', 'POST', ['00000000-0000-4000-8000-000000000000']),
  },
  {
    op: 'POST /api/projects/delete',
    status: 200,
    run: () => call('/api/projects/delete', 'POST', ['00000000-0000-4000-8000-000000000000']),
  },
  {
    op: 'GET /api/organizations/{organizationId}/service-accounts',
    status: 200,
    run: () => call(`/api/organizations/${sm.orgId}/service-accounts?includeAccessToSecrets=true`),
  },
  {
    op: 'GET /api/service-accounts/{id}',
    status: 200,
    run: () => call(`/api/service-accounts/${sm.saId}`),
  },
  {
    op: 'PUT /api/service-accounts/{id}',
    status: 200,
    run: () => call(`/api/service-accounts/${sm.saId}`, 'PUT', { name: enc('sa') }),
  },
  {
    op: 'GET /api/service-accounts/{id}/access-tokens',
    status: 200,
    run: () => call(`/api/service-accounts/${sm.saId}/access-tokens`),
  },
  {
    op: 'POST /api/service-accounts/{id}/access-tokens',
    status: 200,
    run: () =>
      call(`/api/service-accounts/${sm.saId}/access-tokens`, 'POST', {
        name: enc('t2'),
        encryptedPayload: enc('payload'),
        key: enc('key'),
        expireAt: null,
      }),
  },
  {
    op: 'GET /api/projects/{id}/access-policies/people',
    status: 200,
    run: () => call(`/api/projects/${sm.projectId}/access-policies/people`),
  },
  {
    op: 'GET /api/projects/{id}/access-policies/service-accounts',
    status: 200,
    run: () => call(`/api/projects/${sm.projectId}/access-policies/service-accounts`),
  },
  {
    op: 'GET /api/secrets/{secretId}/access-policies',
    status: 200,
    run: () => call(`/api/secrets/${sm.secretId}/access-policies`),
  },
  {
    op: 'GET /api/service-accounts/{id}/access-policies/people',
    status: 200,
    run: () => call(`/api/service-accounts/${sm.saId}/access-policies/people`),
  },
  {
    op: 'GET /api/service-accounts/{id}/granted-policies',
    status: 200,
    run: () => call(`/api/service-accounts/${sm.saId}/granted-policies`),
  },
  {
    op: 'GET /api/organizations/{id}/access-policies/people/potential-grantees',
    status: 200,
    run: () => call(`/api/organizations/${sm.orgId}/access-policies/people/potential-grantees`),
  },
  {
    op: 'GET /api/organizations/{id}/access-policies/projects/potential-grantees',
    status: 200,
    run: () => call(`/api/organizations/${sm.orgId}/access-policies/projects/potential-grantees`),
  },
  {
    op: 'GET /api/organizations/{organizationId}/sm-counts',
    status: 200,
    run: () => call(`/api/organizations/${sm.orgId}/sm-counts`),
  },
  {
    op: 'GET /api/projects/{projectId}/sm-counts',
    status: 200,
    run: () => call(`/api/projects/${sm.projectId}/sm-counts`),
  },
  {
    op: 'GET /api/service-accounts/{serviceAccountId}/sm-counts',
    status: 200,
    run: () => call(`/api/service-accounts/${sm.saId}/sm-counts`),
  },
  {
    op: 'GET /api/sm/events/service-accounts/{serviceAccountId}',
    status: 200,
    run: () => call(`/api/sm/events/service-accounts/${sm.saId}`),
  },
]

const cases: Case[] = [
  { op: 'GET /api/config', status: 200, run: () => call('/api/config') },
  {
    op: 'POST /identity/accounts/prelogin',
    status: 200,
    run: () => json('/identity/accounts/prelogin', { email: 'contract@example.com' }),
  },
  {
    op: 'POST /identity/accounts/prelogin/password',
    status: 200,
    run: () => json('/identity/accounts/prelogin/password', { email: 'contract@example.com' }),
  },
  {
    op: 'POST /identity/connect/token',
    status: 200,
    run: () =>
      form('/identity/connect/token', {
        grant_type: 'password',
        username: state.email,
        password: state.passwordHash,
        scope: 'api offline_access',
        client_id: 'web',
        deviceType: '9',
        deviceName: 'chrome',
        deviceIdentifier: crypto.randomUUID(),
      }),
  },
  {
    op: 'POST /identity/connect/token',
    status: 400,
    run: () =>
      form('/identity/connect/token', {
        grant_type: 'password',
        username: state.email,
        password: 'wrong',
        scope: 'api offline_access',
        client_id: 'web',
        deviceType: '9',
        deviceName: 'chrome',
        deviceIdentifier: crypto.randomUUID(),
      }),
  },
  { op: 'GET /api/accounts/profile', status: 200, run: () => call('/api/accounts/profile') },
  {
    op: 'GET /api/accounts/revision-date',
    status: 200,
    run: () => call('/api/accounts/revision-date'),
  },
  {
    op: 'POST /api/accounts/api-key',
    status: 200,
    run: () => call('/api/accounts/api-key', 'POST', { masterPasswordHash: state.passwordHash }),
  },
  { op: 'GET /api/sync', status: 200, run: () => call('/api/sync') },
  { op: 'GET /api/settings/domains', status: 200, run: () => call('/api/settings/domains') },
  { op: 'GET /api/devices', status: 200, run: () => call('/api/devices') },
  { op: 'GET /api/two-factor', status: 200, run: () => call('/api/two-factor') },
  { op: 'GET /api/auth-requests', status: 200, run: () => call('/api/auth-requests') },
  {
    op: 'GET /api/auth-requests/pending',
    status: 200,
    run: () => call('/api/auth-requests/pending'),
  },
  {
    op: 'POST /api/folders',
    status: 200,
    run: async () => {
      const res = await call('/api/folders', 'POST', { name: enc('folder') })
      state.folderId = ((await res.clone().json()) as Json).id
      return res
    },
  },
  {
    op: 'GET /api/folders/{id}',
    status: 200,
    run: () => call(`/api/folders/${state.folderId}`),
  },
  {
    op: 'PUT /api/folders/{id}',
    status: 200,
    run: () => call(`/api/folders/${state.folderId}`, 'PUT', { name: enc('folder2') }),
  },
  {
    op: 'POST /api/ciphers',
    status: 200,
    run: async () => {
      const res = await call('/api/ciphers', 'POST', {
        type: 1,
        name: enc('name'),
        notes: enc('notes'),
        folderId: state.folderId,
        favorite: false,
        reprompt: 0,
        login: {
          username: enc('user'),
          password: enc('pass'),
          uris: [{ uri: enc('uri'), match: null }],
        },
      })
      state.cipherId = ((await res.clone().json()) as Json).id
      return res
    },
  },
  {
    op: 'GET /api/ciphers/{id}',
    status: 200,
    run: () => call(`/api/ciphers/${state.cipherId}`),
  },
  {
    op: 'GET /api/ciphers/{id}/details',
    status: 200,
    run: () => call(`/api/ciphers/${state.cipherId}/details`),
  },
  {
    op: 'PUT /api/ciphers/{id}',
    status: 200,
    run: () =>
      call(`/api/ciphers/${state.cipherId}`, 'PUT', {
        type: 1,
        name: enc('name2'),
        folderId: state.folderId,
        login: { username: enc('user'), password: enc('pass2') },
      }),
  },
  {
    op: 'POST /api/ciphers/{id}/attachment/v2',
    status: 200,
    run: () =>
      call(`/api/ciphers/${state.cipherId}/attachment/v2`, 'POST', {
        fileName: enc('file'),
        key: enc('key'),
        fileSize: 16,
      }),
  },
  {
    op: 'PUT /api/ciphers/{id}/delete',
    status: 200,
    run: () => call(`/api/ciphers/${state.cipherId}/delete`, 'PUT'),
  },
  {
    op: 'PUT /api/ciphers/{id}/restore',
    status: 200,
    run: () => call(`/api/ciphers/${state.cipherId}/restore`, 'PUT'),
  },
  {
    op: 'GET /api/ciphers/{id}',
    status: 404,
    run: () => call(`/api/ciphers/${crypto.randomUUID()}`),
  },
  {
    op: 'POST /api/sends',
    status: 200,
    run: async () => {
      const res = await call('/api/sends', 'POST', {
        type: 0,
        name: enc('send'),
        key: enc('sendkey'),
        text: { text: enc('text'), hidden: false },
        deletionDate: new Date(Date.now() + 86_400_000).toISOString(),
        disabled: false,
        hideEmail: false,
      })
      state.sendId = ((await res.clone().json()) as Json).id
      return res
    },
  },
  { op: 'GET /api/sends', status: 200, run: () => call('/api/sends') },
  { op: 'GET /api/sends/{id}', status: 200, run: () => call(`/api/sends/${state.sendId}`) },
  {
    op: 'PUT /api/sends/{id}/remove-password',
    status: 200,
    run: () => call(`/api/sends/${state.sendId}/remove-password`, 'PUT'),
  },
  { op: 'GET /api/collections', status: 200, run: () => call('/api/collections') },
  {
    op: 'GET /api/accounts/profile',
    status: 401,
    run: () => authed('/api/accounts/profile', 'bad'),
  },
  {
    op: 'GET /api/webauthn',
    status: 200,
    run: () => call('/api/webauthn'),
  },
  {
    op: 'POST /api/webauthn/attestation-options',
    status: 200,
    run: () =>
      call('/api/webauthn/attestation-options', 'POST', {
        masterPasswordHash: state.passwordHash,
      }),
  },
  {
    op: 'POST /api/webauthn/assertion-options',
    status: 200,
    run: () =>
      call('/api/webauthn/assertion-options', 'POST', { masterPasswordHash: state.passwordHash }),
  },
  {
    op: 'GET /identity/accounts/webauthn/assertion-options',
    status: 200,
    run: () =>
      import('cloudflare:test').then(({ SELF }) =>
        SELF.fetch(`${BASE}/identity/accounts/webauthn/assertion-options`),
      ),
  },
  {
    op: 'POST /identity/accounts/register',
    status: 400,
    run: () => json('/identity/accounts/register', { email: 'not-an-email' }),
  },
]

/**
 * Spec operations the Worker does not serve yet (an unauthenticated probe returns the generic 404).
 * They are listed as skipped below; a drift check fails when one starts being served so the list
 * gets updated and the operation can join the curated set above.
 */
const UNIMPLEMENTED = [
  'PUT /api/accounts/avatar',
  'POST /api/accounts/convert-to-key-connector',
  'POST /api/accounts/delete-recover',
  'POST /api/accounts/delete-recover-token',
  'POST /api/accounts/password-hint',
  'POST /api/accounts/request-otp',
  'POST /api/accounts/set-key-connector-key',
  'POST /api/accounts/set-password',
  'GET /api/accounts/sso/user-identifier',
  'DELETE /api/accounts/sso/{organizationId}',
  'PUT /api/accounts/update-tde-offboarding-password',
  'PUT /api/accounts/update-temp-password',
  'POST /api/accounts/verify-devices',
  'POST /api/accounts/verify-email',
  'POST /api/accounts/verify-email-token',
  'POST /api/accounts/verify-otp',
  'POST /api/auth-requests/admin-request',
  'POST /api/devices/identifier/{deviceIdentifier}/web-push-auth',
  'POST /api/devices/lost-trust',
  'POST /api/devices/untrust',
  'POST /api/devices/update-trust',
  'PUT /api/devices/{deviceIdentifier}/keys',
  'POST /api/devices/{deviceIdentifier}/retrieve-keys',
  'GET /identity/sso/prevalidate',
]

const specOperations = () =>
  Object.entries<Json>(spec.paths).flatMap(([path, item]) =>
    ['get', 'put', 'post', 'delete', 'patch']
      .filter((m) => item[m])
      .map((m) => `${m.toUpperCase()} ${path}`),
  )

describe('API contract (docs/api/openapi.yaml)', () => {
  beforeAll(async () => {
    state.email = 'contract@example.com'
    state.passwordHash = 'client-derived-hash'
    const session = await createSession(state.email)
    state.token = session.access_token

    const org = (await (
      await call('/api/organizations', 'POST', {
        name: 'Contract Org',
        billingEmail: 'billing@example.com',
        key: '4.orgKey',
        keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' },
        planType: 0,
      })
    ).json()) as Json
    sm.orgId = org.id
    sm.projectId = (
      (await (
        await call(`/api/organizations/${sm.orgId}/projects`, 'POST', { name: enc('p') })
      ).json()) as Json
    ).id
    sm.secretId = (
      (await (
        await call(`/api/organizations/${sm.orgId}/secrets`, 'POST', {
          key: enc('k'),
          value: enc('v'),
          note: '',
          projectIds: [sm.projectId],
        })
      ).json()) as Json
    ).id
    sm.saId = (
      (await (
        await call(`/api/organizations/${sm.orgId}/service-accounts`, 'POST', { name: enc('sa') })
      ).json()) as Json
    ).id
    await call(`/api/projects/${sm.projectId}/access-policies/service-accounts`, 'PUT', {
      serviceAccountAccessPolicyRequests: [{ granteeId: sm.saId, read: true, write: false }],
    })
    const token = (await (
      await call(`/api/service-accounts/${sm.saId}/access-tokens`, 'POST', {
        name: enc('t'),
        encryptedPayload: enc('payload'),
        key: enc('key'),
        expireAt: null,
      })
    ).json()) as Json
    sm.tokenId = token.id
    sm.clientSecret = token.clientSecret
    sm.machine = (
      (await (
        await form('/identity/connect/token', {
          grant_type: 'client_credentials',
          scope: 'api.secrets',
          client_id: sm.tokenId,
          client_secret: sm.clientSecret,
        })
      ).json()) as Json
    ).access_token
  })

  for (const c of [...cases, ...smCases]) {
    it(`${c.op} -> ${c.status}`, async () => {
      const res = await c.run()
      expect(res.status).toBe(c.status)
      const text = await res.text()
      validateResponse(c.op, c.status, text ? JSON.parse(text) : undefined)
    })
  }

  for (const op of UNIMPLEMENTED) it.skip(`${op} (not implemented)`, () => {})

  it('lists only operations that exist in the spec', () => {
    const all = new Set(specOperations())
    for (const op of [...cases, ...smCases].map((c) => c.op).concat(UNIMPLEMENTED))
      expect(all.has(op), op).toBe(true)
  })

  it('has not started serving an operation marked unimplemented', async () => {
    const served: string[] = []
    for (const op of UNIMPLEMENTED) {
      const [method, path] = op.split(' ') as [string, string]
      const url = BASE + path.replace(/\{[^}]+\}/g, '00000000-0000-4000-8000-000000000000')
      const res = await fetch_(url, method)
      if (!(res.status === 404 && ((await res.json()) as Json).message === 'Not found'))
        served.push(op)
    }
    expect(served, 'now served: move these into the curated cases').toEqual([])
  })
})

const fetch_ = (url: string, method: string) =>
  import('cloudflare:test').then(({ SELF }) =>
    SELF.fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: method === 'GET' ? undefined : '{}',
    }),
  )
