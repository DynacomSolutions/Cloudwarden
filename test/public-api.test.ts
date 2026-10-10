// Organisation API keys, the organisation `client_credentials` grant, the Public API and the
// Directory Connector import (TASKS #270 to #272). Responses are validated against the Public API
// schemas in docs/api/openapi.yaml.

import { env } from 'cloudflare:workers'
import { Validator } from '@cfworker/json-schema'
import { beforeAll, describe, expect, it } from 'vitest'
import { parse } from 'yaml'
import raw from '../docs/api/openapi.yaml?raw'
import { bearer, raw as call, orgApiKey, orgToken } from './org-api-helpers'
import { type Actor, actor, addMember, createOrg, mail } from './org-helpers'

type Json = any
const spec = parse(raw) as Json
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
const resolve = (node: Json): Json =>
  node?.$ref?.startsWith('#/')
    ? node.$ref
        .slice(2)
        .split('/')
        .reduce((a: Json, k: string) => a[k], spec)
    : node

/** Asserts `body` matches the documented response of `METHOD /path` for `status`. */
function conforms(op: string, status: number, body: unknown) {
  const [method, path] = op.split(' ') as [string, string]
  const operation = spec.paths[path]?.[method.toLowerCase()]
  expect(operation, `${op} is not in the spec`).toBeDefined()
  const response = resolve(operation.responses[String(status)])
  expect(response, `${op} documents no ${status}`).toBeDefined()
  const content = response.content ?? {}
  const schema = (content['application/json'] ?? content['application/scim+json'])?.schema
  if (!schema) return
  const v = new Validator(absolute(schema), '2020-12', false)
  v.addSchema(specDoc)
  const r = v.validate(body)
  expect(
    r.valid,
    `${op} ${status}: ${r.errors.map((e) => `${e.instanceLocation} ${e.error}`).join('; ')}`,
  ).toBe(true)
}

let owner: Actor
let orgId: string
let collectionId: string
let token: string

const pub = async (path: string, method = 'GET', body?: unknown) => {
  const res = await call(`/api/public${path}`, { method, headers: bearer(token), body })
  const text = await res.text()
  return { status: res.status, body: text ? JSON.parse(text) : null }
}

beforeAll(async () => {
  owner = await actor('pub-owner@example.com')
  const org = await createOrg(owner, 'Public API Org')
  orgId = org.id
  collectionId = org.defaultCollectionId
  const key = await orgApiKey(owner, orgId)
  const t = await orgToken(orgId, key)
  expect(t.status).toBe(200)
  token = t.body.access_token
})

describe('organisation API key', () => {
  it('is owner only, needs the master password and is stable until rotated', async () => {
    const admin = await actor('pub-admin@example.com')
    await addMember(owner, orgId, admin, { type: 1 })
    const deny = await admin.call(`/api/organizations/${orgId}/api-key`, 'POST', {
      masterPasswordHash: 'client-derived-hash',
      type: 0,
    })
    expect(deny.status).toBe(403)
    const bad = await owner.call(`/api/organizations/${orgId}/api-key`, 'POST', {
      masterPasswordHash: 'wrong',
      type: 0,
    })
    expect(bad.status).toBe(400)
    const billing = await owner.call(`/api/organizations/${orgId}/api-key`, 'POST', {
      masterPasswordHash: 'client-derived-hash',
      type: 1,
    })
    expect(billing.status).toBe(400)

    const a = await orgApiKey(owner, orgId)
    expect(a).toMatch(/^[A-Za-z0-9]{30}$/)
    expect(await orgApiKey(owner, orgId)).toBe(a)
    const info = await owner.json(`/api/organizations/${orgId}/api-key-information/0`)
    expect(info.data).toHaveLength(1)
    expect(info.data[0]).toMatchObject({ keyType: 0, object: 'organizationApiKeyInformation' })

    // The key is sealed at rest: the plaintext is nowhere in the row.
    const row = await env.DB.prepare(
      'select sealed_key from organization_api_keys where organization_uuid = ?',
    )
      .bind(orgId)
      .first<{ sealed_key: string }>()
    expect(row?.sealed_key).toMatch(/^v1\.[dj]\./)
    expect(row?.sealed_key).not.toContain(a)
  })

  it('issues organisation tokens that only the Public API accepts, revoked by rotation', async () => {
    const other = await actor('pub-rot@example.com')
    const { id } = await createOrg(other, 'Rotation Org')
    const key = await orgApiKey(other, id)
    const wrong = await orgToken(id, `${key.slice(0, -1)}${key.endsWith('x') ? 'y' : 'x'}`)
    expect(wrong.status).toBe(400)
    expect(wrong.body.error).toBe('invalid_client')
    const t = await orgToken(id, key)
    expect(t.body).toMatchObject({
      token_type: 'Bearer',
      scope: 'api.organization',
      expires_in: 3600,
    })
    const h = bearer(t.body.access_token)
    expect((await call('/api/public/members', { headers: h })).status).toBe(200)
    expect((await call('/public/members', { headers: h })).status).toBe(200)
    // Not a user token anywhere else.
    expect((await call('/api/accounts/profile', { headers: h })).status).toBe(401)
    expect((await call(`/api/organizations/${id}/users`, { headers: h })).status).toBe(401)
    // A member token is not an organisation token.
    expect((await call('/api/public/members', { headers: bearer(other.token) })).status).toBe(401)

    const rotated = await orgApiKey(other, id, 0, true)
    expect(rotated).not.toBe(key)
    const res = await call('/api/public/members', { headers: h })
    expect(res.status).toBe(401)
    expect(await res.json()).toMatchObject({ object: 'error' })
    expect((await orgToken(id, key)).status).toBe(400)
    expect((await orgToken(id, rotated)).status).toBe(200)
  })

  it('only sees its own organisation', async () => {
    const other = await actor('pub-iso@example.com')
    const { id } = await createOrg(other, 'Isolated Org')
    const members = await pub('/members')
    const ids = members.body.data.map((m: any) => m.id)
    const foreign = await other.json(`/api/organizations/${id}/users`)
    expect(ids).not.toContain(foreign.data[0].id)
    expect((await pub(`/members/${foreign.data[0].id}`)).status).toBe(404)
  })
})

describe('Public API contract', () => {
  it('manages members', async () => {
    const list = await pub('/members')
    expect(list.status).toBe(200)
    conforms('GET /api/public/members', 200, list.body)
    expect(list.body.data[0]).toMatchObject({ object: 'member', type: 0, status: 2 })

    const before = mail.sent.length
    const created = await pub('/members', 'POST', {
      email: 'Pub-New@Example.com',
      type: 2,
      externalId: 'ext-new',
      collections: [{ id: collectionId, readOnly: true, hidePasswords: false }],
      groups: [],
    })
    expect(created.status).toBe(200)
    conforms('POST /api/public/members', 200, created.body)
    expect(created.body).toMatchObject({
      email: 'pub-new@example.com',
      status: 0,
      externalId: 'ext-new',
      collections: [{ id: collectionId, readOnly: true, hidePasswords: false, manage: false }],
    })
    expect(mail.sent.length).toBe(before + 1)
    const id = created.body.id

    const dup = await pub('/members', 'POST', { email: 'pub-new@example.com', type: 2 })
    expect(dup.status).toBe(400)
    conforms('POST /api/public/members', 400, dup.body)
    expect(dup.body).toMatchObject({ object: 'error' })

    const invalid = await pub('/members', 'POST', { email: 'x@example.com', type: 9 })
    expect(invalid.status).toBe(400)
    expect(invalid.body.errors).toHaveProperty('type')

    // Owners cannot be created through the Public API.
    expect((await pub('/members', 'POST', { email: 'own@example.com', type: 0 })).status).toBe(403)

    const got = await pub(`/members/${id}`)
    conforms('GET /api/public/members/{id}', 200, got.body)

    const group = await pub('/groups', 'POST', { name: 'Engineering', externalId: 'g-eng' })
    const updated = await pub(`/members/${id}`, 'PUT', {
      type: 4,
      externalId: 'ext-new-2',
      permissions: { accessEventLogs: true },
      collections: [],
      groups: [group.body.id],
    })
    expect(updated.status).toBe(200)
    conforms('PUT /api/public/members/{id}', 200, updated.body)
    expect(updated.body).toMatchObject({ type: 4, externalId: 'ext-new-2', collections: [] })
    expect(updated.body.permissions.accessEventLogs).toBe(true)

    const gids = await pub(`/members/${id}/group-ids`)
    conforms('GET /api/public/members/{id}/group-ids', 200, gids.body)
    expect(gids.body).toEqual([group.body.id])
    expect((await pub(`/members/${id}/group-ids`, 'PUT', { groupIds: [] })).status).toBe(200)
    expect((await pub(`/members/${id}/group-ids`)).body).toEqual([])

    expect((await pub(`/members/${id}/reinvite`, 'POST')).status).toBe(200)
    expect((await pub(`/members/${id}/revoke`, 'POST')).status).toBe(200)
    expect((await pub(`/members/${id}`)).body.status).toBe(-1)
    expect((await pub(`/members/${id}/restore`, 'POST')).status).toBe(200)
    expect((await pub(`/members/${id}`)).body.status).toBe(0)

    const ownerId = list.body.data[0].id
    expect((await pub(`/members/${ownerId}`, 'DELETE')).status).toBe(403)
    expect((await pub(`/members/${id}`, 'DELETE')).status).toBe(200)
    const gone = await pub(`/members/${id}`)
    expect(gone.status).toBe(404)
    conforms('GET /api/public/members/{id}', 404, gone.body)
  })

  it('manages groups and their members', async () => {
    const m = await pub('/members', 'POST', { email: 'pub-g1@example.com', type: 2 })
    const g = await pub('/groups', 'POST', {
      name: 'Ops',
      externalId: 'g-ops',
      collections: [{ id: collectionId, readOnly: false, hidePasswords: true, manage: false }],
    })
    conforms('POST /api/public/groups', 200, g.body)
    expect(g.body).toMatchObject({ object: 'group', name: 'Ops', externalId: 'g-ops' })
    expect(g.body.collections[0]).toMatchObject({ id: collectionId, hidePasswords: true })
    conforms('GET /api/public/groups', 200, (await pub('/groups')).body)
    expect(
      (await pub(`/groups/${g.body.id}/member-ids`, 'PUT', { memberIds: [m.body.id] })).status,
    ).toBe(200)
    const ids = await pub(`/groups/${g.body.id}/member-ids`)
    conforms('GET /api/public/groups/{id}/member-ids', 200, ids.body)
    expect(ids.body).toEqual([m.body.id])
    const upd = await pub(`/groups/${g.body.id}`, 'PUT', {
      name: 'Operations',
      externalId: 'g-ops',
    })
    conforms('PUT /api/public/groups/{id}', 200, upd.body)
    // Collections left out are kept.
    expect(upd.body.collections).toHaveLength(1)
    conforms('GET /api/public/groups/{id}', 200, (await pub(`/groups/${g.body.id}`)).body)
    expect((await pub(`/groups/${g.body.id}`, 'DELETE')).status).toBe(200)
    expect((await pub(`/groups/${g.body.id}`)).status).toBe(404)
    const badRef = await pub(`/groups`, 'POST', {
      name: 'X',
      collections: [{ id: '00000000-0000-0000-0000-000000000000' }],
    })
    expect(badRef.status).toBe(400)
  })

  it('updates collections and policies', async () => {
    const g = await pub('/groups', 'POST', { name: 'Readers' })
    const list = await pub('/collections')
    conforms('GET /api/public/collections', 200, list.body)
    const upd = await pub(`/collections/${collectionId}`, 'PUT', {
      externalId: 'col-ext',
      groups: [{ id: g.body.id, readOnly: true }],
    })
    conforms('PUT /api/public/collections/{id}', 200, upd.body)
    expect(upd.body).toMatchObject({ object: 'collection', externalId: 'col-ext' })
    expect(upd.body.groups[0]).toMatchObject({ id: g.body.id, readOnly: true })
    conforms(
      'GET /api/public/collections/{id}',
      200,
      (await pub(`/collections/${collectionId}`)).body,
    )

    expect((await pub('/policies/1')).status).toBe(404)
    const pol = await pub('/policies/1', 'PUT', { enabled: true, data: { minLength: 14 } })
    conforms('PUT /api/public/policies/{type}', 200, pol.body)
    expect(pol.body).toMatchObject({
      object: 'policy',
      type: 1,
      enabled: true,
      data: { minLength: 14 },
    })
    conforms('GET /api/public/policies', 200, (await pub('/policies')).body)
    conforms('GET /api/public/policies/{type}', 200, (await pub('/policies/1')).body)
    // The member-facing endpoint sees the same policy.
    const seen = await owner.json(`/api/organizations/${orgId}/policies/1`)
    expect(seen.enabled).toBe(true)
  })

  it('lists events with filters and marks Public API changes', async () => {
    const events = await pub('/events')
    expect(events.status).toBe(200)
    conforms('GET /api/public/events', 200, events.body)
    expect(events.body.data.length).toBeGreaterThan(0)
    expect(events.body.data[0]).toHaveProperty('memberId')
    const byActor = await pub(`/events?actingUserId=${owner.uuid}`)
    expect(byActor.body.data.every((e: any) => e.actingUserId === owner.uuid)).toBe(true)
    // Admin Console view: Public API events carry systemUser 3 and no acting user.
    const admin = await owner.json(`/api/organizations/${orgId}/events`)
    const viaApi = admin.data.find((e: any) => e.type === 1700)
    expect(viaApi).toMatchObject({ systemUser: 3, actingUserId: null })
  })
})

describe('directory import', () => {
  it('invites, links, groups, deletes and overwrites like the Directory Connector expects', async () => {
    const o = await actor('dc-owner@example.com')
    const { id } = await createOrg(o, 'Directory Org')
    const existing = await actor('dc-existing@example.com')
    await addMember(o, id, existing)
    const key = await orgApiKey(o, id)
    const h = bearer((await orgToken(id, key)).body.access_token)
    const sync = (body: unknown, path = '/public/organization/import') =>
      call(path, { method: 'POST', headers: h, body })

    const before = mail.sent.length
    const first = await sync({
      members: [
        { email: 'dc-alice@example.com', externalId: 'cn=alice', deleted: false },
        { email: 'DC-Bob@example.com', externalId: 'cn=bob' },
        { email: 'dc-existing@example.com', externalId: 'cn=existing' },
      ],
      groups: [
        {
          name: 'Staff',
          externalId: 'cn=staff',
          memberExternalIds: ['cn=alice', 'cn=bob', 'cn=existing'],
        },
        { name: 'Admins', externalId: 'cn=admins', memberExternalIds: ['cn=alice'] },
      ],
      overwriteExisting: false,
      largeImport: false,
    })
    expect(first.status).toBe(200)
    conforms('POST /public/organization/import', 200, null)
    expect(mail.sent.length).toBe(before + 2)

    const members = (await o.json(`/api/organizations/${id}/users?includeGroups=true`)).data
    const byEmail = (e: string) => members.find((m: any) => m.email === e)
    expect(byEmail('dc-alice@example.com')).toMatchObject({
      status: 0,
      externalId: 'cn=alice',
      type: 2,
    })
    expect(byEmail('dc-bob@example.com').externalId).toBe('cn=bob')
    expect(byEmail('dc-existing@example.com')).toMatchObject({
      status: 2,
      externalId: 'cn=existing',
    })
    const groups = (await o.json(`/api/organizations/${id}/groups`)).data
    const staff = groups.find((g: any) => g.externalId === 'cn=staff')
    expect((await o.json(`/api/organizations/${id}/groups/${staff.id}/users`)).sort()).toEqual(
      [
        byEmail('dc-alice@example.com').id,
        byEmail('dc-bob@example.com').id,
        byEmail('dc-existing@example.com').id,
      ].sort(),
    )

    // A second identical run changes nothing and sends no mail.
    const mid = mail.sent.length
    expect(
      (
        await sync({
          members: [{ email: 'dc-alice@example.com', externalId: 'cn=alice' }],
          groups: [],
        })
      ).status,
    ).toBe(200)
    expect(mail.sent.length).toBe(mid)
    expect((await o.json(`/api/organizations/${id}/users`)).data).toHaveLength(4)

    // Deleted entries are removed; groups are renamed and membership replaced.
    await sync({
      members: [{ email: 'dc-bob@example.com', externalId: 'cn=bob', deleted: true }],
      groups: [{ name: 'Everyone', externalId: 'cn=staff', memberExternalIds: ['cn=alice'] }],
      inviteUsersAfterProvisioning: false,
    })
    const after = (await o.json(`/api/organizations/${id}/users`)).data
    expect(after.some((m: any) => m.email === 'dc-bob@example.com')).toBe(false)
    const renamed = await o.json(`/api/organizations/${id}/groups/${staff.id}`)
    expect(renamed.name).toBe('Everyone')
    expect(await o.json(`/api/organizations/${id}/groups/${staff.id}/users`)).toEqual([
      byEmail('dc-alice@example.com').id,
    ])

    // Overwrite: members and groups with an external id not in the import go; the owner stays.
    await sync(
      {
        members: [{ email: 'dc-alice@example.com', externalId: 'cn=alice' }],
        groups: [{ name: 'Everyone', externalId: 'cn=staff', memberExternalIds: ['cn=alice'] }],
        overwriteExisting: true,
      },
      '/api/public/organization/import',
    )
    const final = (await o.json(`/api/organizations/${id}/users`)).data
      .map((m: any) => m.email)
      .sort()
    expect(final).toEqual(['dc-alice@example.com', 'dc-owner@example.com'])
    const finalGroups = (await o.json(`/api/organizations/${id}/groups`)).data
    expect(finalGroups.map((g: any) => g.externalId)).toEqual(['cn=staff'])

    const events = await o.json(`/api/organizations/${id}/events`)
    const dcInvites = events.data.filter((e: any) => e.type === 1500 && e.actingUserId === null)
    expect(dcInvites).toHaveLength(2)
    expect(dcInvites.every((e: any) => e.systemUser === 3)).toBe(true)

    const bad = await sync({ members: [{ email: 'x@example.com' }] })
    expect(bad.status).toBe(400)
    expect(await bad.json()).toMatchObject({ object: 'error' })
  })

  it('keeps admins and custom members unless removing them is requested', async () => {
    const o = await actor('dcp-owner@example.com')
    const { id } = await createOrg(o, 'Privileged Org')
    const admin = await actor('dcp-admin@example.com')
    const custom = await actor('dcp-custom@example.com')
    await addMember(o, id, admin, { type: 1 })
    await addMember(o, id, custom, { type: 4, permissions: { accessEventLogs: true } })
    const h = bearer((await orgToken(id, await orgApiKey(o, id))).body.access_token)
    const sync = (body: unknown) =>
      call('/public/organization/import', { method: 'POST', headers: h, body })
    await sync({
      members: [
        { email: 'dcp-admin@example.com', externalId: 'a' },
        { email: 'dcp-custom@example.com', externalId: 'c' },
      ],
    })
    const emails = async () =>
      (await o.json(`/api/organizations/${id}/users`)).data.map((m: any) => m.email).sort()
    await sync({
      members: [{ email: 'dcp-admin@example.com', externalId: 'a', deleted: true }],
      overwriteExisting: true,
    })
    expect(await emails()).toEqual([
      'dcp-admin@example.com',
      'dcp-custom@example.com',
      'dcp-owner@example.com',
    ])
    await sync({ members: [], overwriteExisting: true, removePrivilegedMembers: true })
    expect(await emails()).toEqual(['dcp-owner@example.com'])
  })
})
