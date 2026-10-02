// Secrets Manager (TASKS #220): projects, secrets, machine accounts, access tokens, machine login,
// access policy enforcement, sync and events.
import { beforeAll, describe, expect, it } from 'vitest'
import { authed, form } from './helpers'
import { type Actor, actor, addMember, createOrg } from './org-helpers'

const enc = (label: string) =>
  `2.${btoa(`${label}-iv`)}|${btoa(`${label}-ct`)}|${btoa(`${label}-mac`)}`
const NIL = '00000000-0000-4000-8000-000000000000'

interface Machine {
  saId: string
  tokenId: string
  clientSecret: string
  payload: string
}

const machineLogin = (clientId: string, clientSecret: string) =>
  form('/identity/connect/token', {
    grant_type: 'client_credentials',
    scope: 'api.secrets',
    client_id: clientId,
    client_secret: clientSecret,
  })

async function machineToken(m: Machine) {
  const res = await machineLogin(m.tokenId, m.clientSecret)
  expect(res.status).toBe(200)
  return ((await res.json()) as { access_token: string }).access_token
}

const decodeJwt = (t: string) =>
  JSON.parse(atob((t.split('.')[1] as string).replace(/-/g, '+').replace(/_/g, '/')))

let owner: Actor
let member: Actor
let outsider: Actor
let orgId: string
let memberOrgUserId: string

async function newMachine(name = 'ci'): Promise<Machine> {
  const sa = await owner.json(`/api/organizations/${orgId}/service-accounts`, 'POST', {
    name: enc(name),
  })
  const payload = enc(`${name}-payload`)
  const t = await owner.json(`/api/service-accounts/${sa.id}/access-tokens`, 'POST', {
    name: enc(`${name}-token`),
    encryptedPayload: payload,
    key: enc(`${name}-key`),
    expireAt: null,
  })
  return { saId: sa.id, tokenId: t.id, clientSecret: t.clientSecret, payload }
}

beforeAll(async () => {
  owner = await actor('sm-owner@example.com')
  member = await actor('sm-member@example.com')
  outsider = await actor('sm-outsider@example.com')
  orgId = (await createOrg(owner, 'SM Org')).id
  memberOrgUserId = await addMember(owner, orgId, member)
})

describe('organisation enablement', () => {
  it('reports useSecretsManager and the owner has access', async () => {
    const profile = await owner.json('/api/accounts/profile')
    const o = profile.organizations.find((x: any) => x.id === orgId)
    expect(o.useSecretsManager).toBe(true)
    expect(o.accessSecretsManager).toBe(true)
    expect((await owner.json(`/api/organizations/${orgId}`)).useSecretsManager).toBe(true)
  })

  it('keeps members without accessSecretsManager out (404)', async () => {
    const res = await member.call(`/api/organizations/${orgId}/projects`)
    expect(res.status).toBe(404)
    const m = await owner.json(`/api/organizations/${orgId}/users/${memberOrgUserId}`)
    expect(m.accessSecretsManager).toBe(false)
  })

  it('admins grant access in bulk and by member update', async () => {
    const bulk = await owner.json(
      `/api/organizations/${orgId}/users/enable-secrets-manager`,
      'PUT',
      { ids: [memberOrgUserId] },
    )
    expect(bulk.data[0]).toMatchObject({ id: memberOrgUserId, error: null })
    expect((await member.call(`/api/organizations/${orgId}/projects`)).status).toBe(200)
    const profile = await member.json('/api/accounts/profile')
    expect(profile.organizations[0].accessSecretsManager).toBe(true)

    const off = await owner.call(`/api/organizations/${orgId}/users/${memberOrgUserId}`, 'PUT', {
      type: 2,
      accessSecretsManager: false,
      collections: [],
      groups: [],
      permissions: null,
    })
    expect(off.status).toBe(200)
    expect((await member.call(`/api/organizations/${orgId}/projects`)).status).toBe(404)
    await owner.call(`/api/organizations/${orgId}/users/${memberOrgUserId}`, 'PUT', {
      type: 2,
      accessSecretsManager: true,
      collections: [],
      groups: [],
      permissions: null,
    })
    expect((await member.call(`/api/organizations/${orgId}/projects`)).status).toBe(200)
  })

  it('hides the organisation from outsiders', async () => {
    expect((await outsider.call(`/api/organizations/${orgId}/secrets`)).status).toBe(404)
  })
})

describe('projects and secrets (owner)', () => {
  it('creates, reads, updates, lists and deletes projects', async () => {
    const p = await owner.json(`/api/organizations/${orgId}/projects`, 'POST', {
      name: enc('proj'),
    })
    expect(p).toMatchObject({
      object: 'project',
      organizationId: orgId,
      name: enc('proj'),
      read: true,
      write: true,
    })
    expect(await owner.json(`/api/projects/${p.id}`)).toMatchObject({ id: p.id })
    const upd = await owner.json(`/api/projects/${p.id}`, 'PUT', { name: enc('proj2') })
    expect(upd.name).toBe(enc('proj2'))
    const listed = await owner.json(`/api/organizations/${orgId}/projects`)
    expect(listed.data.map((x: any) => x.id)).toContain(p.id)
    const del = await owner.json('/api/projects/delete', 'POST', [p.id, NIL])
    expect(del.data).toEqual([
      { object: 'bulkDeleteResponse', id: p.id, error: null },
      { object: 'bulkDeleteResponse', id: NIL, error: 'access denied' },
    ])
    expect((await owner.call(`/api/projects/${p.id}`)).status).toBe(404)
  })

  it('stores secrets opaquely with project relations and bulk operations', async () => {
    const p = await owner.json(`/api/organizations/${orgId}/projects`, 'POST', { name: enc('p') })
    const s = await owner.json(`/api/organizations/${orgId}/secrets`, 'POST', {
      key: enc('k'),
      value: enc('v'),
      note: enc('n'),
      projectIds: [p.id],
    })
    expect(s).toMatchObject({
      object: 'secret',
      key: enc('k'),
      value: enc('v'),
      note: enc('n'),
      projects: [{ id: p.id, name: enc('p') }],
      read: true,
      write: true,
    })
    const loose = await owner.json(`/api/organizations/${orgId}/secrets`, 'POST', {
      key: enc('k2'),
      value: enc('v2'),
      note: '',
      projectIds: null,
    })
    expect(loose.projects).toEqual([])

    const orgList = await owner.json(`/api/organizations/${orgId}/secrets`)
    expect(orgList.secrets.map((x: any) => x.id).sort()).toEqual([s.id, loose.id].sort())
    expect(orgList.secrets[0].value).toBeUndefined()
    expect(orgList.projects).toContainEqual({ id: p.id, name: enc('p') })
    const projList = await owner.json(`/api/projects/${p.id}/secrets`)
    expect(projList.secrets.map((x: any) => x.id)).toEqual([s.id])

    const upd = await owner.json(`/api/secrets/${loose.id}`, 'PUT', {
      key: enc('k2b'),
      value: enc('v2b'),
      note: enc('n2b'),
      projectIds: [p.id],
      valueChanged: true,
    })
    expect(upd).toMatchObject({ key: enc('k2b'), projects: [{ id: p.id }] })

    const byIds = await owner.json('/api/secrets/get-by-ids', 'POST', { ids: [s.id, loose.id] })
    expect(byIds.data.map((x: any) => x.value).sort()).toEqual([enc('v'), enc('v2b')].sort())
    expect((await owner.call('/api/secrets/get-by-ids', 'POST', { ids: [s.id, NIL] })).status).toBe(
      404,
    )
    expect(
      (
        await owner.call(`/api/organizations/${orgId}/secrets`, 'POST', {
          key: enc('k'),
          value: enc('v'),
          note: '',
          projectIds: [p.id, p.id.replace(/.$/, '0')],
        })
      ).status,
    ).toBe(400)

    const del = await owner.json('/api/secrets/delete', 'POST', [s.id, loose.id])
    expect(del.data.every((r: any) => r.error === null)).toBe(true)
    expect((await owner.call(`/api/secrets/${s.id}`)).status).toBe(404)
  })

  it('validates bodies', async () => {
    const res = await owner.call(`/api/organizations/${orgId}/secrets`, 'POST', { key: '' })
    expect(res.status).toBe(400)
  })
})

describe('member access policies', () => {
  let projectId: string
  let secretId: string
  beforeAll(async () => {
    projectId = (
      await owner.json(`/api/organizations/${orgId}/projects`, 'POST', { name: enc('team') })
    ).id
    secretId = (
      await owner.json(`/api/organizations/${orgId}/secrets`, 'POST', {
        key: enc('tk'),
        value: enc('tv'),
        note: '',
        projectIds: [projectId],
      })
    ).id
  })

  it('a member without a policy sees nothing', async () => {
    expect((await member.call(`/api/projects/${projectId}`)).status).toBe(404)
    expect((await member.call(`/api/secrets/${secretId}`)).status).toBe(404)
    const listed = await member.json(`/api/organizations/${orgId}/secrets`)
    expect(listed.secrets).toEqual([])
    // Members may not keep secrets outside a project.
    const loose = await member.call(`/api/organizations/${orgId}/secrets`, 'POST', {
      key: enc('x'),
      value: enc('y'),
      note: '',
    })
    expect(loose.status).toBe(403)
  })

  it('read grants read; write is refused with 403', async () => {
    const put = await owner.json(`/api/projects/${projectId}/access-policies/people`, 'PUT', {
      userAccessPolicyRequests: [{ granteeId: memberOrgUserId, read: true, write: false }],
      groupAccessPolicyRequests: [],
    })
    expect(put.userAccessPolicies).toEqual([
      expect.objectContaining({
        organizationUserId: memberOrgUserId,
        read: true,
        write: false,
        currentUser: false,
      }),
    ])
    expect((await member.json(`/api/secrets/${secretId}`)).value).toBe(enc('tv'))
    const upd = await member.call(`/api/secrets/${secretId}`, 'PUT', {
      key: enc('a'),
      value: enc('b'),
      note: '',
    })
    expect(upd.status).toBe(403)
    const del = await member.json('/api/secrets/delete', 'POST', [secretId])
    expect(del.data[0].error).toBe('access denied')
    expect(
      (
        await member.call(`/api/projects/${projectId}/access-policies/people`, 'PUT', {
          userAccessPolicyRequests: [],
        })
      ).status,
    ).toBe(403)
  })

  it('group write grants write', async () => {
    const g = await owner.json(`/api/organizations/${orgId}/groups`, 'POST', {
      name: 'sm-group',
      accessAll: false,
      collections: [],
      users: [memberOrgUserId],
    })
    await owner.json(`/api/projects/${projectId}/access-policies/people`, 'PUT', {
      userAccessPolicyRequests: [],
      groupAccessPolicyRequests: [{ granteeId: g.id, read: true, write: true }],
    })
    const policies = await member.json(`/api/projects/${projectId}/access-policies/people`)
    expect(policies.groupAccessPolicies[0]).toMatchObject({
      groupId: g.id,
      groupName: 'sm-group',
      write: true,
      currentUserInGroup: true,
    })
    const upd = await member.json(`/api/secrets/${secretId}`, 'PUT', {
      key: enc('tk2'),
      value: enc('tv2'),
      note: '',
    })
    expect(upd).toMatchObject({ key: enc('tk2'), write: true })
    const created = await member.json(`/api/organizations/${orgId}/secrets`, 'POST', {
      key: enc('mk'),
      value: enc('mv'),
      note: '',
      projectIds: [projectId],
    })
    expect(created.write).toBe(true)
  })

  it('a member who creates a project gets write on it', async () => {
    const p = await member.json(`/api/organizations/${orgId}/projects`, 'POST', {
      name: enc('mine'),
    })
    expect(p.write).toBe(true)
    expect((await member.call(`/api/projects/${p.id}`, 'PUT', { name: enc('m2') })).status).toBe(
      200,
    )
  })

  it('direct secret policies come from accessPoliciesRequests', async () => {
    const s = await owner.json(`/api/organizations/${orgId}/secrets`, 'POST', {
      key: enc('direct'),
      value: enc('dv'),
      note: '',
      accessPoliciesRequests: {
        userAccessPolicyRequests: [{ granteeId: memberOrgUserId, read: true, write: false }],
        groupAccessPolicyRequests: [],
        serviceAccountAccessPolicyRequests: [],
      },
    })
    expect((await member.json(`/api/secrets/${s.id}`)).read).toBe(true)
    const pol = await owner.json(`/api/secrets/${s.id}/access-policies`)
    expect(pol.userAccessPolicies[0].organizationUserId).toBe(memberOrgUserId)
    expect(pol.serviceAccountAccessPolicies).toEqual([])
  })

  it('lists potential grantees', async () => {
    const people = await owner.json(
      `/api/organizations/${orgId}/access-policies/people/potential-grantees`,
    )
    const types = new Set(people.data.map((g: any) => g.type))
    expect(types).toEqual(new Set(['user', 'group']))
    const projects = await owner.json(
      `/api/organizations/${orgId}/access-policies/projects/potential-grantees`,
    )
    expect(projects.data.map((p: any) => p.id)).toContain(projectId)
  })
})

describe('machine accounts and tokens', () => {
  it('CRUD and token lifecycle', async () => {
    const sa = await owner.json(`/api/organizations/${orgId}/service-accounts`, 'POST', {
      name: enc('sa'),
    })
    expect(sa).toMatchObject({ object: 'serviceAccount', organizationId: orgId, name: enc('sa') })
    expect((await owner.json(`/api/service-accounts/${sa.id}`)).id).toBe(sa.id)
    expect(
      (await owner.json(`/api/service-accounts/${sa.id}`, 'PUT', { name: enc('sa2') })).name,
    ).toBe(enc('sa2'))
    const listed = await owner.json(
      `/api/organizations/${orgId}/service-accounts?includeAccessToSecrets=true`,
    )
    expect(listed.data.find((x: any) => x.id === sa.id)).toMatchObject({ accessToSecrets: 0 })

    const t = await owner.json(`/api/service-accounts/${sa.id}/access-tokens`, 'POST', {
      name: enc('tok'),
      encryptedPayload: enc('payload'),
      key: enc('key'),
      expireAt: new Date(Date.now() + 86_400_000).toISOString(),
    })
    expect(t).toMatchObject({ object: 'accessTokenCreation', name: enc('tok') })
    expect(t.clientSecret).toMatch(/^[A-Za-z0-9]{30}$/)
    const tokens = await owner.json(`/api/service-accounts/${sa.id}/access-tokens`)
    expect(tokens.data).toEqual([
      expect.objectContaining({ id: t.id, scopes: ['api.secrets'], expireAt: t.expireAt }),
    ])
    expect(JSON.stringify(tokens)).not.toContain(t.clientSecret)
    const counts = await owner.json(`/api/service-accounts/${sa.id}/sm-counts`)
    expect(counts).toMatchObject({ accessTokens: 1, projects: 0 })

    expect(
      (
        await owner.call(`/api/service-accounts/${sa.id}/access-tokens/revoke`, 'POST', {
          ids: [t.id],
        })
      ).status,
    ).toBe(200)
    expect((await owner.json(`/api/service-accounts/${sa.id}/access-tokens`)).data).toEqual([])
    const del = await owner.json('/api/service-accounts/delete', 'POST', [sa.id])
    expect(del.data[0].error).toBe(null)
    expect((await owner.call(`/api/service-accounts/${sa.id}`)).status).toBe(404)
  })

  it('rejects past expiry dates', async () => {
    const sa = await owner.json(`/api/organizations/${orgId}/service-accounts`, 'POST', {
      name: enc('x'),
    })
    const res = await owner.call(`/api/service-accounts/${sa.id}/access-tokens`, 'POST', {
      name: enc('t'),
      encryptedPayload: enc('p'),
      key: enc('k'),
      expireAt: '2000-01-01T00:00:00Z',
    })
    expect(res.status).toBe(400)
  })

  it('members without a policy cannot see a machine account', async () => {
    const m = await newMachine('hidden')
    expect((await member.call(`/api/service-accounts/${m.saId}`)).status).toBe(404)
    await owner.json(`/api/service-accounts/${m.saId}/access-policies/people`, 'PUT', {
      userAccessPolicyRequests: [{ granteeId: memberOrgUserId, read: true, write: false }],
      groupAccessPolicyRequests: [],
    })
    expect((await member.call(`/api/service-accounts/${m.saId}`)).status).toBe(200)
    expect((await member.call(`/api/service-accounts/${m.saId}/access-tokens`)).status).toBe(403)
  })
})

describe('machine login and enforcement', () => {
  let m: Machine
  let token: string
  let projectId: string
  let secretId: string
  let otherSecret: string

  beforeAll(async () => {
    m = await newMachine('bot')
    projectId = (
      await owner.json(`/api/organizations/${orgId}/projects`, 'POST', { name: enc('deploy') })
    ).id
    secretId = (
      await owner.json(`/api/organizations/${orgId}/secrets`, 'POST', {
        key: enc('DB_URL'),
        value: enc('postgres'),
        note: '',
        projectIds: [projectId],
      })
    ).id
    otherSecret = (
      await owner.json(`/api/organizations/${orgId}/secrets`, 'POST', {
        key: enc('OTHER'),
        value: enc('other'),
        note: '',
      })
    ).id
  })

  it('logs in with the token id and secret and returns the encrypted payload', async () => {
    const res = await machineLogin(m.tokenId, m.clientSecret)
    expect(res.status).toBe(200)
    const body = (await res.json()) as Record<string, any>
    expect(body).toMatchObject({
      token_type: 'Bearer',
      scope: 'api.secrets',
      encrypted_payload: m.payload,
    })
    expect(body.expires_in).toBeGreaterThan(0)
    // The SDK would read a Kdf member as a user login.
    expect(body.Kdf).toBeUndefined()
    expect(body.Key).toBeUndefined()
    const claims = decodeJwt(body.access_token)
    expect(claims).toMatchObject({
      sub: m.saId,
      organization: orgId,
      client_id: m.tokenId,
      scope: ['api.secrets'],
    })
    token = body.access_token
  })

  it('refuses bad credentials', async () => {
    const wrong = await machineLogin(m.tokenId, 'x'.repeat(30))
    expect(wrong.status).toBe(400)
    expect(((await wrong.json()) as any).error).toBe('invalid_client')
    expect((await machineLogin(NIL, m.clientSecret)).status).toBe(400)
    expect((await machineLogin(`0.${m.tokenId}`, m.clientSecret)).status).toBe(400)
  })

  it('is refused outside Secrets Manager routes', async () => {
    expect((await authed('/api/sync', token)).status).toBe(401)
    expect((await authed('/api/accounts/profile', token)).status).toBe(401)
    expect((await authed(`/api/organizations/${orgId}/users`, token)).status).toBe(401)
    expect((await authed(`/api/organizations/${orgId}/service-accounts`, token)).status).toBe(404)
    expect((await authed(`/api/service-accounts/${m.saId}`, token)).status).toBe(404)
    expect((await authed(`/api/organizations/${NIL}/secrets`, token)).status).toBe(404)
  })

  it('sees nothing without a policy', async () => {
    const listed = (await (
      await authed(`/api/organizations/${orgId}/secrets`, token)
    ).json()) as any
    expect(listed.secrets).toEqual([])
    expect((await authed(`/api/secrets/${secretId}`, token)).status).toBe(404)
    expect((await authed(`/api/projects/${projectId}`, token)).status).toBe(404)
    expect(
      (await authed('/api/secrets/get-by-ids', token, 'POST', { ids: [secretId] })).status,
    ).toBe(404)
  })

  it('reads through a project grant, but cannot write with read only', async () => {
    const put = await owner.json(
      `/api/projects/${projectId}/access-policies/service-accounts`,
      'PUT',
      { serviceAccountAccessPolicyRequests: [{ granteeId: m.saId, read: true, write: false }] },
    )
    expect(put.serviceAccountAccessPolicies).toEqual([
      expect.objectContaining({ serviceAccountId: m.saId, read: true, write: false }),
    ])
    const listed = (await (
      await authed(`/api/organizations/${orgId}/secrets`, token)
    ).json()) as any
    expect(listed.secrets.map((s: any) => s.id)).toEqual([secretId])
    const got = (await (await authed(`/api/secrets/${secretId}`, token)).json()) as any
    expect(got.value).toBe(enc('postgres'))
    expect((await authed(`/api/secrets/${otherSecret}`, token)).status).toBe(404)
    const byIds = (await (
      await authed('/api/secrets/get-by-ids', token, 'POST', { ids: [secretId] })
    ).json()) as any
    expect(byIds.data[0].value).toBe(enc('postgres'))
    const create = await authed(`/api/organizations/${orgId}/secrets`, token, 'POST', {
      key: enc('new'),
      value: enc('new'),
      note: '',
      projectIds: [projectId],
    })
    expect(create.status).toBe(403)
    const edit = await authed(`/api/secrets/${secretId}`, token, 'PUT', {
      key: enc('a'),
      value: enc('b'),
      note: '',
    })
    expect(edit.status).toBe(403)
    const counts = await owner.json(
      `/api/organizations/${orgId}/service-accounts?includeAccessToSecrets=true`,
    )
    expect(counts.data.find((x: any) => x.id === m.saId).accessToSecrets).toBe(1)
  })

  it('writes with a write grant (granted policies endpoint)', async () => {
    const put = await owner.json(`/api/service-accounts/${m.saId}/granted-policies`, 'PUT', {
      projectGrantedPolicyRequests: [{ grantedId: projectId, read: true, write: true }],
    })
    expect(put.grantedProjectPolicies[0]).toMatchObject({
      accessPolicy: { grantedProjectId: projectId, read: true, write: true },
      hasPermission: true,
    })
    const created = await authed(`/api/organizations/${orgId}/secrets`, token, 'POST', {
      key: enc('NEW'),
      value: enc('value'),
      note: '',
      projectIds: [projectId],
    })
    expect(created.status).toBe(200)
    const loose = await authed(`/api/organizations/${orgId}/secrets`, token, 'POST', {
      key: enc('LOOSE'),
      value: enc('value'),
      note: '',
    })
    expect(loose.status).toBe(403)
    const id = ((await created.json()) as any).id
    const del = (await (await authed('/api/secrets/delete', token, 'POST', [id])).json()) as any
    expect(del.data[0].error).toBe(null)
  })

  it('syncs with lastSyncedDate', async () => {
    const first = (await (
      await authed(`/api/organizations/${orgId}/secrets/sync`, token)
    ).json()) as any
    expect(first).toMatchObject({ object: 'secretsSync', hasChanges: true })
    expect(first.secrets.data.map((s: any) => s.id)).toEqual([secretId])
    const later = new Date(Date.now() + 1000).toISOString()
    const none = (await (
      await authed(`/api/organizations/${orgId}/secrets/sync?lastSyncedDate=${later}`, token)
    ).json()) as any
    expect(none).toEqual({ object: 'secretsSync', hasChanges: false, secrets: null })
    const before = new Date(Date.now() - 1).toISOString()
    await new Promise((r) => setTimeout(r, 5))
    await owner.json(`/api/secrets/${secretId}`, 'PUT', {
      key: enc('DB_URL'),
      value: enc('rotated'),
      note: '',
    })
    const changed = (await (
      await authed(`/api/organizations/${orgId}/secrets/sync?lastSyncedDate=${before}`, token)
    ).json()) as any
    expect(changed.hasChanges).toBe(true)
    expect(changed.secrets.data[0].value).toBe(enc('rotated'))
  })

  it('records events for Secrets Manager actions', async () => {
    const events = await owner.json(`/api/organizations/${orgId}/events`)
    const types = new Set(events.data.map((e: any) => e.type))
    for (const t of [2100, 2101, 2102, 2201, 2304]) expect(types.has(t), String(t)).toBe(true)
    const retrieved = events.data.find((e: any) => e.type === 2100)
    expect(retrieved).toMatchObject({ serviceAccountId: m.saId, actingUserId: null })
    expect(retrieved.secretId).toBeTruthy()
    const saEvents = await owner.json(`/api/sm/events/service-accounts/${m.saId}`)
    expect(saEvents.data.length).toBeGreaterThan(0)
    expect(
      saEvents.data.every((e: any) =>
        [e.serviceAccountId, e.grantedServiceAccountId].includes(m.saId),
      ),
    ).toBe(true)
  })

  it('stops working as soon as the token is revoked', async () => {
    await owner.call(`/api/service-accounts/${m.saId}/access-tokens/revoke`, 'POST', {
      ids: [m.tokenId],
    })
    expect((await authed(`/api/organizations/${orgId}/secrets`, token)).status).toBe(401)
    expect((await machineLogin(m.tokenId, m.clientSecret)).status).toBe(400)
  })

  it('stops working when the machine account is deleted', async () => {
    const m2 = await newMachine('gone')
    const t2 = await machineToken(m2)
    expect((await authed(`/api/organizations/${orgId}/projects`, t2)).status).toBe(200)
    await owner.json('/api/service-accounts/delete', 'POST', [m2.saId])
    expect((await authed(`/api/organizations/${orgId}/projects`, t2)).status).toBe(401)
  })
})

describe('counts', () => {
  it('reports organisation counts for members', async () => {
    const counts = await owner.json(`/api/organizations/${orgId}/sm-counts`)
    expect(counts.object).toBe('organizationCounts')
    expect(counts.projects).toBeGreaterThan(0)
    expect(counts.secrets).toBeGreaterThan(0)
    expect(counts.serviceAccounts).toBeGreaterThan(0)
  })
})

describe('security review fixes', () => {
  it('only lets a member mint a token for a machine account they cannot out-reach', async () => {
    const m = await newMachine('reach')
    const p = await owner.json(`/api/organizations/${orgId}/projects`, 'POST', { name: enc('r') })
    await owner.json(`/api/service-accounts/${m.saId}/granted-policies`, 'PUT', {
      projectGrantedPolicyRequests: [{ grantedId: p.id, read: true, write: false }],
    })
    await owner.json(`/api/service-accounts/${m.saId}/access-policies/people`, 'PUT', {
      userAccessPolicyRequests: [{ granteeId: memberOrgUserId, read: true, write: true }],
      groupAccessPolicyRequests: [],
    })
    const mint = () =>
      member.call(`/api/service-accounts/${m.saId}/access-tokens`, 'POST', {
        name: enc('t'),
        encryptedPayload: enc('p'),
        key: enc('k'),
      })
    expect((await mint()).status).toBe(403)
    await owner.json(`/api/projects/${p.id}/access-policies/people`, 'PUT', {
      userAccessPolicyRequests: [{ granteeId: memberOrgUserId, read: true, write: false }],
      groupAccessPolicyRequests: [],
    })
    expect((await mint()).status).toBe(200)
  })

  it('treats only confirmed members as grantees', async () => {
    const pending = await actor('sm-pending@example.com')
    await owner.call(`/api/organizations/${orgId}/users/invite`, 'POST', {
      emails: [pending.email],
      type: 2,
      accessSecretsManager: true,
      collections: [],
      groups: [],
      permissions: null,
    })
    const users = await owner.json(`/api/organizations/${orgId}/users`)
    const invited = users.data.find((u: any) => u.email === pending.email)
    const people = await owner.json(
      `/api/organizations/${orgId}/access-policies/people/potential-grantees`,
    )
    expect(people.data.map((g: any) => g.id)).not.toContain(invited.id)
    const p = await owner.json(`/api/organizations/${orgId}/projects`, 'POST', { name: enc('c') })
    const put = await owner.call(`/api/projects/${p.id}/access-policies/people`, 'PUT', {
      userAccessPolicyRequests: [{ granteeId: invited.id, read: true, write: false }],
      groupAccessPolicyRequests: [],
    })
    expect(put.status).toBe(400)
  })

  it('restricts who may change Secrets Manager access', async () => {
    const custom = await actor('sm-custom@example.com')
    const target = await actor('sm-target@example.com')
    const customId = await addMember(owner, orgId, custom, {
      type: 4,
      permissions: { manageUsers: true },
    })
    const targetId = await addMember(owner, orgId, target)
    const bulk = await custom.json(
      `/api/organizations/${orgId}/users/enable-secrets-manager`,
      'PUT',
      { ids: [targetId, customId] },
    )
    expect(bulk.data.every((r: any) => r.error !== null)).toBe(true)
    const upd = await custom.call(`/api/organizations/${orgId}/users/${targetId}`, 'PUT', {
      type: 2,
      accessSecretsManager: true,
      collections: [],
      groups: [],
      permissions: null,
    })
    expect(upd.status).toBe(403)
    const inv = await custom.call(`/api/organizations/${orgId}/users/invite`, 'POST', {
      emails: ['sm-new@example.com'],
      type: 2,
      accessSecretsManager: true,
      collections: [],
      groups: [],
      permissions: null,
    })
    expect(inv.status).toBe(403)
    // Once the custom member has access they may grant it, but never to themselves.
    await owner.json(`/api/organizations/${orgId}/users/enable-secrets-manager`, 'PUT', {
      ids: [customId],
    })
    const again = await custom.json(
      `/api/organizations/${orgId}/users/enable-secrets-manager`,
      'PUT',
      { ids: [targetId, customId] },
    )
    expect(again.data.find((r: any) => r.id === targetId).error).toBe(null)
    expect(again.data.find((r: any) => r.id === customId).error).not.toBe(null)
  })

  it('marks secrets changed when membership or groups change', async () => {
    const m = await newMachine('rev')
    const t = await machineToken(m)
    const now = new Date(Date.now() + 1).toISOString()
    await new Promise((r) => setTimeout(r, 5))
    const q = `/api/organizations/${orgId}/secrets/sync?lastSyncedDate=${now}`
    expect(((await (await authed(q, t)).json()) as any).hasChanges).toBe(false)
    await owner.json(`/api/organizations/${orgId}/groups`, 'POST', {
      name: 'rev-group',
      accessAll: false,
      collections: [],
      users: [],
    })
    expect(((await (await authed(q, t)).json()) as any).hasChanges).toBe(true)
  })
})

describe('trash (TASKS #231)', () => {
  it('moves deleted secrets to the trash, restores them and empties it', async () => {
    const p = await owner.json(`/api/organizations/${orgId}/projects`, 'POST', {
      name: enc('trash-p'),
    })
    const mk = async (label: string) =>
      (
        await owner.json(`/api/organizations/${orgId}/secrets`, 'POST', {
          key: enc(label),
          value: enc(`${label}-v`),
          note: '',
          projectIds: [p.id],
        })
      ).id as string
    const a = await mk('TRASH_A')
    const b = await mk('TRASH_B')
    const del = await owner.json('/api/secrets/delete', 'POST', [a, b])
    expect(del.data.every((r: any) => r.error === null)).toBe(true)

    // Hidden from every normal read.
    expect((await owner.call(`/api/secrets/${a}`)).status).toBe(404)
    const listed = await owner.json(`/api/organizations/${orgId}/secrets`)
    expect(listed.secrets.some((s: any) => [a, b].includes(s.id))).toBe(false)
    expect((await owner.call('/api/secrets/get-by-ids', 'POST', { ids: [a] })).status).toBe(404)
    const again = await owner.json('/api/secrets/delete', 'POST', [a])
    expect(again.data[0].error).not.toBe(null)

    const trash = await owner.json(`/api/secrets/${orgId}/trash`)
    expect(trash.object).toBe('SecretsWithProjectsList')
    const ids = trash.secrets.map((s: any) => s.id)
    expect(ids).toContain(a)
    expect(ids).toContain(b)
    expect(trash.projects.map((x: any) => x.id)).toContain(p.id)

    // Outsiders and members without Secrets Manager access cannot see the trash.
    expect((await outsider.call(`/api/secrets/${orgId}/trash`)).status).toBe(404)
    expect((await outsider.call(`/api/secrets/${orgId}/trash/restore`, 'POST', [a])).status).toBe(
      404,
    )
    // Unknown or live ids are refused as a whole.
    expect((await owner.call(`/api/secrets/${orgId}/trash/restore`, 'POST', [a, NIL])).status).toBe(
      404,
    )

    expect((await owner.call(`/api/secrets/${orgId}/trash/restore`, 'POST', [a])).status).toBe(200)
    expect((await owner.json(`/api/secrets/${a}`)).id).toBe(a)
    expect((await owner.call(`/api/secrets/${orgId}/trash/empty`, 'POST', [b])).status).toBe(200)
    const left = (await owner.json(`/api/secrets/${orgId}/trash`)).secrets.map((s: any) => s.id)
    expect(left).not.toContain(a)
    expect(left).not.toContain(b)
    const events = await owner.json(`/api/organization/${orgId}/secrets/${a}/events`)
    const types = events.data.map((e: any) => e.type)
    expect(types).toContain(2103)
    expect(types).toContain(2105)
    const orgEvents = await owner.json(`/api/organizations/${orgId}/events`)
    expect(orgEvents.data.some((e: any) => e.type === 2104 && e.secretId === b)).toBe(true)
  })
})

describe('object events (TASKS #231)', () => {
  it('lists events of a project, a secret and a machine account', async () => {
    const p = await owner.json(`/api/organizations/${orgId}/projects`, 'POST', {
      name: enc('ev-p'),
    })
    await owner.json(`/api/projects/${p.id}`, 'PUT', { name: enc('ev-p2') })
    const s = await owner.json(`/api/organizations/${orgId}/secrets`, 'POST', {
      key: enc('EV'),
      value: enc('v'),
      note: '',
      projectIds: [p.id],
    })
    const sa = await owner.json(`/api/organizations/${orgId}/service-accounts`, 'POST', {
      name: enc('ev-sa'),
    })
    const pe = await owner.json(`/api/organization/${orgId}/projects/${p.id}/events`)
    expect(pe.object).toBe('list')
    expect(pe.data.map((e: any) => e.type).sort()).toEqual([2201, 2202])
    expect(pe.data.every((e: any) => e.projectId === p.id)).toBe(true)
    const se = await owner.json(`/api/organization/${orgId}/secrets/${s.id}/events`)
    expect(se.data.map((e: any) => e.type)).toEqual([2101])
    const sae = await owner.json(`/api/organization/${orgId}/service-account/${sa.id}/events`)
    expect(sae.data.map((e: any) => e.type)).toEqual([2304])

    // Wrong organisation in the path, outsiders and bad ids are 404.
    expect((await owner.call(`/api/organization/${NIL}/projects/${p.id}/events`)).status).toBe(404)
    expect((await outsider.call(`/api/organization/${orgId}/secrets/${s.id}/events`)).status).toBe(
      404,
    )
    expect((await owner.call(`/api/organization/${orgId}/service-account/x/events`)).status).toBe(
      404,
    )
  })
})
