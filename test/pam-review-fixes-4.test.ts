// Review fixes of the privileged access feature (docs/privileged-access.md), fourth round: no
// writer lets a non-admin give a member Manage access to a covered collection, or add a member to
// a group that holds it. Manage access lifts the lease restriction, so each path below used to
// turn the reduced row back into the full item. The guard lives in src/pam/manage-guard.ts.
import { beforeAll, describe, expect, it, vi } from 'vitest'

// Org flows are slow on the shared CI host (see vitest.config.ts); give each test room.
vi.setConfig({ testTimeout: 600_000 })

import { bearer, orgApiKey, raw } from './org-api-helpers'
import { type Actor, actor, addMember, createOrg, loginCipher } from './org-helpers'
import { sql } from './pam-helpers'

let owner: Actor
let manager: Actor
let decider: Actor
let approver: Actor
let target: Actor
let orgId: string
let ids: Record<string, string>
let covered: string
let cipherId: string
let deciders: string
let plain: string
let scimKey: string

const grant = (id: string, manage: boolean) => ({
  id,
  readOnly: false,
  hidePasswords: false,
  manage,
})

const readOnly = (id: string) => ({ ...grant(id, false), readOnly: true })

const scim = async (path: string, method = 'GET', body?: unknown) => {
  const res = await raw(`/scim/v2/${orgId}${path}`, {
    method,
    headers: { ...bearer(scimKey), 'Content-Type': 'application/scim+json' },
    body,
  })
  const text = await res.text()
  return { status: res.status, body: text ? JSON.parse(text) : null }
}

/** The item as /api/sync returns it to one member. */
const synced = async (who: Actor) =>
  ((await who.json('/api/sync')).ciphers as any[]).find((c) => c.id === cipherId)

/** The reduced row of the official clients: name and URIs, no secrets. */
const expectReduced = async (who: Actor) => {
  const row = await synced(who)
  expect(row).toBeDefined()
  expect(row.partialData).toEqual(expect.any(String))
  expect(row.login).toBeNull()
}

const membersOf = async (groupId: string) =>
  (
    await sql(
      'select organization_user_uuid as m from groups_users where group_uuid = ? order by 1',
      groupId,
    )
  ).results.map((r: any) => r.m as string)

const memberRows = async (email: string) =>
  (
    await sql(
      'select count(*) as n from users_organizations where organization_uuid = ? and email = ?',
      orgId,
      email,
    )
  ).results[0].n

const manageGrants = async (memberUuid: string) =>
  (
    await sql(
      'select count(*) as n from users_collections where organization_user_uuid = ? and collection_uuid = ? and manage = 1',
      memberUuid,
      covered,
    )
  ).results[0].n

beforeAll(async () => {
  owner = await actor('fix4-owner@example.com')
  manager = await actor('fix4-manager@example.com')
  decider = await actor('fix4-decider@example.com')
  approver = await actor('fix4-approver@example.com')
  target = await actor('fix4-target@example.com')
  orgId = (await createOrg(owner, 'Fix Four Org')).id
  ids = {}
  ids.approver = await addMember(owner, orgId, approver, { type: 2 })
  ids.target = await addMember(owner, orgId, target, { type: 2 })
  // The manager: manages members, groups and SCIM, but is no owner or admin and has no Manage
  // access to the covered collection (read-only access only).
  ids.manager = await addMember(owner, orgId, manager, {
    type: 4,
    permissions: { manageUsers: true, manageGroups: true, manageScim: true },
  })
  // A second custom member who does hold Manage access to the covered collection.
  ids.decider = await addMember(owner, orgId, decider, {
    type: 4,
    permissions: { manageUsers: true },
  })
  const made = await owner.json(`/api/organizations/${orgId}/collections`, 'POST', {
    name: '2.covered',
    users: [
      grant(ids.approver as string, true),
      grant(ids.decider as string, true),
      readOnly(ids.manager as string),
      readOnly(ids.target as string),
    ],
    groups: [],
  })
  covered = made.id
  cipherId = (
    await owner.json('/api/ciphers/create', 'POST', {
      cipher: loginCipher('2.prod', { organizationId: orgId }),
      collectionIds: [covered],
    })
  ).id
  const rule = await owner.call(`/api/organizations/${orgId}/access-rules`, 'POST', {
    name: 'Rule',
    enabled: true,
    conditions: { approvalMode: 'Human' },
    singleActiveLease: false,
    defaultLeaseDurationSeconds: 3600,
    maxLeaseDurationSeconds: 7200,
    allowsExtensions: true,
    maxExtensionDurationSeconds: 1800,
    collections: [covered],
  })
  expect(rule.status).toBe(200)
  // A group that holds Manage access to the covered collection, and one that holds nothing.
  deciders = (
    await owner.json(`/api/organizations/${orgId}/groups`, 'POST', {
      name: 'Deciders',
      users: [ids.approver],
      collections: [grant(covered, true)],
    })
  ).id
  plain = (
    await owner.json(`/api/organizations/${orgId}/groups`, 'POST', {
      name: 'Plain',
      users: [],
      collections: [],
    })
  ).id
  // The manager reads the SCIM key (`manageScim`), as org-api-keys.ts allows.
  const cfg = await owner.json(`/api/organizations/${orgId}/scim-config`, 'PUT', {
    enabled: true,
    provider: 1,
  })
  expect(cfg.enabled).toBe(true)
  scimKey = await orgApiKey(manager, orgId, 2)
}, 600_000)

describe('no path gives a non-admin Manage access to a covered collection (round 4, A)', () => {
  it('starts with the reduced row for the manager and the target', async () => {
    await expectReduced(manager)
    await expectReduced(target)
  })

  it('refuses SCIM PATCH and PUT that add a member to a group that holds Manage access', async () => {
    const patch = await scim(`/Groups/${deciders}`, 'PATCH', {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'Add', path: 'members', value: [{ value: ids.manager }] }],
    })
    expect(patch.status).toBe(403)
    expect(patch.body).toMatchObject({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '403',
    })
    const put = await scim(`/Groups/${deciders}`, 'PUT', {
      displayName: 'Deciders',
      members: [{ value: ids.approver }, { value: ids.manager }],
    })
    expect(put.status).toBe(403)
    expect(await membersOf(deciders)).toEqual([ids.approver])
    await expectReduced(manager)
  })

  it('refuses a directory import that puts the importer into a group that holds Manage access', async () => {
    // Step one is allowed: a rename that keeps the group as it is.
    const named = await manager.call(`/api/organizations/${orgId}/groups/${deciders}`, 'PUT', {
      name: 'Deciders',
      externalId: 'deciders',
      users: [ids.approver],
      collections: [grant(covered, true)],
    })
    expect(named.status).toBe(200)
    const res = await manager.call(`/api/organizations/${orgId}/import`, 'POST', {
      groups: [{ name: 'Deciders', externalId: 'deciders', users: ['appr-ext', 'mgr-ext'] }],
      users: [
        { email: approver.email, externalId: 'appr-ext', deleted: false },
        { email: manager.email, externalId: 'mgr-ext', deleted: false },
      ],
    })
    expect(res.status).toBe(403)
    expect(await membersOf(deciders)).toEqual([ids.approver])
    await expectReduced(manager)
  })

  it('refuses to invite a second account with Manage access to the covered collection', async () => {
    const email = 'fix4-second@example.com'
    const res = await manager.call(`/api/organizations/${orgId}/users/invite`, 'POST', {
      emails: [email],
      type: 2,
      collections: [grant(covered, true)],
      groups: [],
    })
    expect(res.status).toBe(403)
    expect(await memberRows(email)).toBe(0)
  })

  it('refuses to invite a member into a group that holds Manage access', async () => {
    const email = 'fix4-second-group@example.com'
    const res = await manager.call(`/api/organizations/${orgId}/users/invite`, 'POST', {
      emails: [email],
      type: 2,
      collections: [],
      groups: [deciders],
    })
    expect(res.status).toBe(403)
    expect(await memberRows(email)).toBe(0)
  })

  it('refuses to update a member with Manage access to the covered collection', async () => {
    const res = await manager.call(`/api/organizations/${orgId}/users/${ids.target}`, 'PUT', {
      type: 2,
      accessAll: false,
      collections: [grant(covered, true)],
    })
    expect(res.status).toBe(403)
    expect(await manageGrants(ids.target as string)).toBe(0)
    await expectReduced(target)
  })

  it('refuses to update a member into a group that holds Manage access', async () => {
    const res = await manager.call(`/api/organizations/${orgId}/users/${ids.target}`, 'PUT', {
      type: 2,
      accessAll: false,
      groups: [deciders],
    })
    expect(res.status).toBe(403)
    expect(await membersOf(deciders)).toEqual([ids.approver])
    await expectReduced(target)
  })

  it('refuses PUT users/:id/groups into a group that holds Manage access', async () => {
    const res = await manager.call(
      `/api/organizations/${orgId}/users/${ids.target}/groups`,
      'PUT',
      { groupIds: [deciders] },
    )
    expect(res.status).toBe(403)
    expect(await membersOf(deciders)).toEqual([ids.approver])
    await expectReduced(target)
  })

  it('keeps allowing what lifts nothing', async () => {
    // A plain group, and an update that leaves the member as it is.
    const join = await manager.call(
      `/api/organizations/${orgId}/users/${ids.target}/groups`,
      'PUT',
      { groupIds: [plain] },
    )
    expect(join.status).toBe(200)
    const same = await manager.call(`/api/organizations/${orgId}/users/${ids.target}`, 'PUT', {
      type: 2,
      accessAll: false,
      collections: [readOnly(covered)],
      groups: [plain],
    })
    expect(same.status).toBe(200)
    // SCIM adds members to a group that holds no Manage access.
    const add = await scim(`/Groups/${plain}`, 'PATCH', {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'Add', path: 'members', value: [{ value: ids.approver }] }],
    })
    expect(add.status).toBe(200)
    await expectReduced(target)
  })
})

describe('owners and holders of Manage access keep their grants (round 4, control)', () => {
  it('lets a member with Manage access invite a second account with it', async () => {
    const res = await decider.call(`/api/organizations/${orgId}/users/invite`, 'POST', {
      emails: ['fix4-decider-invite@example.com'],
      type: 2,
      collections: [grant(covered, true)],
      groups: [deciders],
    })
    expect(res.status).toBe(200)
  })

  it('lets an owner invite, update and change groups with Manage access', async () => {
    const invite = await owner.call(`/api/organizations/${orgId}/users/invite`, 'POST', {
      emails: ['fix4-owner-invite@example.com'],
      type: 2,
      collections: [grant(covered, true)],
      groups: [deciders],
    })
    expect(invite.status).toBe(200)
    const groups = await owner.call(
      `/api/organizations/${orgId}/users/${ids.target}/groups`,
      'PUT',
      { groupIds: [deciders] },
    )
    expect(groups.status).toBe(200)
    const update = await owner.call(`/api/organizations/${orgId}/users/${ids.target}`, 'PUT', {
      type: 2,
      accessAll: false,
      collections: [grant(covered, true)],
      groups: [deciders],
    })
    expect(update.status).toBe(200)
    expect(await manageGrants(ids.target as string)).toBe(1)
    // The target now holds Manage access, so the item is full for them.
    const row = await synced(target)
    expect(row.login).not.toBeNull()
  })

  it('lets an owner import a member into a group that holds Manage access', async () => {
    const res = await owner.call(`/api/organizations/${orgId}/import`, 'POST', {
      groups: [{ name: 'Deciders', externalId: 'deciders', users: ['appr-ext', 'mgr-ext'] }],
      users: [
        { email: approver.email, externalId: 'appr-ext', deleted: false },
        { email: manager.email, externalId: 'mgr-ext', deleted: false },
      ],
    })
    expect(res.status).toBe(200)
    expect(await membersOf(deciders)).toEqual([ids.approver, ids.manager].sort())
  })
})

describe('a restore does not turn old Manage grants back on (round 4, restore)', () => {
  let direct: Actor
  let viaGroup: Actor
  let bulk: Actor
  let viaScim: Actor
  let control: Actor
  // A custom member who manages members and holds no Manage access (the earlier controls made
  // `manager` a member of the Deciders group).
  let restorer: Actor
  const rid: Record<string, string> = {}

  /** An admin (the owner) gives the member Manage access to the covered collection, then revokes them. */
  const grantAndRevoke = async (who: Actor, key: string, how: 'direct' | 'group') => {
    rid[key] = await addMember(owner, orgId, who, {
      type: 2,
      collections: [readOnly(covered)],
    })
    const body =
      how === 'direct'
        ? { type: 2, accessAll: false, collections: [grant(covered, true)] }
        : { type: 2, accessAll: false, groups: [deciders] }
    expect(
      (await owner.call(`/api/organizations/${orgId}/users/${rid[key]}`, 'PUT', body)).status,
    ).toBe(200)
    expect(
      (await owner.call(`/api/organizations/${orgId}/users/${rid[key]}/revoke`, 'PUT')).status,
    ).toBe(200)
  }

  const statusOf = async (key: string) =>
    (await sql('select status as s from users_organizations where uuid = ?', rid[key])).results[0]
      .s as number

  /** The revoked member must not read the item in full. */
  const notFull = async (who: Actor) => {
    const res = await who.call('/api/sync')
    if (res.status !== 200) return
    const row = ((await res.json<any>()).ciphers as any[]).find((c) => c.id === cipherId)
    if (row) expect(row.login).toBeNull()
  }

  beforeAll(async () => {
    direct = await actor('fix4-restore-direct@example.com')
    viaGroup = await actor('fix4-restore-group@example.com')
    bulk = await actor('fix4-restore-bulk@example.com')
    viaScim = await actor('fix4-restore-scim@example.com')
    control = await actor('fix4-restore-control@example.com')
    restorer = await actor('fix4-restorer@example.com')
    await addMember(owner, orgId, restorer, { type: 4, permissions: { manageUsers: true } })
    await grantAndRevoke(direct, 'direct', 'direct')
    await grantAndRevoke(viaGroup, 'group', 'group')
    await grantAndRevoke(bulk, 'bulk', 'direct')
    await grantAndRevoke(viaScim, 'scim', 'direct')
    await grantAndRevoke(control, 'control', 'direct')
  }, 600_000)

  it('refuses a restore by a custom member of an account that holds Manage access directly', async () => {
    const res = await restorer.call(
      `/api/organizations/${orgId}/users/${rid.direct}/restore`,
      'PUT',
    )
    expect(res.status).toBe(403)
    expect(await statusOf('direct')).toBe(-1)
    await notFull(direct)
  })

  it('refuses a restore of an account that holds Manage access through a group', async () => {
    const res = await restorer.call(`/api/organizations/${orgId}/users/${rid.group}/restore`, 'PUT')
    expect(res.status).toBe(403)
    expect(await statusOf('group')).toBe(-1)
    await notFull(viaGroup)
  })

  it('refuses a bulk restore with an error row and leaves the member revoked', async () => {
    const res = await restorer.call(`/api/organizations/${orgId}/users/restore`, 'PUT', {
      ids: [rid.bulk],
    })
    expect(res.status).toBe(200)
    const body = await res.json<any>()
    expect(body.data[0].error).toEqual(expect.any(String))
    expect(await statusOf('bulk')).toBe(-1)
    await notFull(bulk)
  })

  it('refuses SCIM active: true for an account that holds Manage access', async () => {
    const res = await scim(`/Users/${rid.scim}`, 'PATCH', {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'Replace', path: 'active', value: 'True' }],
    })
    expect(res.status).toBe(403)
    expect(res.body).toMatchObject({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      status: '403',
    })
    expect(await statusOf('scim')).toBe(-1)
    await notFull(viaScim)
  })

  it('lets a member with Manage access restore, and an owner restore anyone', async () => {
    // The decider holds Manage access to the covered collection, so a restore adds nothing.
    const byDecider = await decider.call(
      `/api/organizations/${orgId}/users/${rid.direct}/restore`,
      'PUT',
    )
    expect(byDecider.status).toBe(200)
    const res = await owner.call(`/api/organizations/${orgId}/users/${rid.control}/restore`, 'PUT')
    expect(res.status).toBe(200)
    expect(await statusOf('control')).toBeGreaterThan(-1)
    // The owner may restore through the bulk route too.
    const bulkOwner = await owner.call(`/api/organizations/${orgId}/users/restore`, 'PUT', {
      ids: [rid.group, rid.bulk],
    })
    expect(bulkOwner.status).toBe(200)
    expect(await statusOf('bulk')).toBeGreaterThan(-1)
  })
})
