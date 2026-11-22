// Review fixes of the privileged access feature (docs/privileged-access.md), third round: group
// grants do not lift a restriction, bulk collection access loads the caller once, a restricted
// item does not leak its existence, a rotation request survives an unusable target, the window
// start push happens once, and a human extension decision respects a single-lease rule.
import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it, vi } from 'vitest'

// Org flows are slow on the shared CI host (see vitest.config.ts); give each test room.
vi.setConfig({ testTimeout: 600_000 })

import { createDb } from '../src/db'
import { sweepAccess } from '../src/pam/leases'
import { flushRotateAfterJob } from '../src/pam/rotation'
import { BASE } from './helpers'
import { type Actor, actor, addMember, createOrg, loginCipher } from './org-helpers'
import { sql } from './pam-helpers'

let owner: Actor
let requester: Actor
let requester2: Actor
let approver: Actor
let grouper: Actor
let editor: Actor
let orgId: string
let ids: Record<string, string>
let covered: string
let reachable: string
let humanSingle: string

const grant = (id: string, manage: boolean) => ({
  id,
  readOnly: false,
  hidePasswords: false,
  manage,
})

const collection = async (name: string, grants: [string, boolean, boolean?][]) =>
  (
    await owner.json(`/api/organizations/${orgId}/collections`, 'POST', {
      name,
      users: grants.map(([id, manage, readOnly]) => ({
        id,
        readOnly: readOnly ?? false,
        hidePasswords: false,
        manage,
      })),
      groups: [],
    })
  ).id as string

async function cipherIn(collectionIds: string[], name = '2.prod') {
  const c = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher(name, { organizationId: orgId }),
    collectionIds,
  })
  return c.id as string
}

async function addRule(extra: Record<string, unknown>) {
  const res = await owner.call(`/api/organizations/${orgId}/access-rules`, 'POST', {
    name: 'Rule',
    enabled: true,
    conditions: { approvalMode: 'Human' },
    singleActiveLease: false,
    defaultLeaseDurationSeconds: 3600,
    maxLeaseDurationSeconds: 7200,
    allowsExtensions: true,
    maxExtensionDurationSeconds: 1800,
    collections: [] as string[],
    ...extra,
  })
  expect(res.status).toBe(200)
  return (await res.json<any>()).id as string
}

const groupCount = async () =>
  (await sql('select count(*) as n from groups where organization_uuid = ?', orgId)).results[0].n

beforeAll(async () => {
  owner = await actor('fix3-owner@example.com')
  requester = await actor('fix3-requester@example.com')
  requester2 = await actor('fix3-requester2@example.com')
  approver = await actor('fix3-approver@example.com')
  grouper = await actor('fix3-grouper@example.com')
  editor = await actor('fix3-editor@example.com')
  orgId = (await createOrg(owner, 'Fix Three Org')).id
  ids = {}
  for (const [key, who] of [
    ['requester', requester],
    ['requester2', requester2],
    ['approver', approver],
  ] as const) {
    ids[key] = await addMember(owner, orgId, who, { type: 2 })
  }
  // Custom members: one who manages groups and every item, one who edits every collection.
  ids.grouper = await addMember(owner, orgId, grouper, {
    type: 4,
    permissions: { manageGroups: true, manageCiphers: true },
  })
  ids.editor = await addMember(owner, orgId, editor, {
    type: 4,
    permissions: { editAnyCollection: true },
  })
  await owner.call(`/api/organizations/${orgId}/users/enable-pam`, 'PUT', {
    ids: [ids.requester, ids.requester2, ids.approver],
  })
  covered = await collection('2.covered', [[ids.approver as string, true]])
  reachable = await collection('2.reachable', [
    [ids.requester as string, false],
    [ids.requester2 as string, false],
  ])
  humanSingle = await collection('2.human-single', [
    [ids.requester as string, false],
    [ids.requester2 as string, false],
  ])
  await addRule({ name: 'Human', collections: [covered] })
  await addRule({ name: 'HumanSingle', singleActiveLease: true, collections: [humanSingle] })
}, 600_000)

describe('group grants do not lift a restriction (round 3, A)', () => {
  it('refuses a group that gives its creator Manage access to a covered collection', async () => {
    const id = await cipherIn([covered], '2.grouped')
    const before = await groupCount()
    const made = await grouper.call(`/api/organizations/${orgId}/groups`, 'POST', {
      name: 'Self grant',
      users: [ids.grouper],
      collections: [grant(covered, true)],
    })
    expect(made.status).toBe(403)
    expect(await groupCount()).toBe(before)
    // The item still reaches the custom manager only as the reduced row.
    const shown = await (
      await grouper.call(`/api/ciphers/organization-details?organizationId=${orgId}`)
    ).json<any>()
    const row = shown.data.find((c: any) => c.id === id)
    expect(row.partialData).toEqual(expect.any(String))
    expect(row.login).toBeNull()
    // A read-only grant lifts nothing, so it stays allowed.
    const readOnly = await grouper.call(`/api/organizations/${orgId}/groups`, 'POST', {
      name: 'Reader',
      users: [ids.grouper],
      collections: [{ ...grant(covered, false), readOnly: true }],
    })
    expect(readOnly.status).toBe(200)
  })

  it('refuses to add Manage access to a covered collection to a group, or to join such a group', async () => {
    const made = await owner.json(`/api/organizations/${orgId}/groups`, 'POST', {
      name: 'Deciders',
      users: [ids.approver],
      collections: [grant(covered, true)],
    })
    const update = await grouper.call(
      `/api/organizations/${orgId}/groups/${made.id}/users`,
      'PUT',
      [ids.approver, ids.grouper],
    )
    expect(update.status).toBe(403)
    const body = (collections: unknown[]) => ({
      name: 'Deciders',
      users: [ids.approver, ids.grouper],
      collections,
    })
    expect(
      (
        await grouper.call(
          `/api/organizations/${orgId}/groups/${made.id}`,
          'PUT',
          body([grant(covered, true)]),
        )
      ).status,
    ).toBe(403)
    const other = await owner.json(`/api/organizations/${orgId}/groups`, 'POST', {
      name: 'Plain',
      users: [],
      collections: [],
    })
    expect(
      (
        await grouper.call(`/api/organizations/${orgId}/groups/${other.id}`, 'PUT', {
          name: 'Plain',
          users: [ids.grouper],
          collections: [grant(covered, true)],
        })
      ).status,
    ).toBe(403)
    expect(
      (
        await sql(
          'select count(*) as n from groups_users where group_uuid = ? and organization_user_uuid = ?',
          made.id,
          ids.grouper,
        )
      ).results[0].n,
    ).toBe(0)
    // A change that leaves the existing Manage grant as it is stays allowed (a rename).
    const rename = await grouper.call(`/api/organizations/${orgId}/groups/${made.id}`, 'PUT', {
      name: 'Deciders renamed',
      users: [ids.approver],
      collections: [grant(covered, true)],
    })
    expect(rename.status).toBe(200)
    // A group without such a grant takes members freely.
    expect(
      (
        await grouper.call(`/api/organizations/${orgId}/groups/${other.id}/users`, 'PUT', [
          ids.requester,
        ])
      ).status,
    ).toBe(200)
  })
})

describe('bulk collection access loads the caller once (round 3, C)', () => {
  it('grants 30 collections with a constant number of access queries', async () => {
    const made = await Promise.all(
      Array.from({ length: 30 }, (_, i) => collection(`2.bulk-access-${i}`, [])),
    )
    let gated = 0
    const counting = new Proxy(env.DB, {
      get(target, prop) {
        const v = Reflect.get(target, prop) as unknown
        if (prop === 'prepare') {
          return (q: string) => {
            if (q.includes('pam_rule_collections')) gated++
            return target.prepare(q)
          }
        }
        return typeof v === 'function' ? v.bind(target) : v
      },
    })
    const { default: app } = await import('../src/index')
    const res = await app.fetch(
      new Request(`${BASE}/api/organizations/${orgId}/collections/bulk-access`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${editor.token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          collectionIds: made,
          users: [{ ...grant(ids.requester as string, false), readOnly: true }],
        }),
      }),
      { ...env, DB: counting },
    )
    expect(res.status).toBe(200)
    // One load for the check; never one per collection.
    expect(gated).toBeLessThanOrEqual(2)
  })
})

describe('a restricted item does not leak its existence (round 3, D)', () => {
  it('answers 404 before 403 for a member who cannot reach the item', async () => {
    const id = await cipherIn([covered], '2.hidden')
    const res = await requester.call('/api/ciphers/bulk-collections', 'POST', {
      organizationId: orgId,
      cipherIds: [id],
      collectionIds: [reachable],
    })
    expect(res.status).toBe(404)
  })
})

describe('an unusable rotation target keeps the request (round 3, E)', () => {
  it('keeps rotate_after_job while the configuration is disabled', async () => {
    const cipher = await cipherIn([reachable], '2.rotating')
    const target = await (
      await owner.call(
        `/api/organizations/${orgId}/access-connectors/rotation/target-systems`,
        'POST',
        {
          name: 'Target',
          method: 0,
        },
      )
    ).json<any>()
    await owner.call(
      `/api/organizations/${orgId}/access-connectors/rotation/target-systems/${target.id}`,
      'PUT',
      { name: 'Target', sealedData: '2.sealed', wrappedKey: '2.wrapped' },
    )
    const cfg = await owner.call(
      `/api/organizations/${orgId}/access-connectors/rotation/configs`,
      'POST',
      {
        cipherId: cipher,
        targetSystemId: target.id,
        sealedData: '2.sealed',
        wrappedKey: '2.wrapped',
        rotateOnAccessEnd: true,
        enabled: true,
      },
    )
    expect(cfg.status).toBe(200)
    const configId = (
      await sql('select uuid from pam_rotation_configs where cipher_uuid = ?', cipher)
    ).results[0].uuid as string
    await sql(
      'update pam_rotation_configs set rotate_after_job = 1, enabled = 0 where uuid = ?',
      configId,
    )
    await flushRotateAfterJob(createDb(env.DB), Date.now(), configId)
    const [kept] = (
      await sql('select rotate_after_job as r from pam_rotation_configs where uuid = ?', configId)
    ).results
    expect(kept.r).toBe(1)
    // Once the configuration works again, the waiting request becomes a job.
    await sql('update pam_rotation_configs set enabled = 1 where uuid = ?', configId)
    await flushRotateAfterJob(createDb(env.DB), Date.now(), configId)
    expect(
      (await sql('select count(*) as n from pam_rotation_jobs where config_uuid = ?', configId))
        .results[0].n,
    ).toBe(1)
    expect(
      (await sql('select rotate_after_job as r from pam_rotation_configs where uuid = ?', configId))
        .results[0].r,
    ).toBe(0)
  })
})

describe('the window start push happens once (round 3, F)', () => {
  it('does not bump the member again on a later sweep', async () => {
    const autoCol = await collection('2.auto', [[ids.requester2 as string, false]])
    await addRule({
      name: 'Auto',
      conditions: { approvalMode: 'Automatic' },
      collections: [autoCol],
    })
    const id = await cipherIn([autoCol], '2.window')
    const start = Date.now() + 2 * 3600_000
    const made = await (
      await requester2.call(`/api/leases/ciphers/${id}`, 'POST', {
        start: new Date(start).toISOString(),
        end: new Date(start + 3600_000).toISOString(),
      })
    ).json<any>()
    const leaseId = made.request.producedLeaseId as string
    await sql(
      'update pam_leases set not_before = ?, not_after = ?, created_at = ? where uuid = ?',
      Date.now() - 60_000,
      Date.now() + 3600_000,
      Date.now() - 3600_000,
      leaseId,
    )
    await sql('update users set updated_at = 1 where uuid = ?', requester2.uuid)
    await sweepAccess(env)
    expect(
      (await sql('select updated_at from users where uuid = ?', requester2.uuid)).results[0]
        .updated_at,
    ).toBeGreaterThan(1)
    // The next minute's sweep sees the same lease inside the look-back time: no second push.
    await sql('update users set updated_at = 1 where uuid = ?', requester2.uuid)
    await sweepAccess(env)
    expect(
      (await sql('select updated_at from users where uuid = ?', requester2.uuid)).results[0]
        .updated_at,
    ).toBe(1)
  })
})

describe('a human extension decision respects a single-lease rule (round 3, G)', () => {
  it('refuses to approve an extension that would cover a lease scheduled right after', async () => {
    const id = await cipherIn([humanSingle], '2.human-ext')
    const asked = await (
      await requester.call(`/api/leases/ciphers/${id}`, 'POST', { durationSeconds: 3600 })
    ).json<any>()
    const requestId = asked.request.id as string
    const approved = await owner.call(`/api/access-requests/${requestId}/decision`, 'POST', {
      verdict: 1,
    })
    expect(approved.status).toBe(200)
    const active = await requester.call(`/api/access-requests/${requestId}/activate`, 'POST')
    expect(active.status).toBe(200)
    const mine = (await (await requester.call('/api/leases/mine')).json<any>()).data[0]
    const end = Date.parse(mine.notAfter)
    // Another member holds a lease that starts a minute after this one ends.
    const second = await (
      await requester2.call(`/api/leases/ciphers/${id}`, 'POST', {
        start: new Date(end + 60_000).toISOString(),
        end: new Date(end + 60_000 + 3600_000).toISOString(),
      })
    ).json<any>()
    await sql(
      'insert into pam_leases (uuid, request_uuid, organization_uuid, cipher_uuid, collection_uuid, requester_uuid, status, not_before, not_after, created_at) values (?, ?, ?, ?, ?, ?, 0, ?, ?, ?)',
      crypto.randomUUID(),
      second.request.id,
      orgId,
      id,
      humanSingle,
      requester2.uuid,
      end + 60_000,
      end + 60_000 + 3600_000,
      Date.now(),
    )
    const ext = await requester.call(`/api/leases/${mine.id}/extend`, 'POST', {
      durationSeconds: 1800,
      reason: 'more time',
    })
    expect(ext.status).toBe(200)
    const extId = (await ext.json<any>()).id as string
    const decided = await owner.call(`/api/access-requests/${extId}/decision`, 'POST', {
      verdict: 1,
    })
    expect(decided.status).toBe(409)
    expect(
      (await sql('select not_after from pam_leases where uuid = ?', mine.id)).results[0].not_after,
    ).toBe(end)
  })
})
