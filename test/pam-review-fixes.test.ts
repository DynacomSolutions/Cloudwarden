// Review fixes of the privileged access feature (docs/privileged-access.md), second round:
// custom managers do not lift a restriction, one rule set for requests and restrictions,
// access-end rotations wait for an open job, expired claims are released, extensions respect a
// single-lease rule, and a started window tells the member to sync.
import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it, vi } from 'vitest'

// Org flows are slow on the shared CI host (see vitest.config.ts); give each test room.
vi.setConfig({ testTimeout: 600_000 })

import { sweepAccess } from '../src/pam/leases'
import { sweepRotation } from '../src/pam/rotation'
import { BASE } from './helpers'
import { type Actor, actor, addMember, createOrg, loginCipher } from './org-helpers'
import { connectorFor, sql } from './pam-helpers'

let owner: Actor
let requester: Actor
let requester2: Actor
let approver: Actor
let manager: Actor
let orgId: string
let ids: Record<string, string>
let covered: string
let reachable: string
let autoCol: string
let singleCol: string

const rules = (path = '', method = 'GET', body?: unknown) =>
  owner.call(`/api/organizations/${orgId}/access-rules${path}`, method, body)
const admin = (path: string, method = 'GET', body?: unknown) =>
  owner.call(`/api/organizations/${orgId}/access-connectors${path}`, method, body)

const ruleBody = (extra: Record<string, unknown> = {}) => ({
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

const request = (who: Actor, cipherId: string, body: Record<string, unknown> = {}) =>
  who.call(`/api/leases/ciphers/${cipherId}`, 'POST', body)

async function addRule(extra: Record<string, unknown>) {
  const res = await rules('', 'POST', ruleBody(extra))
  expect(res.status).toBe(200)
  return (await res.json<any>()).id as string
}

async function sealedTarget(name: string) {
  const t = await (await admin('/rotation/target-systems', 'POST', { name, method: 0 })).json<any>()
  const put = await admin(`/rotation/target-systems/${t.id}`, 'PUT', {
    name,
    sealedData: '2.sealed',
    wrappedKey: '2.wrapped',
  })
  expect(put.status).toBe(200)
  return t.id as string
}

beforeAll(async () => {
  owner = await actor('fix2-owner@example.com')
  requester = await actor('fix2-requester@example.com')
  requester2 = await actor('fix2-requester2@example.com')
  approver = await actor('fix2-approver@example.com')
  manager = await actor('fix2-manager@example.com')
  orgId = (await createOrg(owner, 'Fix Two Org')).id
  ids = {}
  for (const [key, who] of [
    ['requester', requester],
    ['requester2', requester2],
    ['approver', approver],
  ] as const) {
    ids[key] = await addMember(owner, orgId, who, { type: 2 })
  }
  // A custom member who may manage every item and every collection (no grants of their own).
  ids.manager = await addMember(owner, orgId, manager, {
    type: 4,
    permissions: { manageCiphers: true, editAnyCollection: true },
  })
  await owner.call(`/api/organizations/${orgId}/users/enable-pam`, 'PUT', {
    ids: [ids.requester, ids.requester2, ids.approver],
  })
  // `covered` is under a human rule that the requester cannot even see; `reachable` is plain.
  covered = await collection('2.covered', [[ids.approver as string, true]])
  reachable = await collection('2.reachable', [[ids.requester as string, false, true]])
  autoCol = await collection('2.auto', [
    [ids.requester as string, false],
    [ids.requester2 as string, false],
  ])
  singleCol = await collection('2.single', [
    [ids.requester as string, false],
    [ids.requester2 as string, false],
  ])
  await addRule({ name: 'Human', collections: [covered] })
  await addRule({
    name: 'Auto',
    conditions: { approvalMode: 'Automatic' },
    collections: [autoCol],
  })
  await addRule({
    name: 'Single',
    conditions: { approvalMode: 'Automatic' },
    singleActiveLease: true,
    collections: [singleCol],
  })
}, 600_000)

describe('custom managers do not lift a restriction', () => {
  it('refuses to move a restricted item out of its covered collection', async () => {
    const id = await cipherIn([covered])
    // The manager reaches the item only as the reduced row.
    const shown = await (
      await manager.call(`/api/ciphers/organization-details?organizationId=${orgId}`)
    ).json<any>()
    const row = shown.data.find((c: any) => c.id === id)
    expect(row.partialData).toEqual(expect.any(String))
    expect(row.login).toBeNull()

    const admin403 = await manager.call(`/api/ciphers/${id}/collections-admin`, 'PUT', {
      collectionIds: [reachable],
    })
    expect(admin403.status).toBe(403)
    const bulk = await manager.call('/api/ciphers/bulk-collections', 'POST', {
      organizationId: orgId,
      cipherIds: [id],
      collectionIds: [covered],
      removeCollections: true,
    })
    expect(bulk.status).toBe(403)
    const links = (
      await sql('select collection_uuid from ciphers_collections where cipher_uuid = ?', id)
    ).results
    expect(links).toEqual([{ collection_uuid: covered }])
    // Nor can the manager delete it.
    expect(
      (await manager.call('/api/ciphers/delete-admin', 'PUT', { ids: [id], organizationId: orgId }))
        .status,
    ).toBe(403)
  })

  it('refuses to grant the manager Manage access to a covered collection, or to delete it', async () => {
    const grant = await manager.call(
      `/api/organizations/${orgId}/collections/${covered}/users`,
      'PUT',
      [{ id: ids.manager, readOnly: false, hidePasswords: false, manage: true }],
    )
    expect(grant.status).toBe(403)
    const bulk = await manager.call(`/api/organizations/${orgId}/collections/bulk-access`, 'POST', {
      collectionIds: [covered],
      users: [{ id: ids.manager, readOnly: false, hidePasswords: false, manage: true }],
    })
    expect(bulk.status).toBe(403)
    expect(
      (await manager.call(`/api/organizations/${orgId}/collections/${covered}`, 'DELETE')).status,
    ).toBe(403)
    expect(
      (
        await sql(
          'select count(*) as n from users_collections where collection_uuid = ? and organization_user_uuid = ?',
          covered,
          ids.manager,
        )
      ).results[0].n,
    ).toBe(0)
    // A collection without a rule stays open to the manager.
    const open = await manager.call(
      `/api/organizations/${orgId}/collections/${reachable}/users`,
      'PUT',
      [{ id: ids.requester, readOnly: true, hidePasswords: false, manage: false }],
    )
    expect(open.status).toBe(200)
  })
})

describe('one set of collections for rules and restrictions', () => {
  it('lets a member request an item whose rule sits on a collection they cannot reach', async () => {
    // The item is in `covered` (rule, no access for the requester) and `reachable` (View only).
    const id = await cipherIn([covered, reachable])
    const synced = ((await requester.json('/api/sync')).ciphers as any[]).find((c) => c.id === id)
    expect(synced.partialData).toEqual(expect.any(String))
    const res = await request(requester, id, { reason: 'fix the db' })
    expect(res.status).toBe(200)
    const made = await res.json<any>()
    expect(made.request).toMatchObject({ cipherId: id, collectionId: covered, status: 0 })
    // The decider of the covered collection sees it.
    const inbox = (await (await approver.call('/api/access-requests/inbox')).json<any>()).data
    expect(inbox.some((r: any) => r.id === made.request.id)).toBe(true)
  })
})

describe('access-end rotation waits for an open job', () => {
  async function leasedWithConfig(name: string) {
    const target = await sealedTarget(name)
    const cipherId = await cipherIn([autoCol], `2.${name}`)
    const cfg = await (
      await admin('/rotation/configs', 'POST', {
        cipherId,
        targetSystemId: target,
        sealedData: '2.a',
        wrappedKey: '2.b',
        rotateOnAccessEnd: true,
      })
    ).json<any>()
    return { target, cipherId, cfg }
  }
  const jobsOf = async (cfgId: string) =>
    (
      await sql(
        'select source, status from pam_rotation_jobs where config_uuid = ? order by created_at, source',
        cfgId,
      )
    ).results

  it('queues the rotation when the open job ends (sweep)', async () => {
    const { cipherId, cfg } = await leasedWithConfig('after-sweep')
    expect((await admin(`/rotation/configs/${cfg.id}/rotate`, 'POST')).status).toBe(200)
    const made = await (await request(requester, cipherId)).json<any>()
    const leaseId = made.request.producedLeaseId as string
    expect(leaseId).toBeTruthy()
    expect((await requester.call(`/api/leases/${leaseId}/revoke`, 'POST', {})).status).toBe(200)
    // The on-demand job is still open: no second job, but the request is kept.
    expect(await jobsOf(cfg.id)).toEqual([{ source: 1, status: 0 }])
    await sweepRotation(env)
    expect(await jobsOf(cfg.id)).toEqual([{ source: 1, status: 0 }])
    // The open job ends: the next sweep queues the access-end rotation, once.
    await sql('update pam_rotation_jobs set status = 3 where config_uuid = ?', cfg.id)
    await sweepRotation(env)
    await sweepRotation(env)
    expect(await jobsOf(cfg.id)).toEqual([
      { source: 1, status: 3 },
      { source: 2, status: 0 },
    ])
  })

  it('queues the rotation at once when the connector reports the open job as failed', async () => {
    const dev = await connectorFor(owner, orgId, 'after-failure')
    const { target, cipherId, cfg } = await leasedWithConfig('after-failure')
    await admin(`/${dev.reg.id}/assignments`, 'POST', { targetSystemId: target })
    await admin(`/rotation/configs/${cfg.id}/rotate`, 'POST')
    const made = await (await request(requester, cipherId)).json<any>()
    await requester.call(`/api/leases/${made.request.producedLeaseId}/revoke`, 'POST', {})
    expect(await jobsOf(cfg.id)).toEqual([{ source: 1, status: 0 }])
    const jobs = await (await dev.call('/jobs')).json<any>()
    const claim = await (await dev.call(`/jobs/${jobs.data[0].jobId}/claim`, 'POST')).json<any>()
    const fail = await dev.call(`/attempts/${claim.attemptId}/failure`, 'POST', {
      syncState: 0,
      errorCode: 'unreachable',
    })
    expect(fail.status).toBe(200)
    expect(await jobsOf(cfg.id)).toEqual([
      { source: 1, status: 3 },
      { source: 2, status: 0 },
    ])
  })
})

describe('expired claims', () => {
  async function claimed(name: string) {
    const dev = await connectorFor(owner, orgId, name)
    const target = await sealedTarget(`claim-${name}`)
    await admin(`/${dev.reg.id}/assignments`, 'POST', { targetSystemId: target })
    const cipherId = await cipherIn([], `2.${name}`)
    const cfg = await (
      await admin('/rotation/configs', 'POST', {
        cipherId,
        targetSystemId: target,
        sealedData: '2.a',
        wrappedKey: '2.b',
      })
    ).json<any>()
    await admin(`/rotation/configs/${cfg.id}/rotate`, 'POST')
    const jobs = await (await dev.call('/jobs')).json<any>()
    const jobId = jobs.data[0].jobId as string
    const claim = await (await dev.call(`/jobs/${jobId}/claim`, 'POST')).json<any>()
    return { dev, jobId, claim }
  }

  it('releases a claim after its lease even when the connector keeps polling', async () => {
    const { dev, jobId, claim } = await claimed('still-polling')
    await sql(
      'update pam_rotation_jobs set claimed_at = ? where uuid = ?',
      Date.now() - 10 * 60_000,
      jobId,
    )
    // The connector is online: it polls the queue right now.
    expect((await dev.call('/jobs')).status).toBe(200)
    await sweepRotation(env)
    const [job] = (
      await sql(
        'select status, claimed_by_connector_uuid as c from pam_rotation_jobs where uuid = ?',
        jobId,
      )
    ).results
    expect(job).toMatchObject({ status: 0, c: null })
    // The job is offered again, and the old attempt is abandoned.
    expect((await (await dev.call('/jobs')).json<any>()).data.map((j: any) => j.jobId)).toContain(
      jobId,
    )
    expect(
      (await sql('select status from pam_rotation_attempts where uuid = ?', claim.attemptId))
        .results[0].status,
    ).toBe(3)
  })

  it('accepts a failure report of the claimant after the lease ended', async () => {
    const { dev, jobId, claim } = await claimed('late-failure')
    await sql(
      'update pam_rotation_jobs set claimed_at = ? where uuid = ?',
      Date.now() - 10 * 60_000,
      jobId,
    )
    const late = await dev.call(`/attempts/${claim.attemptId}/failure`, 'POST', {
      syncState: 2,
      errorCode: 'late',
    })
    expect(late.status).toBe(200)
    expect(
      (await sql('select status from pam_rotation_jobs where uuid = ?', jobId)).results[0].status,
    ).toBe(3)
    expect(
      (
        await sql(
          'select status, sync_state from pam_rotation_attempts where uuid = ?',
          claim.attemptId,
        )
      ).results[0],
    ).toMatchObject({ status: 2, sync_state: 2 })
    // A success after the lease is still refused.
    const second = await claimed('late-success')
    await sql(
      'update pam_rotation_jobs set claimed_at = ? where uuid = ?',
      Date.now() - 10 * 60_000,
      second.jobId,
    )
    expect(
      (
        await second.dev.call(`/attempts/${second.claim.attemptId}/success`, 'POST', {
          sessionTermination: 0,
        })
      ).status,
    ).toBe(409)
  })
})

describe('extensions under a single-lease rule', () => {
  it('refuses an extension that would cover a lease scheduled right after', async () => {
    const id = await cipherIn([singleCol], '2.single-ext')
    const first = await (await request(requester, id)).json<any>()
    const lease = await (await requester.call('/api/leases/mine')).json<any>()
    const mine = lease.data.find((l: any) => l.id === first.request.producedLeaseId)
    expect(mine).toBeTruthy()
    const end = Date.parse(mine.notAfter)
    // Another member schedules a lease that starts a minute after the first one ends.
    const start = end + 60_000
    const second = await request(requester2, id, {
      start: new Date(start).toISOString(),
      end: new Date(start + 3600_000).toISOString(),
    })
    expect(second.status).toBe(200)
    // Extending by 30 minutes would overlap it: refused, and the lease keeps its end.
    const ext = await requester.call(`/api/leases/${mine.id}/extend`, 'POST', {
      durationSeconds: 1800,
      reason: 'more time',
    })
    expect(ext.status).toBe(409)
    expect(
      (await sql('select not_after from pam_leases where uuid = ?', mine.id)).results[0].not_after,
    ).toBe(end)
  })
})

describe('a started window syncs the member', () => {
  it('bumps the revision date of a member whose windowed lease started', async () => {
    const id = await cipherIn([autoCol], '2.window')
    const start = Date.now() + 2 * 3600_000
    const made = await (
      await request(requester2, id, {
        start: new Date(start).toISOString(),
        end: new Date(start + 3600_000).toISOString(),
      })
    ).json<any>()
    const leaseId = made.request.producedLeaseId as string
    expect(leaseId).toBeTruthy()
    // Move the window so that it started a minute ago, as if the clock had passed its start.
    await sql(
      'update pam_leases set not_before = ?, not_after = ?, created_at = ? where uuid = ?',
      Date.now() - 60_000,
      Date.now() + 3600_000,
      Date.now() - 3600_000,
      leaseId,
    )
    await sql('update users set updated_at = 1 where uuid = ?', requester2.uuid)
    await sweepAccess(env)
    const [row] = (await sql('select updated_at from users where uuid = ?', requester2.uuid))
      .results
    expect(row.updated_at).toBeGreaterThan(1)
    // A lease that was never scheduled does not trigger it.
    await sql('update users set updated_at = 1 where uuid = ?', requester2.uuid)
    await sql('update pam_leases set created_at = not_before where uuid = ?', leaseId)
    await sweepAccess(env)
    expect(
      (await sql('select updated_at from users where uuid = ?', requester2.uuid)).results[0]
        .updated_at,
    ).toBe(1)
  })
})

describe('admin bulk routes load the access of a custom manager once', () => {
  it('restores 25 items with a constant number of access queries', async () => {
    const made = await Promise.all(
      Array.from({ length: 25 }, (_, i) => cipherIn([reachable], `2.bulk${i}`)),
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
      new Request(`${BASE}/api/ciphers/restore-admin`, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${manager.token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids: made, organizationId: orgId }),
      }),
      { ...env, DB: counting },
    )
    expect(res.status).toBe(200)
    expect((((await res.json()) as any).data as any[]).length).toBe(25)
    // One load for the permission check, one for the response; never one per item.
    expect(gated).toBeLessThanOrEqual(3)
  })
})
