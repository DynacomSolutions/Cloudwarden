// Lease enforcement and the review fixes of the access rules and leases
// (docs/privileged-access.md): a member without a live lease receives the reduced row of an item
// that an access rule covers, a revoke or expiry takes the item back at once, and the state
// machine keeps its limits (extension cap, approval window, rule choice, id chunking).
import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it, vi } from 'vitest'

// Org flows are slow on the shared CI host (see vitest.config.ts); give each test room.
vi.setConfig({ testTimeout: 600_000 })

import { createDb } from '../src/db'
import { requestViews } from '../src/pam/leases'
import { type Actor, actor, addMember, createOrg, loginCipher } from './org-helpers'
import { sql } from './pam-helpers'

let owner: Actor
let requester: Actor
let requester2: Actor
let approver: Actor
let orgId: string
let memberIds: Record<string, string>
let autoCol: string
let humanCol: string
let multiCol: string

const rules = (path = '', method = 'GET', body?: unknown) =>
  owner.call(`/api/organizations/${orgId}/access-rules${path}`, method, body)

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

const collection = async (name: string, grants: Record<string, boolean>) =>
  (
    await owner.json(`/api/organizations/${orgId}/collections`, 'POST', {
      name,
      users: Object.entries(grants).map(([id, manage]) => ({
        id,
        readOnly: false,
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
const decide = (who: Actor, id: string, verdict: number) =>
  who.call(`/api/access-requests/${id}/decision`, 'POST', { verdict })

/** The item as /api/sync returns it to one member, or undefined when it is missing. */
const synced = async (who: Actor, cipherId: string) =>
  ((await who.json('/api/sync')).ciphers as any[]).find((c) => c.id === cipherId)

beforeAll(async () => {
  owner = await actor('enf-owner@example.com')
  requester = await actor('enf-requester@example.com')
  requester2 = await actor('enf-requester2@example.com')
  approver = await actor('enf-approver@example.com')
  orgId = (await createOrg(owner, 'Enforcement Org')).id
  memberIds = {}
  for (const [key, who] of [
    ['requester', requester],
    ['requester2', requester2],
    ['approver', approver],
  ] as const) {
    memberIds[key] = await addMember(owner, orgId, who, { type: 2 })
  }
  await owner.call(`/api/organizations/${orgId}/users/enable-pam`, 'PUT', {
    ids: Object.values(memberIds),
  })
  const grants = { [memberIds.requester as string]: false, [memberIds.requester2 as string]: false }
  const withApprover = { ...grants, [memberIds.approver as string]: true }
  autoCol = await collection('2.auto', withApprover)
  humanCol = await collection('2.human', withApprover)
  multiCol = await collection('2.multi', grants)
  const ok = async (body: Record<string, unknown>) => {
    const res = await rules('', 'POST', ruleBody(body))
    expect(res.status).toBe(200)
    return (await res.json<any>()).id as string
  }
  await ok({
    name: 'Auto single',
    conditions: { approvalMode: 'Automatic' },
    singleActiveLease: true,
    collections: [autoCol],
  })
  await ok({ name: 'Human', collections: [humanCol] })
  await ok({
    name: 'Auto multi',
    conditions: { approvalMode: 'Automatic' },
    collections: [multiCol],
  })
}, 600_000)

describe('lease enforcement', () => {
  it('shows a reduced row without a lease, the full item with one, and the reduced row again after a revoke', async () => {
    const id = await cipherIn([autoCol])

    // No lease: the official clients expect `partialData` (name, URIs) and no secrets.
    const before = await synced(requester, id)
    expect(before).toBeDefined()
    expect(before.partialData).toEqual(expect.any(String))
    expect(JSON.parse(before.partialData)).toMatchObject({ name: '2.prod' })
    expect(JSON.stringify(before)).not.toContain('2.p"')
    expect(before).toMatchObject({
      login: null,
      notes: null,
      attachments: null,
      edit: false,
      viewPassword: false,
      key: '2.ckey',
      permissions: { delete: false, restore: false },
    })
    const detail = await (await requester.call(`/api/ciphers/${id}`)).json<any>()
    expect(detail.partialData).toEqual(expect.any(String))
    expect(detail.login).toBeNull()

    // Owners, admins and deciders keep the full item.
    for (const who of [owner, approver]) {
      const full = await synced(who, id)
      expect(full.partialData).toBeUndefined()
      expect(full.login.password).toBe('2.p')
    }

    // A restricted item cannot be edited or given attachments.
    const edit = await requester.call(`/api/ciphers/${id}`, 'PUT', {
      ...loginCipher('2.hacked', { organizationId: orgId }),
    })
    expect(edit.status).toBe(403)
    const attach = await requester.call(`/api/ciphers/${id}/attachment/v2`, 'POST', {
      fileName: '2.f',
      key: '2.k',
      fileSize: 5,
    })
    expect(attach.status).toBe(403)

    // An active lease gives the full item at the next sync.
    const made = await (await request(requester, id)).json<any>()
    const leaseId = made.request.producedLeaseId as string
    expect(leaseId).toBeTruthy()
    const during = await synced(requester, id)
    expect(during.partialData).toBeUndefined()
    expect(during.login.password).toBe('2.p')
    expect((await (await requester.call(`/api/ciphers/${id}`)).json<any>()).login.password).toBe(
      '2.p',
    )

    // A revoke takes it away at once, and the next sync no longer carries the secrets.
    expect((await approver.call(`/api/leases/${leaseId}/revoke`, 'POST', {})).status).toBe(200)
    const after = await synced(requester, id)
    expect(after.partialData).toEqual(expect.any(String))
    expect(after.login).toBeNull()
    expect(
      (
        await requester.call(`/api/ciphers/${id}/attachment/v2`, 'POST', {
          fileName: '2.f',
          key: '2.k',
          fileSize: 5,
        })
      ).status,
    ).toBe(403)
  })

  it('ends access when the lease passes its end time, before any sweep runs', async () => {
    const id = await cipherIn([autoCol])
    const made = await (await request(requester, id)).json<any>()
    expect((await synced(requester, id)).login.password).toBe('2.p')
    await sql(
      'update pam_leases set not_after = ? where uuid = ?',
      Date.now() - 1000,
      made.request.producedLeaseId,
    )
    const after = await synced(requester, id)
    expect(after.partialData).toEqual(expect.any(String))
    expect(after.login).toBeNull()
  })

  it('counts a windowed lease only between its start and end', async () => {
    const id = await cipherIn([autoCol])
    const start = Date.now() + 2 * 3600_000
    const made = await (
      await request(requester, id, {
        start: new Date(start).toISOString(),
        end: new Date(start + 3600_000).toISOString(),
      })
    ).json<any>()
    expect(made.request.producedLeaseId).toBeTruthy()
    // Not started yet: still the reduced row.
    expect((await synced(requester, id)).partialData).toEqual(expect.any(String))
    // Under a single-lease rule, another member can lease the item before that window starts.
    const other = await request(requester2, id, { durationSeconds: 1800 })
    expect(other.status).toBe(200)
    expect((await synced(requester2, id)).login.password).toBe('2.p')
    // A request that would overlap the window of the first lease is refused.
    await sql(
      'update pam_leases set status = 2 where requester_uuid = ? and cipher_uuid = ?',
      requester2.uuid,
      id,
    )
    const overlap = await request(requester2, id, {
      start: new Date(start + 600_000).toISOString(),
      end: new Date(start + 1200_000).toISOString(),
    })
    expect(overlap.status).toBe(409)
  })

  it('leaves items outside any rule untouched', async () => {
    const open = await collection('2.open', {
      [memberIds.requester as string]: false,
    })
    const id = await cipherIn([open])
    const row = await synced(requester, id)
    expect(row.partialData).toBeUndefined()
    expect(row.login.password).toBe('2.p')
  })
})

describe('lease limits', () => {
  it('caps the total lease length across extensions', async () => {
    const id = await cipherIn([autoCol])
    await request(requester, id) // 3600 s; the rule allows at most 7200 s
    const leaseId = (await (await requester.json(`/api/leases/mine`)).data[0].id) as string
    const extend = () =>
      requester.call(`/api/leases/${leaseId}/extend`, 'POST', {
        durationSeconds: 1800,
        reason: 'more time',
      })
    expect((await extend()).status).toBe(200) // 5400
    expect((await extend()).status).toBe(200) // 7200
    expect((await extend()).status).toBe(400) // would be 9000
    const [row] = (
      await sql('select not_before, not_after from pam_leases where uuid = ?', leaseId)
    ).results
    expect(row.not_after - row.not_before).toBeLessThanOrEqual(7200 * 1000)
  })

  it('keeps an approval valid until a window that starts in days begins', async () => {
    const id = await cipherIn([humanCol])
    const start = Date.now() + 3 * 24 * 3600_000
    const created = await (
      await request(requester, id, {
        start: new Date(start).toISOString(),
        end: new Date(start + 2 * 3600_000).toISOString(),
      })
    ).json<any>()
    const approved = await (await decide(approver, created.request.id, 1)).json<any>()
    expect(approved.status).toBe(1)
    const [row] = (
      await sql('select expires_at from pam_access_requests where uuid = ?', created.request.id)
    ).results
    // A day from the window start, not a day from now: the approval is still valid at the start.
    expect(row.expires_at).toBeGreaterThan(start)
    expect(row.expires_at).toBeLessThanOrEqual(start + 2 * 3600_000)
    await requester.call(`/api/access-requests/${created.request.id}/revoke`, 'POST', {})
  })

  it('writes no approval for an extension whose lease ended', async () => {
    const id = await cipherIn([humanCol])
    const created = await (await request(requester, id)).json<any>()
    await decide(approver, created.request.id, 1)
    const lease = await (
      await requester.call(`/api/access-requests/${created.request.id}/activate`, 'POST')
    ).json<any>()
    const ext = await (
      await requester.call(`/api/leases/${lease.id}/extend`, 'POST', {
        durationSeconds: 600,
        reason: 'late',
      })
    ).json<any>()
    expect(ext.status).toBe(0)
    await sql('update pam_leases set not_after = ? where uuid = ?', Date.now() - 1000, lease.id)
    const res = await decide(approver, ext.id, 1)
    expect(res.status).toBe(409)
    const decisions = await sql(
      'select count(*) n from pam_access_decisions where request_uuid = ?',
      ext.id,
    )
    expect(decisions.results[0].n).toBe(0)
    const audit = await sql(
      "select count(*) n from pam_audit where kind = 'access_approved' and ref_uuid = ?",
      ext.id,
    )
    expect(audit.results[0].n).toBe(0)
    const [req] = (await sql('select status from pam_access_requests where uuid = ?', ext.id))
      .results
    expect(req.status).toBe(3)
  })

  it('chooses the same rule every time: human approval first', async () => {
    const colA = await collection('2.pick-auto', { [memberIds.requester as string]: false })
    const colB = await collection('2.pick-human', { [memberIds.requester as string]: false })
    // The automatic rule is created first, so an unordered read finds it first.
    const a = await rules(
      '',
      'POST',
      ruleBody({
        name: 'Pick auto',
        conditions: { approvalMode: 'Automatic' },
        collections: [colA],
      }),
    )
    const b = await rules('', 'POST', ruleBody({ name: 'Pick human', collections: [colB] }))
    expect(a.status).toBe(200)
    expect(b.status).toBe(200)
    const id = await cipherIn([colA, colB])
    for (let i = 0; i < 3; i++) {
      const pre = await (await requester.call(`/api/leases/ciphers/${id}/pre-check`)).json<any>()
      expect(pre.approvalMode).toBe(1)
    }
  })

  it('never gives one member two live leases on an item, even for racing requests', async () => {
    const id = await cipherIn([multiCol])
    const results = await Promise.all([request(requester, id), request(requester, id)])
    expect(results.some((r) => r.status === 200)).toBe(true)
    const live = await sql(
      'select count(*) n from pam_leases where cipher_uuid = ? and requester_uuid = ? and status = 0 and not_after > ?',
      id,
      requester.uuid,
      Date.now(),
    )
    expect(live.results[0].n).toBe(1)
  })
})

describe('statements stay below the bound-parameter limit', () => {
  let bulk: string[] = []

  beforeAll(async () => {
    await sql(
      `with recursive n(i) as (select 1 union all select i + 1 from n where i < 120)
       insert into collections (uuid, organization_uuid, name, created_at, updated_at)
       select printf('00000000-0000-4000-8000-%012d', i), ?, '2.bulk-' || i, 1, 1 from n`,
      orgId,
    )
    bulk = (
      await sql("select uuid from collections where name like '2.bulk-%' order by name")
    ).results.map((r: any) => r.uuid)
    expect(bulk).toHaveLength(120)
  })

  it('creates, lists, reads and updates a rule over 120 collections', async () => {
    const created = await rules('', 'POST', ruleBody({ name: 'Wide', collections: bulk }))
    expect(created.status).toBe(200)
    const rule = await created.json<any>()
    expect(rule.collections).toHaveLength(120)
    const listed = await (await rules()).json<any>()
    expect(listed.data.find((r: any) => r.id === rule.id).collections).toHaveLength(120)
    expect(((await (await rules(`/${rule.id}`)).json<any>()).collections as string[]).length).toBe(
      120,
    )
    const put = await rules(
      `/${rule.id}`,
      'PUT',
      ruleBody({ name: 'Wide', collections: bulk.slice(0, 100) }),
    )
    expect(put.status).toBe(200)
    expect((await put.json<any>()).collections).toHaveLength(100)
    // Another rule cannot take one of them.
    const clash = await rules('', 'POST', ruleBody({ name: 'Clash', collections: [bulk[0]] }))
    expect(clash.status).toBe(409)
    await rules(`/${rule.id}`, 'DELETE')
  })

  it('loads the views of 150 requests', async () => {
    const now = Date.now()
    const rows = Array.from({ length: 150 }, (_, i) => ({
      uuid: crypto.randomUUID(),
      organizationUuid: orgId,
      cipherUuid: crypto.randomUUID(),
      collectionUuid: crypto.randomUUID(),
      ruleUuid: crypto.randomUUID(),
      requesterUuid: i % 2 ? requester.uuid : requester2.uuid,
      status: 0,
      reason: null,
      windowStart: null,
      windowEnd: null,
      durationSeconds: 60,
      submittedAt: now,
      expiresAt: now + 1000,
      resolvedAt: null,
      extensionOfLeaseUuid: null,
      createdAt: now,
      updatedAt: now,
    }))
    const views = await requestViews(createDb(env.DB), rows, now)
    expect(views).toHaveLength(150)
    expect(views[0]?.requesterEmail).toBe('enf-requester2@example.com')
  })

  it('lists the inbox and active leases of an approver who manages 100 collections', async () => {
    const [m] = (
      await sql(
        'select uuid from users_organizations where user_uuid = ? and organization_uuid = ?',
        approver.uuid,
        orgId,
      )
    ).results
    await sql(
      `with recursive n(i) as (select 1 union all select i + 1 from n where i < 100)
       insert into users_collections (organization_user_uuid, collection_uuid, read_only, hide_passwords, manage)
       select ?, printf('00000000-0000-4000-8000-%012d', i), 0, 0, 1 from n`,
      m.uuid,
    )
    const inbox = await approver.call('/api/access-requests/inbox')
    expect(inbox.status).toBe(200)
    expect((await approver.call('/api/access-requests/history')).status).toBe(200)
    expect((await approver.call('/api/leases/active')).status).toBe(200)
    expect((await approver.call('/api/leases/history')).status).toBe(200)
    // The approver still sees the request of a collection they manage through a grant.
    const id = await cipherIn([humanCol])
    const created = await (await request(requester, id)).json<any>()
    const items = (await (await approver.call('/api/access-requests/inbox')).json<any>()).data
    expect(items.map((r: any) => r.id)).toContain(created.request.id)
  })
})
