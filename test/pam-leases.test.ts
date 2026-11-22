// Access rules, access requests and leases (docs/privileged-access.md). Covers every route, the
// pending / approved / active / expired / revoked state machine and the activation races.
import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it, vi } from 'vitest'

// Org flows are slow on the shared CI host (see vitest.config.ts); give each test room.
vi.setConfig({ testTimeout: 600_000 })

import { sweepAccess } from '../src/pam/leases'
import { sweepRotation } from '../src/pam/rotation'
import { raw } from './org-api-helpers'
import { type Actor, actor, addMember, createOrg, loginCipher } from './org-helpers'
import { sql } from './pam-helpers'

let owner: Actor
let requester: Actor
let requester2: Actor
let approver: Actor
let plain: Actor
let outsider: Actor
let orgId: string
let humanCollection: string
let autoCollection: string
let humanRule: string
let autoRule: string

const rules = (path = '', method = 'GET', body?: unknown) =>
  owner.call(`/api/organizations/${orgId}/access-rules${path}`, method, body)

const ruleBody = (extra: Record<string, unknown> = {}) => ({
  name: 'Production databases',
  description: 'Break glass',
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

async function cipherIn(collectionId: string, name = '2.prod') {
  const c = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher(name, { organizationId: orgId }),
    collectionIds: [collectionId],
  })
  return c.id as string
}

const request = (who: Actor, cipherId: string, body: Record<string, unknown> = {}) =>
  who.call(`/api/leases/ciphers/${cipherId}`, 'POST', body)
const decide = (who: Actor, id: string, verdict: number, comment?: string) =>
  who.call(`/api/access-requests/${id}/decision`, 'POST', { verdict, comment })

beforeAll(async () => {
  owner = await actor('lease-owner@example.com')
  requester = await actor('lease-requester@example.com')
  requester2 = await actor('lease-requester2@example.com')
  approver = await actor('lease-approver@example.com')
  plain = await actor('lease-plain@example.com')
  outsider = await actor('lease-outsider@example.com')
  const org = await createOrg(owner, 'Lease Org')
  orgId = org.id
  const makeCollection = async (name: string, grants: Record<string, [string, boolean]>) =>
    (
      await owner.json(`/api/organizations/${orgId}/collections`, 'POST', {
        name,
        users: Object.values(grants).map(([id, manage]) => ({
          id,
          readOnly: false,
          hidePasswords: false,
          manage,
        })),
        groups: [],
      })
    ).id as string
  const ids: Record<string, string> = {}
  for (const [key, who] of [
    ['requester', requester],
    ['requester2', requester2],
    ['approver', approver],
    ['plain', plain],
  ] as const) {
    ids[key] = await addMember(owner, orgId, who, { type: 2 })
  }
  await owner.call(`/api/organizations/${orgId}/users/enable-pam`, 'PUT', {
    ids: [ids.requester, ids.requester2, ids.approver],
  })
  humanCollection = await makeCollection('2.human', {
    r: [ids.requester as string, false],
    r2: [ids.requester2 as string, false],
    a: [ids.approver as string, true],
  })
  autoCollection = await makeCollection('2.auto', {
    r: [ids.requester as string, false],
    r2: [ids.requester2 as string, false],
  })
  humanRule = (
    await (await rules('', 'POST', ruleBody({ collections: [humanCollection] }))).json<any>()
  ).id
  autoRule = (
    await (
      await rules(
        '',
        'POST',
        ruleBody({
          name: 'Auto',
          conditions: { approvalMode: 'Automatic' },
          collections: [autoCollection],
          singleActiveLease: true,
        }),
      )
    ).json<any>()
  ).id
}, 600_000)

describe('access rules', () => {
  it('creates, lists, reads, updates and deletes a rule', async () => {
    const col = (
      await owner.json(`/api/organizations/${orgId}/collections`, 'POST', {
        name: '2.tmp',
        users: [],
        groups: [],
      })
    ).id
    const created = await (
      await rules(
        '',
        'POST',
        ruleBody({ name: 'Temp', collections: [col], maxLeaseDurationSeconds: 3600 }),
      )
    ).json<any>()
    expect(created).toMatchObject({
      object: 'accessRule',
      name: 'Temp',
      enabled: true,
      conditions: { approvalMode: 'Human' },
      defaultLeaseDurationSeconds: 3600,
      maxLeaseDurationSeconds: 3600,
      allowsExtensions: true,
      maxExtensionDurationSeconds: 1800,
      collections: [col],
      organizationId: orgId,
    })
    const listed = await (await rules()).json<any>()
    expect(listed.data.map((r: any) => r.id)).toEqual(
      expect.arrayContaining([created.id, humanRule, autoRule]),
    )
    expect((await (await rules(`/${created.id}`)).json<any>()).id).toBe(created.id)

    const put = await rules(
      `/${created.id}`,
      'PUT',
      ruleBody({ name: 'Renamed', enabled: false, allowsExtensions: false, collections: [] }),
    )
    expect(put.status).toBe(200)
    expect(await put.json<any>()).toMatchObject({
      name: 'Renamed',
      enabled: false,
      collections: [],
      maxExtensionDurationSeconds: null,
    })
    expect((await rules(`/${created.id}`, 'DELETE')).status).toBe(200)
    expect((await rules(`/${created.id}`)).status).toBe(404)
    expect((await rules(`/${created.id}`, 'PUT', ruleBody())).status).toBe(404)
  })

  it('validates the terms and the collections', async () => {
    expect((await rules('', 'POST', ruleBody({ name: '' }))).status).toBe(400)
    expect(
      (
        await rules(
          '',
          'POST',
          ruleBody({ defaultLeaseDurationSeconds: 7200, maxLeaseDurationSeconds: 3600 }),
        )
      ).status,
    ).toBe(400)
    expect((await rules('', 'POST', ruleBody({ defaultLeaseDurationSeconds: 5 }))).status).toBe(400)
    expect((await rules('', 'POST', ruleBody({ conditions: [1] }))).status).toBe(400)
    expect((await rules('', 'POST', ruleBody({ collections: [crypto.randomUUID()] }))).status).toBe(
      400,
    )
    // A collection already covered by another rule.
    expect(
      (await rules('', 'POST', ruleBody({ name: 'Dup', collections: [humanCollection] }))).status,
    ).toBe(409)
  })

  it('limits rule administration to owners and admins', async () => {
    expect((await approver.call(`/api/organizations/${orgId}/access-rules`)).status).toBe(403)
    expect((await outsider.call(`/api/organizations/${orgId}/access-rules`)).status).toBe(404)
    expect((await raw(`/api/organizations/${orgId}/access-rules`)).status).toBe(401)
    expect(
      (await approver.call(`/api/organizations/${orgId}/access-rules/${humanRule}`, 'DELETE'))
        .status,
    ).toBe(403)
  })
})

describe('human approval flow', () => {
  it('runs request, inbox, approval, activation, extension and revocation', async () => {
    const cipherId = await cipherIn(humanCollection)

    const pre = await (
      await requester.call(`/api/leases/ciphers/${cipherId}/pre-check`)
    ).json<any>()
    expect(pre).toMatchObject({
      approvalMode: 1,
      hasActiveLease: false,
      defaultDurationSeconds: 3600,
      maxDurationSeconds: 7200,
      canStartLease: true,
      slotFreesAt: null,
    })
    const state0 = await (await requester.call(`/api/leases/ciphers/${cipherId}/state`)).json<any>()
    expect(state0).toMatchObject({
      activeLease: null,
      pendingRequest: null,
      approvedRequest: null,
      extensionsAllowed: true,
      maxExtensionDurationSeconds: 1800,
      canRequest: true,
    })

    // Too long, bad window and missing rule are refused.
    expect((await request(requester, cipherId, { durationSeconds: 9000 })).status).toBe(400)
    expect((await request(requester, cipherId, { start: new Date().toISOString() })).status).toBe(
      400,
    )

    const created = await (
      await request(requester, cipherId, { durationSeconds: 1800, reason: 'Incident 42' })
    ).json<any>()
    expect(created).toMatchObject({ object: 'accessRequestResult', approvalMode: 1 })
    const req = created.request
    expect(req).toMatchObject({
      status: 0,
      cipherId,
      collectionId: humanCollection,
      ruleId: humanRule,
      requesterId: requester.uuid,
      reason: 'Incident 42',
      decisions: [],
      producedLeaseId: null,
      extensionOfLeaseId: null,
    })
    expect(req.requesterEmail).toBe('lease-requester@example.com')

    // A second request for the same item is refused.
    expect((await request(requester, cipherId)).status).toBe(409)
    expect(
      (await (await requester.call(`/api/leases/ciphers/${cipherId}/state`)).json<any>())
        .pendingRequest.id,
    ).toBe(req.id)
    expect(
      (await (await requester.call(`/api/leases/ciphers/${cipherId}/pre-check`)).json<any>())
        .canStartLease,
    ).toBe(false)

    // Lists.
    const mine = await (await requester.call('/api/access-requests/mine')).json<any>()
    expect(mine.data.map((r: any) => r.id)).toContain(req.id)
    const inbox = await (await approver.call('/api/access-requests/inbox')).json<any>()
    expect(inbox.data.map((r: any) => r.id)).toContain(req.id)
    expect(
      (await (await requester.call('/api/access-requests/inbox')).json<any>()).data.map(
        (r: any) => r.id,
      ),
    ).not.toContain(req.id)
    expect((await (await plain.call('/api/access-requests/inbox')).json<any>()).data).toEqual([])
    expect(
      (await (await owner.call('/api/access-requests/inbox')).json<any>()).data.map(
        (r: any) => r.id,
      ),
    ).toContain(req.id)

    // Visibility of one request.
    expect((await requester.call(`/api/access-requests/${req.id}`)).status).toBe(200)
    expect((await approver.call(`/api/access-requests/${req.id}`)).status).toBe(200)
    expect((await requester2.call(`/api/access-requests/${req.id}`)).status).toBe(404)
    expect((await outsider.call(`/api/access-requests/${req.id}`)).status).toBe(404)
    expect((await approver.call(`/api/access-requests/${crypto.randomUUID()}`)).status).toBe(404)

    // Decisions: not the requester, not a bystander, valid verdicts only.
    expect((await decide(requester, req.id, 1)).status).toBe(403)
    expect((await decide(requester2, req.id, 1)).status).toBe(404)
    expect((await decide(approver, req.id, 7)).status).toBe(400)
    // Activation needs an approval first.
    expect((await requester.call(`/api/access-requests/${req.id}/activate`, 'POST')).status).toBe(
      409,
    )

    // Deny, then see it in history and refuse a second decision.
    const denied = await (await decide(approver, req.id, 0, 'not now')).json<any>()
    expect(denied).toMatchObject({
      status: 2,
      decisions: [{ deciderKind: 1, id: approver.uuid, comment: 'not now', verdict: 0 }],
    })
    expect((await decide(approver, req.id, 1)).status).toBe(409)
    expect((await requester.call(`/api/access-requests/${req.id}/revoke`, 'POST', {})).status).toBe(
      409,
    )
    expect(
      (await (await approver.call('/api/access-requests/history')).json<any>()).data.map(
        (r: any) => r.id,
      ),
    ).toContain(req.id)
    expect(
      (await (await requester.call('/api/access-requests/mine')).json<any>()).data.map(
        (r: any) => r.id,
      ),
    ).not.toContain(req.id)
    expect(
      (await (await approver.call('/api/access-requests/inbox')).json<any>()).data.map(
        (r: any) => r.id,
      ),
    ).not.toContain(req.id)

    // Ask again and approve.
    const second = (await (await request(requester, cipherId, { reason: 'again' })).json<any>())
      .request
    expect(second.id).not.toBe(req.id)
    const approved = await (await decide(approver, second.id, 1, 'ok')).json<any>()
    expect(approved).toMatchObject({ status: 1, producedLeaseId: null })
    expect(
      (await (await requester.call(`/api/leases/ciphers/${cipherId}/state`)).json<any>())
        .approvedRequest.id,
    ).toBe(second.id)

    // Only the requester activates; the lease starts and is shown everywhere.
    expect((await approver.call(`/api/access-requests/${second.id}/activate`, 'POST')).status).toBe(
      404,
    )
    const act = await requester.call(`/api/access-requests/${second.id}/activate`, 'POST')
    expect(act.status).toBe(200)
    const lease = await act.json<any>()
    expect(lease).toMatchObject({
      object: 'accessLease',
      requestId: second.id,
      cipherId,
      collectionId: humanCollection,
      requesterId: requester.uuid,
      status: 0,
      ruleId: null,
      revokedAt: null,
    })
    expect(Date.parse(lease.notAfter) - Date.parse(lease.notBefore)).toBeGreaterThan(3590_000)
    expect(
      (await requester.call(`/api/access-requests/${second.id}/activate`, 'POST')).status,
    ).toBe(409)
    expect((await requester.call(`/api/access-requests/${second.id}`)).status).toBe(200)
    expect(
      await (await requester.call(`/api/access-requests/${second.id}`)).json<any>(),
    ).toMatchObject({
      status: 1,
      producedLeaseId: lease.id,
      producedLeaseStatus: 0,
    })

    expect(
      (await (await requester.call('/api/leases/mine')).json<any>()).data.map((l: any) => l.id),
    ).toEqual([lease.id])
    expect(
      (await (await approver.call('/api/leases/active')).json<any>()).data.map((l: any) => l.id),
    ).toContain(lease.id)
    expect(
      (await (await requester2.call('/api/leases/active')).json<any>()).data.map((l: any) => l.id),
    ).not.toContain(lease.id)
    const state = await (await requester.call(`/api/leases/ciphers/${cipherId}/state`)).json<any>()
    expect(state).toMatchObject({ activeLease: { id: lease.id }, canRequest: false })
    expect(
      (await (await requester.call(`/api/leases/ciphers/${cipherId}/pre-check`)).json<any>())
        .hasActiveLease,
    ).toBe(true)

    // Extension: bounded by the rule, needs a reason, approved by a human, applied at approval.
    expect(
      (await requester.call(`/api/leases/${lease.id}/extend`, 'POST', { durationSeconds: 1800 }))
        .status,
    ).toBe(400)
    expect(
      (
        await requester.call(`/api/leases/${lease.id}/extend`, 'POST', {
          durationSeconds: 5000,
          reason: 'long',
        })
      ).status,
    ).toBe(400)
    expect(
      (
        await approver.call(`/api/leases/${lease.id}/extend`, 'POST', {
          durationSeconds: 600,
          reason: 'x',
        })
      ).status,
    ).toBe(404)
    const ext = await (
      await requester.call(`/api/leases/${lease.id}/extend`, 'POST', {
        durationSeconds: 1200,
        reason: 'still debugging',
      })
    ).json<any>()
    expect(ext).toMatchObject({
      status: 0,
      extensionOfLeaseId: lease.id,
      reason: 'still debugging',
    })
    expect(
      (
        await requester.call(`/api/leases/${lease.id}/extend`, 'POST', {
          durationSeconds: 600,
          reason: 'again',
        })
      ).status,
    ).toBe(409)
    expect((await decide(requester, ext.id, 1)).status).toBe(403)
    const extDone = await (await decide(approver, ext.id, 1)).json<any>()
    expect(extDone.status).toBe(1)
    const after = (await (await requester.call('/api/leases/mine')).json<any>()).data[0]
    expect(Date.parse(after.notAfter) - Date.parse(lease.notAfter)).toBe(1_200_000)
    // An approved extension cannot be activated.
    expect((await requester.call(`/api/access-requests/${ext.id}/activate`, 'POST')).status).toBe(
      400,
    )

    // An approver revokes the lease; it moves to history and cannot be revoked again.
    expect(
      (await requester2.call(`/api/leases/${lease.id}/revoke`, 'POST', { reason: 'x' })).status,
    ).toBe(404)
    expect(
      (await approver.call(`/api/leases/${lease.id}/revoke`, 'POST', { reason: 'incident over' }))
        .status,
    ).toBe(200)
    expect(
      (await approver.call(`/api/leases/${lease.id}/revoke`, 'POST', { reason: 'again' })).status,
    ).toBe(409)
    const hist = (await (await approver.call('/api/leases/history')).json<any>()).data.find(
      (l: any) => l.id === lease.id,
    )
    expect(hist).toMatchObject({
      status: 2,
      revokedByUserId: approver.uuid,
      revocationReason: 'incident over',
    })
    expect((await (await requester.call('/api/leases/mine')).json<any>()).data).toEqual([])
    expect(
      (
        await requester.call(`/api/leases/${lease.id}/extend`, 'POST', {
          durationSeconds: 600,
          reason: 'late',
        })
      ).status,
    ).toBe(409)
    // The requester may ask again once the lease is over.
    expect((await request(requester, cipherId)).status).toBe(200)
  })

  it('lets the requester withdraw a request and cancel their own lease', async () => {
    const cipherId = await cipherIn(humanCollection, '2.withdraw')
    const r1 = (await (await request(requester, cipherId)).json<any>()).request
    expect(
      (await approver.call(`/api/access-requests/${r1.id}/revoke`, 'POST', { reason: 'no' }))
        .status,
    ).toBe(200)
    expect((await requester.call(`/api/access-requests/${r1.id}`)).status).toBe(200)
    expect((await (await requester.call(`/api/access-requests/${r1.id}`)).json<any>()).status).toBe(
      3,
    )
    expect((await decide(approver, r1.id, 1)).status).toBe(409)

    const r2 = (await (await request(requester, cipherId)).json<any>()).request
    expect((await decide(approver, r2.id, 1)).status).toBe(200)
    // Withdrawing an approved request that has no lease yet.
    expect((await requester.call(`/api/access-requests/${r2.id}/revoke`, 'POST', {})).status).toBe(
      200,
    )
    expect((await requester.call(`/api/access-requests/${r2.id}/activate`, 'POST')).status).toBe(
      409,
    )

    const r3 = (await (await request(requester, cipherId)).json<any>()).request
    await decide(approver, r3.id, 1)
    const lease = await (
      await requester.call(`/api/access-requests/${r3.id}/activate`, 'POST')
    ).json<any>()
    // Revoking the request of a live lease ends the lease; the requester's own end reads as cancelled.
    expect(
      (await requester.call(`/api/access-requests/${r3.id}/revoke`, 'POST', { reason: 'done' }))
        .status,
    ).toBe(200)
    const ended = (await (await requester.call('/api/leases/history')).json<any>()).data.find(
      (l: any) => l.id === lease.id,
    )
    expect(ended).toMatchObject({
      status: 3,
      revokedByUserId: requester.uuid,
      revocationReason: 'done',
    })
  })

  it('refuses members without privileged access, without an item, or without a rule', async () => {
    const cipherId = await cipherIn(humanCollection, '2.guard')
    expect((await request(plain, cipherId)).status).toBe(404)
    expect((await request(outsider, cipherId)).status).toBe(404)
    expect((await outsider.call(`/api/leases/ciphers/${cipherId}/state`)).status).toBe(404)
    expect((await request(requester, crypto.randomUUID())).status).toBe(404)
    const ownerMember = (await owner.json(`/api/organizations/${orgId}/users`)).data.find(
      (m: any) => m.email === owner.email,
    ).id as string
    const open = (
      await owner.json(`/api/organizations/${orgId}/collections`, 'POST', {
        name: '2.open',
        users: [
          {
            id: ownerMember,
            readOnly: false,
            hidePasswords: false,
            manage: true,
          },
        ],
        groups: [],
      })
    ).id
    const free = await cipherIn(open, '2.norule')
    expect((await request(owner, free)).status).toBe(400)
    expect((await owner.call(`/api/leases/ciphers/${free}/pre-check`)).status).toBe(404)
    expect(await (await owner.call(`/api/leases/ciphers/${free}/state`)).json<any>()).toMatchObject(
      {
        canRequest: false,
        extensionsAllowed: false,
        activeLease: null,
      },
    )
    for (const path of [
      '/api/leases/active',
      '/api/leases/mine',
      '/api/leases/history',
      '/api/access-requests/inbox',
      '/api/access-requests/mine',
      '/api/access-requests/history',
    ]) {
      expect((await raw(path)).status, path).toBe(401)
    }
  })
})

describe('automatic approval and single active lease', () => {
  it('grants a lease at once and holds the item for one member', async () => {
    const cipherId = await cipherIn(autoCollection, '2.auto')
    const res = await (await request(requester, cipherId, { durationSeconds: 900 })).json<any>()
    expect(res).toMatchObject({ approvalMode: 0 })
    expect(res.request).toMatchObject({
      status: 1,
      decisions: [{ deciderKind: 0, verdict: 1, id: null }],
    })
    expect(res.request.producedLeaseId).toBeTruthy()
    const mine = (await (await requester.call('/api/leases/mine')).json<any>()).data
    expect(mine.find((l: any) => l.cipherId === cipherId)).toMatchObject({
      status: 0,
      requestId: res.request.id,
    })
    // The rule allows one live lease: the other member waits.
    const pre = await (
      await requester2.call(`/api/leases/ciphers/${cipherId}/pre-check`)
    ).json<any>()
    expect(pre).toMatchObject({ canStartLease: false, hasActiveLease: false })
    expect(pre.slotFreesAt).toBeTruthy()
    expect((await request(requester2, cipherId)).status).toBe(409)
    expect((await request(requester, cipherId)).status).toBe(409)
    // Extensions on an automatic rule apply at once.
    const lease = mine.find((l: any) => l.cipherId === cipherId)
    const ext = await (
      await requester.call(`/api/leases/${lease.id}/extend`, 'POST', {
        durationSeconds: 600,
        reason: 'more',
      })
    ).json<any>()
    expect(ext).toMatchObject({ status: 1, decisions: [{ deciderKind: 0 }] })
    const after = (await (await requester.call('/api/leases/mine')).json<any>()).data.find(
      (l: any) => l.id === lease.id,
    )
    expect(Date.parse(after.notAfter) - Date.parse(lease.notAfter)).toBe(600_000)
    // Once the lease is revoked the slot frees up.
    expect((await requester.call(`/api/leases/${lease.id}/revoke`, 'POST', {})).status).toBe(200)
    expect((await request(requester2, cipherId)).status).toBe(200)
  })

  it('lets exactly one of two concurrent automatic requests win', async () => {
    const cipherId = await cipherIn(autoCollection, '2.race-auto')
    const results = await Promise.all([request(requester, cipherId), request(requester2, cipherId)])
    expect(results.map((r) => r.status).sort()).toEqual([200, 409])
    const live = (
      await sql(
        'select count(*) as n from pam_leases where cipher_uuid = ? and status = 0',
        cipherId,
      )
    ).results[0]
    expect(live.n).toBe(1)
  })

  it('lets exactly one of two concurrent activations win under a single-lease rule', async () => {
    // Switch the human rule to a single active lease for this test.
    const col = (
      await owner.json(`/api/organizations/${orgId}/collections`, 'POST', {
        name: '2.single',
        users: [
          {
            id: await requesterId(requester),
            readOnly: false,
            hidePasswords: false,
            manage: false,
          },
          {
            id: await requesterId(requester2),
            readOnly: false,
            hidePasswords: false,
            manage: false,
          },
        ],
        groups: [],
      })
    ).id
    const rule = await (
      await rules(
        '',
        'POST',
        ruleBody({ name: 'Single human', singleActiveLease: true, collections: [col] }),
      )
    ).json<any>()
    const cipherId = await cipherIn(col, '2.race-human')
    const a = (await (await request(requester, cipherId)).json<any>()).request
    const b = (await (await request(requester2, cipherId)).json<any>()).request
    expect((await decide(owner, a.id, 1)).status).toBe(200)
    expect((await decide(owner, b.id, 1)).status).toBe(200)
    const results = await Promise.all([
      requester.call(`/api/access-requests/${a.id}/activate`, 'POST'),
      requester2.call(`/api/access-requests/${b.id}/activate`, 'POST'),
    ])
    expect(results.map((r) => r.status).sort()).toEqual([200, 409])
    const live = (
      await sql(
        'select count(*) as n from pam_leases where cipher_uuid = ? and status = 0',
        cipherId,
      )
    ).results[0]
    expect(live.n).toBe(1)
    await rules(`/${rule.id}`, 'DELETE')
  })

  it('lets exactly one of two concurrent decisions win', async () => {
    const cipherId = await cipherIn(humanCollection, '2.race-decide')
    const req = (await (await request(requester2, cipherId)).json<any>()).request
    const results = await Promise.all([decide(approver, req.id, 1), decide(owner, req.id, 0)])
    expect(results.map((r) => r.status).sort()).toEqual([200, 409])
    const n = (
      await sql('select count(*) as n from pam_access_decisions where request_uuid = ?', req.id)
    ).results[0]
    expect(n.n).toBe(1)
  })
})

async function requesterId(who: Actor) {
  const row = (
    await sql(
      'select uo.uuid as id from users_organizations uo join users u on u.uuid = uo.user_uuid where u.email = ? and uo.organization_uuid = ?',
      who.email,
      orgId,
    )
  ).results[0]
  return row.id as string
}

describe('expiry and the sweep', () => {
  it('expires undecided and unactivated requests and ended leases, and queues access-end rotations', async () => {
    const cipherId = await cipherIn(humanCollection, '2.expire')
    // A pending request past its deadline reads as expired at once, and the sweep stores it.
    const r1 = (await (await request(requester, cipherId)).json<any>()).request
    await sql(
      'update pam_access_requests set expires_at = ? where uuid = ?',
      Date.now() - 1000,
      r1.id,
    )
    expect((await (await requester.call(`/api/access-requests/${r1.id}`)).json<any>()).status).toBe(
      4,
    )
    expect((await decide(approver, r1.id, 1)).status).toBe(409)
    expect((await requester.call(`/api/access-requests/${r1.id}/activate`, 'POST')).status).toBe(
      409,
    )
    await sweepAccess(env)
    expect(
      (await sql('select status from pam_access_requests where uuid = ?', r1.id)).results[0].status,
    ).toBe(4)

    // An approved request that is never activated expires too.
    const r2 = (await (await request(requester, cipherId)).json<any>()).request
    await decide(approver, r2.id, 1)
    await sql(
      'update pam_access_requests set expires_at = ? where uuid = ?',
      Date.now() - 1000,
      r2.id,
    )
    expect((await requester.call(`/api/access-requests/${r2.id}/activate`, 'POST')).status).toBe(
      409,
    )
    await sweepAccess(env)
    expect(
      (await sql('select status from pam_access_requests where uuid = ?', r2.id)).results[0].status,
    ).toBe(4)

    // A lease whose time ran out reads as Expired; the sweep stores it and queues a rotation.
    const target = (
      await (
        await owner.call(
          `/api/organizations/${orgId}/access-connectors/rotation/target-systems`,
          'POST',
          { name: 'exp', method: 0 },
        )
      ).json<any>()
    ).id
    await owner.call(
      `/api/organizations/${orgId}/access-connectors/rotation/target-systems/${target}`,
      'PUT',
      { name: 'exp', sealedData: '2.s', wrappedKey: '2.w' },
    )
    const cfg = await (
      await owner.call(`/api/organizations/${orgId}/access-connectors/rotation/configs`, 'POST', {
        cipherId,
        targetSystemId: target,
        sealedData: '2.a',
        wrappedKey: '2.b',
        rotateOnAccessEnd: true,
      })
    ).json<any>()
    const r3 = (await (await request(requester, cipherId)).json<any>()).request
    await decide(approver, r3.id, 1)
    const lease = await (
      await requester.call(`/api/access-requests/${r3.id}/activate`, 'POST')
    ).json<any>()
    await sql('update pam_leases set not_after = ? where uuid = ?', Date.now() - 1000, lease.id)
    const shown = (await (await approver.call('/api/leases/history')).json<any>()).data.find(
      (l: any) => l.id === lease.id,
    )
    expect(shown.status).toBe(1)
    expect(
      (await (await requester.call('/api/leases/mine')).json<any>()).data.some(
        (l: any) => l.id === lease.id,
      ),
    ).toBe(false)
    expect((await requester.call(`/api/leases/${lease.id}/revoke`, 'POST', {})).status).toBe(409)
    await sweepAccess(env)
    expect(
      (await sql('select status from pam_leases where uuid = ?', lease.id)).results[0].status,
    ).toBe(1)
    const jobs = (
      await sql('select source, status from pam_rotation_jobs where config_uuid = ?', cfg.id)
    ).results
    expect(jobs).toEqual([{ source: 2, status: 0 }])
    // Sweeping again changes nothing.
    await sweepAccess(env)
    await sweepRotation(env)
    expect(
      (await sql('select count(*) as n from pam_rotation_jobs where config_uuid = ?', cfg.id))
        .results[0].n,
    ).toBe(1)
  })

  it('ends a lease by revocation and rotates after access when the config asks for it', async () => {
    const cipherId = await cipherIn(humanCollection, '2.rotate-on-revoke')
    const target = (
      await (
        await owner.call(
          `/api/organizations/${orgId}/access-connectors/rotation/target-systems`,
          'POST',
          { name: 'rv', method: 0 },
        )
      ).json<any>()
    ).id
    await owner.call(
      `/api/organizations/${orgId}/access-connectors/rotation/target-systems/${target}`,
      'PUT',
      { name: 'rv', sealedData: '2.s', wrappedKey: '2.w' },
    )
    const cfg = await (
      await owner.call(`/api/organizations/${orgId}/access-connectors/rotation/configs`, 'POST', {
        cipherId,
        targetSystemId: target,
        sealedData: '2.a',
        wrappedKey: '2.b',
        rotateOnAccessEnd: true,
      })
    ).json<any>()
    const r = (await (await request(requester, cipherId)).json<any>()).request
    await decide(approver, r.id, 1)
    const lease = await (
      await requester.call(`/api/access-requests/${r.id}/activate`, 'POST')
    ).json<any>()
    expect(
      (await sql('select count(*) as n from pam_rotation_jobs where config_uuid = ?', cfg.id))
        .results[0].n,
    ).toBe(0)
    await approver.call(`/api/leases/${lease.id}/revoke`, 'POST', { reason: 'done' })
    expect(
      (await sql('select source from pam_rotation_jobs where config_uuid = ?', cfg.id)).results,
    ).toEqual([{ source: 2 }])
  })
})
