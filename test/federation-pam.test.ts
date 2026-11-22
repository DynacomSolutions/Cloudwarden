// Privileged access across two instances (docs/privileged-access.md, "Federation"): a federated
// member requests and uses a lease through their own server, which forwards the lease and access
// request calls to the instance that hosts the organisation. Two instances in one workerd.
import { beforeAll, describe, expect, it, vi } from 'vitest'
import { loadIdentity } from '../src/federation/identity'
import { signRequest } from '../src/federation/signature'
import { cipherBody, type Net, pair, twoInstances, type User, userOn } from './federation-helpers'

vi.setConfig({ testTimeout: 600_000, hookTimeout: 600_000 })

const fed = '/api/cloudwarden/federation'

let net: Net
let adminA: User
let adminB: User
let owner: User
let alice: User
let orgId: string
let collectionId: string
let cipherId: string
let memberId: string
let requestId: string
let leaseId: string

const sync = (u: User) => u.json('/api/sync')
const item = async () =>
  (await sync(alice)).ciphers.find((c: { id: string }) => c.id === cipherId) as Record<string, any>

beforeAll(async () => {
  net = await twoInstances()
  adminA = await userOn(net.A, 'pam-admin-a@example.com', { verified: true })
  adminB = await userOn(net.B, 'pam-admin-b@example.org', { verified: true })
  owner = await userOn(net.A, 'pam-owner@example.com')
  alice = await userOn(net.B, 'pam-alice@example.org', { publicKey: 'alice-public-key-b64' })
  const org = await owner.json('/api/organizations', 'POST', {
    name: 'Acme',
    billingEmail: 'billing@example.com',
    key: '4.ownerOrgKey',
    keys: { publicKey: 'orgPublic', encryptedPrivateKey: '2.orgPrivate' },
    collectionName: '2.defaultCollection',
    planType: 0,
  })
  orgId = org.id
  collectionId = (await sync(owner)).collections[0].id
  const { peerOnA } = await pair(net, adminA, adminB)
  const inv = await owner.json(`${fed}/organizations/${orgId}/members`, 'POST', {
    email: alice.email,
    peerId: peerOnA,
    type: 2,
    collections: [{ id: collectionId, readOnly: false, hidePasswords: false, manage: false }],
  })
  memberId = inv.id
  const invitations = await alice.json(`${fed}/invitations`)
  expect(
    (await alice.call(`${fed}/invitations/${invitations.data[0].id}/accept`, 'POST')).status,
  ).toBe(200)
  expect(
    (
      await owner.call(`/api/organizations/${orgId}/users/${memberId}/confirm`, 'POST', {
        key: '4.wrapped',
      })
    ).status,
  ).toBe(200)
  await net.flush()
  // Privileged access for the federated member, and a rule on their collection.
  expect(
    (await owner.call(`/api/organizations/${orgId}/users/enable-pam`, 'PUT', { ids: [memberId] }))
      .status,
  ).toBe(200)
  const rule = await owner.call(`/api/organizations/${orgId}/access-rules`, 'POST', {
    name: 'Human',
    enabled: true,
    conditions: { approvalMode: 'Human' },
    singleActiveLease: false,
    defaultLeaseDurationSeconds: 3600,
    maxLeaseDurationSeconds: 7200,
    allowsExtensions: true,
    maxExtensionDurationSeconds: 1800,
    collections: [collectionId],
  })
  expect(rule.status).toBe(200)
  cipherId = (
    await owner.json('/api/ciphers/create', 'POST', {
      cipher: cipherBody(orgId, '2.restricted'),
      collectionIds: [collectionId],
    })
  ).id
  await net.flush()
}, 600_000)

describe('privileged access through a federated organisation', () => {
  it('shows the item as the reduced row before any lease', async () => {
    const row = await item()
    expect(row.partialData).toEqual(expect.any(String))
    expect(row.login).toBeNull()
  })

  it('asks the hosting instance about an item that only exists there', async () => {
    // The item is not on this instance: answered locally, this would be a 404.
    const pre = await alice.call(`/api/leases/ciphers/${cipherId}/pre-check`)
    expect(pre.status).toBe(200)
    expect(await pre.json()).toMatchObject({ cipherId, canStartLease: true, hasActiveLease: false })
    const state = await alice.call(`/api/leases/ciphers/${cipherId}/state`)
    expect(state.status).toBe(200)
  })

  it('requests a lease through the own server, gets it approved and uses it', async () => {
    const asked = await alice.call(`/api/leases/ciphers/${cipherId}`, 'POST', {
      durationSeconds: 3600,
      reason: 'maintenance',
    })
    expect(asked.status).toBe(200)
    requestId = (await asked.json<any>()).request.id
    // The request list of the member merges the rows of their hosting instance.
    const mine = await alice.json('/api/access-requests/mine')
    expect(mine.data.map((r: { id: string }) => r.id)).toContain(requestId)
    // The owner decides on the hosting instance itself.
    const inbox = await owner.json('/api/access-requests/inbox')
    expect(inbox.data.map((r: { id: string }) => r.id)).toContain(requestId)
    const decided = await owner.call(`/api/access-requests/${requestId}/decision`, 'POST', {
      verdict: 1,
    })
    expect(decided.status).toBe(200)
    // The id is unknown here, so the call goes to the hosting instance that knows it.
    const detail = await alice.call(`/api/access-requests/${requestId}`)
    expect(detail.status).toBe(200)
    expect(await detail.json()).toMatchObject({ id: requestId, status: 1 })
    const active = await alice.call(`/api/access-requests/${requestId}/activate`, 'POST')
    expect(active.status).toBe(200)
    const leases = await alice.json('/api/leases/mine')
    expect(leases.data).toHaveLength(1)
    leaseId = leases.data[0].id
    await net.flush()
    // The replica refreshed: the item arrives in full.
    const row = await item()
    expect(row.login).not.toBeNull()
  })

  it('answers 404 for an id that no instance knows', async () => {
    const res = await alice.call(`/api/access-requests/${crypto.randomUUID()}`)
    expect(res.status).toBe(404)
  })

  it('lists only the rows of organisations that may serve federated members', async () => {
    const idn = await loadIdentity(net.B.env as never)
    const proxy = async (path: string) => {
      const url = `${net.A.base}/federation/v1/members/${alice.uuid}/proxy${path}`
      const headers = new Headers({ 'cloudwarden-federated-user': alice.uuid })
      await signRequest('GET', url, headers, new Uint8Array(), idn.instanceId, idn.privateKey)
      return net.A.fetch(new URL(url).pathname, { method: 'GET', headers })
    }
    expect(((await (await proxy('/api/leases/mine')).json()) as any).data).toHaveLength(1)
    const db = net.A.env.DB as D1Database
    await db
      .prepare(
        "INSERT INTO sso_configs (organization_uuid, enabled, data, created_at, updated_at) VALUES (?1, 1, '{}', 0, 0)",
      )
      .bind(orgId)
      .run()
    try {
      for (const path of [
        '/api/leases/mine',
        '/api/leases/history',
        '/api/access-requests/history',
      ]) {
        const res = await proxy(path)
        expect(res.status, path).toBe(200)
        expect(((await res.json()) as any).data, path).toEqual([])
      }
    } finally {
      await db.prepare('DELETE FROM sso_configs WHERE organization_uuid = ?1').bind(orgId).run()
    }
    expect(((await (await proxy('/api/leases/mine')).json()) as any).data).toHaveLength(1)
  })

  it('ends the lease through the own server and the item is reduced again', async () => {
    const res = await alice.call(`/api/leases/${leaseId}/revoke`, 'POST', { reason: 'done' })
    expect(res.status).toBe(200)
    await net.flush()
    const row = await item()
    expect(row.login).toBeNull()
    expect((await alice.json('/api/leases/mine')).data).toHaveLength(0)
  })
})
