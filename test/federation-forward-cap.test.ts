// The serving side applies the local import cap before it forwards (TASKS #417). Two instances in
// one workerd (test/federation-helpers.ts).
import { beforeAll, expect, it } from 'vitest'
import { MAX_IMPORT_BODY } from '../src/limits'
import { type Net, pair, twoInstances, type User, userOn } from './federation-helpers'

const fed = '/api/cloudwarden/federation'
let net: Net
let alice: User
let orgId: string

beforeAll(async () => {
  net = await twoInstances()
  const adminA = await userOn(net.A, 'admin-a@example.com', { verified: true })
  const adminB = await userOn(net.B, 'admin-b@example.org', { verified: true })
  const owner = await userOn(net.A, 'owner@example.com')
  alice = await userOn(net.B, 'alice@example.org', { publicKey: 'alice-public-key-b64' })
  orgId = (
    await owner.json('/api/organizations', 'POST', {
      name: 'Acme',
      billingEmail: 'billing@example.com',
      key: '4.ownerOrgKey',
      keys: { publicKey: 'orgPublic', encryptedPrivateKey: '2.orgPrivate' },
      collectionName: '2.defaultCollection',
      planType: 0,
    })
  ).id
  const { peerOnA } = await pair(net, adminA, adminB)
  const inv = await owner.json(`${fed}/organizations/${orgId}/members`, 'POST', {
    email: alice.email,
    peerId: peerOnA,
    type: 2,
    collections: [],
  })
  const list = await alice.json(`${fed}/invitations`)
  await alice.call(`${fed}/invitations/${list.data[0].id}/accept`, 'POST')
  await owner.call(`/api/organizations/${orgId}/users/${inv.id}/confirm`, 'POST', {
    key: '4.wrapped',
  })
  await net.flush()
}, 120_000)

it('refuses an over-cap chunked import for a federated organisation without forwarding it', async () => {
  const chunk = new Uint8Array(65_536).fill(120)
  let sent = 0
  const stream = new ReadableStream({
    pull(ctrl) {
      if (sent > MAX_IMPORT_BODY + 100_000) return ctrl.close()
      sent += chunk.length
      ctrl.enqueue(chunk)
    },
  })
  net.log.length = 0
  const res = await net.B.fetch(`/api/ciphers/import-organization?organizationId=${orgId}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${alice.token}`, 'Content-Type': 'application/json' },
    body: stream,
    duplex: 'half',
  } as RequestInit)
  expect(res.status).toBe(400)
  expect(await res.json()).toMatchObject({ message: 'You cannot import this much data at once.' })
  expect(net.log.filter((l) => l.includes(net.A.domain))).toEqual([])
  expect(sent).toBeLessThan(MAX_IMPORT_BODY + 2_000_000)
}, 60_000)
