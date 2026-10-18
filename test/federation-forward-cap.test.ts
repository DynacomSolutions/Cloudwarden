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

/** About 200 MB of chunks made on demand; `pulled.bytes` counts what the server asked for. */
const endless = () => {
  const chunk = new Uint8Array(65_536).fill(120)
  const pulled = { bytes: 0 }
  const stream = new ReadableStream({
    pull(ctrl) {
      if (pulled.bytes >= 200_000_000) return ctrl.close()
      pulled.bytes += chunk.length
      ctrl.enqueue(chunk)
    },
  })
  return { stream, pulled }
}

const post = (path: string, body: ReadableStream) =>
  net.B.fetch(path, {
    method: 'POST',
    headers: { Authorization: `Bearer ${alice.token}`, 'Content-Type': 'application/json' },
    body,
    duplex: 'half',
  } as RequestInit)

it('refuses an over-cap chunked import-organization for a federated organisation without forwarding it', async () => {
  const { stream, pulled } = endless()
  net.log.length = 0
  const res = await post(`/api/ciphers/import-organization?organizationId=${orgId}`, stream)
  expect(res.status).toBe(400)
  expect(await res.json()).toMatchObject({ message: 'You cannot import this much data at once.' })
  expect(net.log.filter((l) => l.includes(net.A.domain))).toEqual([])
  expect(pulled.bytes).toBeLessThanOrEqual(MAX_IMPORT_BODY + 2_000_000)
}, 60_000)

// `/import` is a feature that does not cross instances: it is refused before any body read.
it('refuses a chunked organisation import for a federated organisation without reading or forwarding it', async () => {
  const { stream, pulled } = endless()
  net.log.length = 0
  const res = await post(`/api/organizations/${orgId}/import`, stream)
  expect(res.status).toBe(400)
  expect(net.log.filter((l) => l.includes(net.A.domain))).toEqual([])
  expect(pulled.bytes).toBeLessThanOrEqual(2_000_000)
}, 60_000)
