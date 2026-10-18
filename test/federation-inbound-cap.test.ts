// An inbound peer request is read under a cap while it streams (TASKS #422). Two instances in one
// workerd (test/federation-helpers.ts).
import { beforeAll, expect, it } from 'vitest'
import { loadIdentity } from '../src/federation/identity'
import { MAX_INBOUND_BYTES } from '../src/federation/peers'
import { signRequest } from '../src/federation/signature'
import { type Net, pair, twoInstances, userOn } from './federation-helpers'

let net: Net

beforeAll(async () => {
  net = await twoInstances()
  const adminA = await userOn(net.A, 'admin-a@example.com', { verified: true })
  const adminB = await userOn(net.B, 'admin-b@example.org', { verified: true })
  await pair(net, adminA, adminB)
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

const signed = async (body: Uint8Array) => {
  const id = await loadIdentity(net.A.env as never)
  const headers = new Headers({ 'content-type': 'application/json' })
  await signRequest(
    'POST',
    `${net.B.base}/federation/v1/ping`,
    headers,
    body,
    id.instanceId,
    id.privateKey,
  )
  return headers
}

it('refuses an over-cap chunked peer request while streaming', async () => {
  const { stream, pulled } = endless()
  const res = await net.B.fetch('/federation/v1/ping', {
    method: 'POST',
    headers: await signed(new Uint8Array()),
    body: stream,
    duplex: 'half',
  } as RequestInit)
  expect(res.status).toBe(413)
  expect(pulled.bytes).toBeLessThanOrEqual(MAX_INBOUND_BYTES + 2_000_000)
}, 60_000)

it('accepts a valid signed peer request under the cap', async () => {
  const body = new TextEncoder().encode('{}')
  const res = await net.B.fetch('/federation/v1/ping', {
    method: 'POST',
    headers: await signed(body),
    body,
  })
  expect(res.status).toBe(200)
})
