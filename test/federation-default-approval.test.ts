// Incoming workspaces wait for approval unless an admin stored another choice (TASKS #407).
import { beforeAll, describe, expect, it } from 'vitest'
import { type Net, twoInstances, type User, userOn } from './federation-helpers'

const fed = '/api/cloudwarden/federation'
let net: Net
let adminA: User
let adminB: User

beforeAll(async () => {
  net = await twoInstances({ shippedDefaults: true })
  adminA = await userOn(net.A, 'admin-a@example.com', { verified: true })
  adminB = await userOn(net.B, 'admin-b@example.org', { verified: true })
}, 120_000)

describe('incoming approval default', { timeout: 120_000 }, () => {
  it('refuses to trust an unknown instance until an admin approves it', async () => {
    expect(await adminB.json(`${fed}/admin/settings`)).toMatchObject({
      requireIncomingApproval: true,
    })
    const added = await adminA.json(`${fed}/admin/peers`, 'POST', { domain: net.B.domain })
    const fingerprint = (
      (await (await net.B.fetch('/.well-known/cloudwarden-federation')).json()) as any
    ).fingerprint
    const res = await adminA.call(`${fed}/admin/peers/${added.id}/approve`, 'POST', {
      fingerprint,
    })
    expect(await res.json()).toMatchObject({ active: false })
    const [onB] = (await adminB.json(`${fed}/admin/peers`)).data as any[]
    expect(onB).toMatchObject({ status: 'pending', acceptedAutomatically: false })
  })

  it('keeps an explicitly stored choice', async () => {
    const off = await adminB.json(`${fed}/admin/settings`, 'PUT', {
      requireIncomingApproval: false,
    })
    expect(off).toMatchObject({ requireIncomingApproval: false })
    expect(await adminB.json(`${fed}/admin/settings`)).toMatchObject({
      requireIncomingApproval: false,
    })
  })
})
