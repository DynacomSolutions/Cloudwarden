// Share first, ask the admin after (TASKS #382): while a workspace awaits an instance admin the
// Access dialog queues shares without contacting the peer; approval sends them (checked again),
// a decline or expiry cancels them. Two instances in one workerd (test/federation-helpers.ts).
import { beforeAll, describe, expect, it } from 'vitest'
import { type Net, twoInstances, type User, userOn } from './federation-helpers'
import { addMember } from './org-helpers'

const fed = '/api/cloudwarden/federation'

let net: Net
let adminA: User
let adminB: User
let owner: User
let mgr: User
let mgr2: User
let viewer: User
let owner2: User
let alice: User
let orgId: string
let col1: string
let col2: string
let org2: string
let org2Col: string
let mgrMember: string
let fingerprintB: string

const ext = (collection: string, rest = '', org = orgId) =>
  `${fed}/organizations/${org}/collections/${collection}/external-access${rest}`

const state = (u: User, col = col1) => u.json(ext(col))
const peersOf = async (admin: User) => (await admin.json(`${fed}/admin/peers`)).data as any[]
const sql = (q: string, ...args: unknown[]) =>
  (net.A.env.DB as D1Database)
    .prepare(q)
    .bind(...args)
    .run()

/**
 * A's admin approves the workspace; B remembers a domain that was removed, so its admin approves
 * too (the next incoming request would otherwise be trusted automatically).
 */
async function approveBoth(id: string) {
  await adminA.json(`${fed}/admin/peers/${id}/approve`, 'POST', { fingerprint: fingerprintB })
  const waiting = (await peersOf(adminB)).find((p) => !p.active)
  if (waiting) {
    const descA = (await (await net.A.fetch('/.well-known/cloudwarden-federation')).json()) as any
    await adminB.json(`${fed}/admin/peers/${waiting.id}/approve`, 'POST', {
      fingerprint: descA.fingerprint,
    })
  }
  await net.flush()
}

async function unpairAll() {
  for (const p of await peersOf(adminA)) await adminA.call(`${fed}/admin/peers/${p.id}`, 'DELETE')
  for (const p of await peersOf(adminB)) await adminB.call(`${fed}/admin/peers/${p.id}`, 'DELETE')
}

/** A non-admin asks for B from the dialog; returns the pending workspace id. */
async function request(u: User, col = col1, org = orgId) {
  const r = await u.json(ext(col, '/workspaces', org), 'POST', {
    domain: net.B.domain,
    fingerprint: fingerprintB,
  })
  return r.workspace.id as string
}

const share = (u: User, workspaceId: string, emails: string[], extra: object = {}) =>
  u.json(ext(col1), 'POST', { workspaceId, emails, readOnly: true, ...extra })

beforeAll(async () => {
  net = await twoInstances()
  adminA = await userOn(net.A, 'admin-a@example.com', { verified: true })
  adminB = await userOn(net.B, 'admin-b@example.org', { verified: true })
  owner = await userOn(net.A, 'owner@example.com')
  mgr = await userOn(net.A, 'mgr@example.com')
  mgr2 = await userOn(net.A, 'mgr2@example.com')
  viewer = await userOn(net.A, 'viewer@example.com')
  alice = await userOn(net.B, 'alice@example.org', { publicKey: 'alice-public-key-b64' })
  const org = await owner.json('/api/organizations', 'POST', {
    name: 'Acme',
    billingEmail: 'billing@example.com',
    key: '4.ownerOrgKey',
    keys: { publicKey: 'orgPublic', encryptedPrivateKey: '2.orgPrivate' },
    collectionName: '2.defaultCollection',
    planType: 0,
  })
  orgId = org.id
  col1 = (await owner.json('/api/sync')).collections[0].id
  col2 = (await owner.json(`/api/organizations/${orgId}/collections`, 'POST', { name: '2.second' }))
    .id
  await addMember(
    owner,
    orgId,
    viewer,
    { collections: [{ id: col1, readOnly: true, hidePasswords: false, manage: false }] },
    net.A.mail,
  )
  mgrMember = await addMember(
    owner,
    orgId,
    mgr,
    { collections: [{ id: col1, readOnly: false, hidePasswords: false, manage: true }] },
    net.A.mail,
  )
  await addMember(
    owner,
    orgId,
    mgr2,
    { collections: [{ id: col1, readOnly: false, hidePasswords: false, manage: true }] },
    net.A.mail,
  )
  owner2 = await userOn(net.A, 'owner2@example.com')
  const o2 = await owner2.json('/api/organizations', 'POST', {
    name: 'Other',
    billingEmail: 'billing2@example.com',
    key: '4.otherOrgKey',
    keys: { publicKey: 'orgPublic3', encryptedPrivateKey: '2.pk' },
    collectionName: '2.otherCollection',
    planType: 0,
  })
  org2 = o2.id
  org2Col = (await owner2.json('/api/sync')).collections[0].id
  fingerprintB = (await (await net.B.fetch('/.well-known/cloudwarden-federation')).json<any>())
    .fingerprint
}, 120_000)

describe('shares queued behind a workspace request', { timeout: 120_000 }, () => {
  let ws: string
  let aliceItem: string
  let nobodyItem: string

  it('queues without contacting the peer and tells the instance admins', async () => {
    ws = await request(owner)
    expect(
      net.A.mail.sent.some((m) => m.to === adminA.email && /Workspace request/.test(m.subject)),
    ).toBe(true)
    net.log.length = 0
    const res = await share(owner, ws, [alice.email, 'nobody@example.org'])
    expect(res.data ?? res).toBeDefined()
    const rows = (res.data ?? res) as { email: string; ok: boolean; result: string; id: string }[]
    expect(rows.map((r) => [r.ok, r.result])).toEqual([
      [true, 'queued'],
      [true, 'queued'],
    ])
    aliceItem = rows[0]?.id as string
    nobodyItem = rows[1]?.id as string
    // Nothing crossed the network and B knows nothing.
    expect(net.log).toEqual([])
    expect(await peersOf(adminB)).toHaveLength(0)
    const st = await state(owner)
    expect(st.queued).toHaveLength(2)
    expect(st.queued[0]).toMatchObject({ status: 'queued', peerDomain: net.B.domain })
    expect(st.grantees).toHaveLength(0)
    // The admin sees what waits behind the request, and the count for the nav badge.
    const [p] = await peersOf(adminA)
    expect(p.queued).toEqual([
      {
        organizationId: orgId,
        organizationName: 'Acme',
        requestedByEmail: owner.email,
        collections: 1,
        people: 2,
      },
    ])
    expect((await adminA.json(`${fed}/status`)).pendingRequests).toBe(1)
    expect((await owner.json(`${fed}/status`)).pendingRequests).toBe(0)
  })

  it('lets collection managers edit and remove queued items, and nobody else', async () => {
    const put = (u: User, col: string, id: string, org = orgId) =>
      u.call(ext(col, `/queued/${id}`, org), 'PUT', { readOnly: false, hidePasswords: true })
    expect((await put(mgr, col1, aliceItem)).status).toBe(200)
    expect((await state(owner)).queued.find((r: any) => r.id === aliceItem)).toMatchObject({
      readOnly: false,
      hidePasswords: true,
    })
    // Not a manager of the collection, or of the organisation at all.
    expect((await put(viewer, col1, aliceItem)).status).toBe(403)
    expect((await put(owner2, org2Col, aliceItem, org2)).status).toBe(404)
    expect((await put(owner2, col1, aliceItem)).status).toBe(404)
    // The path must match the item: another collection of the same organisation is a 404.
    expect((await put(owner, col2, aliceItem)).status).toBe(404)
    expect((await owner.call(ext(col2, `/queued/${aliceItem}`), 'DELETE')).status).toBe(404)
    expect((await owner2.call(ext(org2Col, `/queued/${aliceItem}`, org2), 'DELETE')).status).toBe(
      404,
    )
    expect((await state(owner)).queued).toHaveLength(2)
    expect((await mgr.call(ext(col1, `/queued/${nobodyItem}`), 'DELETE')).status).toBe(200)
    expect((await state(owner)).queued).toHaveLength(1)
    // Re-queue the second address for the approval below.
    const again = await share(owner, ws, ['nobody@example.org'])
    expect((again.data ?? again)[0].result).toBe('queued')
  })

  it('caps the people queued per requester and per request', async () => {
    const owners = (await sql('SELECT uuid FROM users WHERE email = ?1', owner.email)) as any
    expect(owners).toBeDefined()
    // 19 more for the owner makes 21 with the two real ones: the next one is refused.
    for (let i = 0; i < 19; i++) {
      await sql(
        "INSERT INTO federation_queued_shares (uuid, peer_uuid, peer_domain, organization_uuid, collection_uuid, email, requested_by, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', 0, 0)",
        crypto.randomUUID(),
        ws,
        net.B.domain,
        orgId,
        col2,
        `fill${i}@example.org`,
        owner.uuid,
      )
    }
    const over = await share(owner, ws, ['one-more@example.org'])
    expect((over.data ?? over)[0]).toMatchObject({ ok: false })
    expect((over.data ?? over)[0].error).toMatch(/too many/i)
    await sql("DELETE FROM federation_queued_shares WHERE email LIKE 'fill%@example.org'")
    // Per request: 50 queued by others fills it.
    for (let i = 0; i < 50; i++) {
      await sql(
        "INSERT INTO federation_queued_shares (uuid, peer_uuid, peer_domain, organization_uuid, collection_uuid, email, requested_by, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', 0, 0)",
        crypto.randomUUID(),
        ws,
        net.B.domain,
        orgId,
        col2,
        `fill${i}@example.org`,
        adminA.uuid,
      )
    }
    const full = await share(owner, ws, ['one-more@example.org'])
    expect((full.data ?? full)[0].error).toMatch(/too many/i)
    await sql("DELETE FROM federation_queued_shares WHERE email LIKE 'fill%@example.org'")
  })

  it('sends the queue when the admin approves, checked again, and tells the requester', async () => {
    // mgr edited alice's item, so it is theirs and would be dropped (no right to invite): the
    // owner takes it over again, which re-attributes it and is audited.
    expect(
      (
        await owner.call(ext(col1, `/queued/${aliceItem}`), 'PUT', {
          readOnly: false,
          hidePasswords: true,
        })
      ).status,
    ).toBe(200)
    expect(
      (await adminA.json(`${fed}/admin/events`)).data.filter(
        (e: any) => e.name === 'QueuedShareEdited',
      ).length,
    ).toBeGreaterThanOrEqual(2)
    net.log.length = 0
    const before = net.A.mail.sent.length
    const ap = await adminA.json(`${fed}/admin/peers/${ws}/approve`, 'POST', {
      fingerprint: fingerprintB,
    })
    expect(ap.active).toBe(true)
    await net.flush()
    // B invited the user; the queue is empty and the person shows as a normal external grantee.
    const st = await state(owner)
    expect(st.queued).toHaveLength(0)
    expect(st.grantees.map((g: any) => g.email).sort()).toEqual([alice.email, 'nobody@example.org'])
    expect(st.grantees.every((g: any) => g.status === 0)).toBe(true)
    const inv = await alice.json(`${fed}/invitations`)
    expect(inv.data).toHaveLength(1)
    expect(inv.data[0]).toMatchObject({ organizationName: 'Acme', status: 'pending' })
    expect(net.log.some((l) => l.includes('/federation/v1/invitations'))).toBe(true)
    expect(
      net.A.mail.sent
        .slice(before)
        .some((m) => m.to === owner.email && /external shares/i.test(m.subject)),
    ).toBe(true)
    const events = (await adminA.json(`${fed}/admin/events`)).data.map((e: any) => e.name)
    expect(events).toContain('QueuedShareSent')
    expect(events).toContain('ShareQueued')
    expect((await adminA.json(`${fed}/status`)).pendingRequests).toBe(0)
  })

  it('drops items whose requester may no longer invite or manage', async () => {
    await unpairAll()
    const settings = `${fed}/organizations/${orgId}/settings`
    const members = `/api/organizations/${orgId}/users/${mgrMember}`
    const access = (manage: boolean) => ({
      type: 2,
      accessAll: false,
      collections: [{ id: col1, readOnly: !manage, hidePasswords: false, manage }],
      groups: [],
    })
    const approveAndRead = async (id: string) => {
      net.log.length = 0
      await approveBoth(id)
      // Nothing was invited.
      expect(net.log.filter((l) => l.includes('/federation/v1/invitations'))).toHaveLength(0)
      const queued = (await state(mgr)).queued
      await unpairAll()
      return queued
    }
    // Round one: the owner turns managers' inviting off after the share was queued.
    await owner.json(settings, 'PUT', { collectionManagersMayInvite: true })
    const w1 = await request(mgr)
    expect((await share(mgr, w1, ['dropped1@example.org'])).data[0].result).toBe('queued')
    await owner.json(settings, 'PUT', { collectionManagersMayInvite: false })
    const one = await approveAndRead(w1)
    expect(one).toEqual([
      expect.objectContaining({ email: 'dropped1@example.org', status: 'dropped' }),
    ])
    expect(one[0].note).toMatch(/manage users/i)
    await mgr.call(ext(col1, `/queued/${one[0].id}`), 'DELETE')
    // Round two: the manager was reduced to view only after queueing.
    await owner.json(settings, 'PUT', { collectionManagersMayInvite: true })
    const w2 = await request(mgr)
    expect((await share(mgr, w2, ['dropped2@example.org'])).data[0].result).toBe('queued')
    expect((await owner.call(members, 'PUT', access(false))).status).toBe(200)
    // Viewing the state needs manage, so read the rows from the database.
    net.log.length = 0
    await approveBoth(w2)
    expect(net.log.filter((l) => l.includes('/federation/v1/invitations'))).toHaveLength(0)
    const row = (await (net.A.env.DB as D1Database)
      .prepare(
        "SELECT status, note FROM federation_queued_shares WHERE email = 'dropped2@example.org'",
      )
      .first()) as { status: string; note: string }
    expect(row.status).toBe('dropped')
    expect(row.note).toBeTruthy()
    expect((await adminA.json(`${fed}/admin/events`)).data.map((e: any) => e.name)).toContain(
      'QueuedShareDropped',
    )
    await owner.call(members, 'PUT', access(true))
    await owner.json(settings, 'PUT', { collectionManagersMayInvite: false })
    await unpairAll()
    await sql("DELETE FROM federation_queued_shares WHERE email LIKE 'dropped%'")
  })

  it('cancels the queue when the admin declines, and when the request expires', async () => {
    await owner.json(`${fed}/organizations/${orgId}/settings`, 'PUT', {
      collectionManagersMayInvite: true,
    })
    const wsDecline = await request(mgr)
    const a = await share(mgr, wsDecline, ['declined@example.org'])
    expect((a.data ?? a)[0].result).toBe('queued')
    const before = net.A.mail.sent.length
    net.log.length = 0
    expect((await adminA.call(`${fed}/admin/peers/${wsDecline}`, 'DELETE')).status).toBe(200)
    expect(net.log.filter((l) => l.includes('/federation/v1/invitations'))).toHaveLength(0)
    expect((await state(mgr)).queued).toEqual([
      expect.objectContaining({ email: 'declined@example.org', status: 'declined' }),
    ])
    expect(net.A.mail.sent.slice(before).some((m) => m.to === mgr.email)).toBe(true)
    expect((await adminA.json(`${fed}/admin/events`)).data.map((e: any) => e.name)).toContain(
      'QueuedShareCancelled',
    )
    // Expiry after seven days.
    const wsOld = await request(mgr)
    const b = await share(mgr, wsOld, ['expired@example.org'])
    expect((b.data ?? b)[0].result).toBe('queued')
    await sql(
      'UPDATE federation_peers SET created_at = ?1 WHERE uuid = ?2',
      Date.now() - 8 * 86_400_000,
      wsOld,
    )
    await adminA.json(`${fed}/admin/peers`)
    const st = (await state(mgr)).queued
    expect(st.find((r: any) => r.email === 'expired@example.org')).toMatchObject({
      status: 'expired',
    })
    expect(st.find((r: any) => r.email === 'declined@example.org')).toMatchObject({
      status: 'declined',
    })
    expect(await peersOf(adminA)).toHaveLength(0)
    // A finished entry can be cleared by a manager.
    for (const r of st)
      expect((await mgr.call(ext(col1, `/queued/${r.id}`), 'DELETE')).status).toBe(200)
    expect((await state(mgr)).queued).toHaveLength(0)
  })

  it('does not queue for a workspace the user cannot see or a suspended one', async () => {
    const wsMgr = await request(mgr)
    // Another non-admin cannot see mgr's request, so cannot queue behind it.
    const res = await owner.call(ext(col1), 'POST', {
      workspaceId: wsMgr,
      emails: ['x@example.org'],
    })
    expect(res.status).toBe(400)
    await adminA.call(`${fed}/admin/peers/${wsMgr}`, 'DELETE')
  })
})
