// Collection-first federated sharing (TASKS #370 to #372): inline pairing from a collection's
// Access dialog, sharing with people of a workspace, updating an existing federated member and
// removal on both sides. Two instances in one workerd (test/federation-helpers.ts).
import { beforeAll, describe, expect, it } from 'vitest'
import { loadIdentity } from '../src/federation/identity'
import { signRequest } from '../src/federation/signature'
import { type Net, twoInstances, type User, userOn } from './federation-helpers'
import { addMember } from './org-helpers'

const fed = '/api/cloudwarden/federation'

let net: Net
let adminA: User
let adminB: User
let owner: User
let viewer: User
let mgr: User
let mgr2: User
let owner2: User
let org2: string
let org2Col: string
let alice: User
let bob: User
let orgId: string
let col1: string
let col2: string
let peerOnA: string
let peerOnB: string
let fingerprintB: string
let aliceMember: string

const ext = (collection: string, rest = '') =>
  `${fed}/organizations/${orgId}/collections/${collection}/external-access${rest}`

const fakePeer = (domain: string, requestedBy: string | null, createdAt = Date.now()) =>
  (net.A.env.DB as D1Database)
    .prepare(
      "INSERT INTO federation_peers (uuid, instance_id, domain, public_key, fingerprint, protocol_version, status, local_approved, remote_approved, requested_by, created_at, updated_at) VALUES (?1, ?1, ?2, 'k', 'f', 1, 'pending', 0, 0, ?3, ?4, ?4)",
    )
    .bind(crypto.randomUUID(), domain, requestedBy, createdAt)
    .run()
const dropFakePeers = () =>
  (net.A.env.DB as D1Database)
    .prepare("DELETE FROM federation_peers WHERE domain LIKE '%.example.net'")
    .run()

const members = async () => (await owner.json(`${fed}/organizations/${orgId}/members`)).data

beforeAll(async () => {
  net = await twoInstances()
  adminA = await userOn(net.A, 'admin-a@example.com', { verified: true })
  adminB = await userOn(net.B, 'admin-b@example.org', { verified: true })
  owner = await userOn(net.A, 'owner@example.com')
  viewer = await userOn(net.A, 'viewer@example.com')
  alice = await userOn(net.B, 'alice@example.org', { publicKey: 'alice-public-key-b64' })
  bob = await userOn(net.B, 'bob@example.org', { publicKey: 'bob-public-key-b64' })
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
  // A local member who can only view col1: not allowed to share it.
  await addMember(
    owner,
    orgId,
    viewer,
    { collections: [{ id: col1, readOnly: true, hidePasswords: false, manage: false }] },
    net.A.mail,
  )
  // Collection managers without the manage users permission.
  mgr = await userOn(net.A, 'mgr@example.com')
  mgr2 = await userOn(net.A, 'mgr2@example.com')
  for (const m of [mgr, mgr2]) {
    await addMember(
      owner,
      orgId,
      m,
      { collections: [{ id: col1, readOnly: false, hidePasswords: false, manage: true }] },
      net.A.mail,
    )
  }
  // A second organisation nobody above belongs to, for cross-organisation checks.
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

describe('collection-first federated sharing', { timeout: 120_000 }, () => {
  it('shows the remote fingerprint and refuses a mismatch', async () => {
    const look = await owner.json(ext(col1, '/workspaces/lookup'), 'POST', {
      domain: net.B.domain,
    })
    expect(look).toMatchObject({ domain: net.B.domain, fingerprint: fingerprintB, workspace: null })
    const wrong = await owner.call(ext(col1, '/workspaces'), 'POST', {
      domain: net.B.domain,
      fingerprint: '0000:1111',
    })
    expect(wrong.status).toBe(400)
    expect((await adminA.json(`${fed}/admin/peers`)).data).toHaveLength(0)
  })

  it('only lets people who manage the collection use the dialog endpoints', async () => {
    expect((await viewer.call(ext(col1))).status).toBe(403)
    expect(
      (await viewer.call(ext(col1, '/workspaces/lookup'), 'POST', { domain: net.B.domain })).status,
    ).toBe(403)
    expect(
      (
        await viewer.call(ext(col1, '/workspaces'), 'POST', {
          domain: net.B.domain,
          fingerprint: fingerprintB,
        })
      ).status,
    ).toBe(403)
    // Somebody outside the organisation does not learn that it exists.
    expect((await adminA.call(ext(col1))).status).toBe(404)
  })

  it('keeps non-admin requests under their own small caps and expires them', async () => {
    // Per user: two open requests at most.
    await fakePeer('a1.example.net', mgr.uuid)
    await fakePeer('a2.example.net', mgr.uuid)
    const perUser = await mgr.call(ext(col1, '/workspaces'), 'POST', {
      domain: net.B.domain,
      fingerprint: fingerprintB,
    })
    expect(perUser.status).toBe(429)
    await dropFakePeers()
    // Instance wide: five open requests at most.
    for (let i = 0; i < 5; i++) await fakePeer(`o${i}.example.net`, crypto.randomUUID())
    expect(
      (
        await mgr.call(ext(col1, '/workspaces'), 'POST', {
          domain: net.B.domain,
          fingerprint: fingerprintB,
        })
      ).status,
    ).toBe(429)
    await dropFakePeers()
    // Requests nobody approved within seven days are dropped.
    await fakePeer('old.example.net', crypto.randomUUID(), Date.now() - 8 * 24 * 3_600_000)
    await mgr.json(ext(col1))
    const left = await (net.A.env.DB as D1Database)
      .prepare("SELECT count(*) AS n FROM federation_peers WHERE domain = 'old.example.net'")
      .first<{ n: number }>()
    expect(left?.n).toBe(0)
    // A full admin and inbound queue does not block them: those are counted separately.
    for (let i = 0; i < 20; i++) await fakePeer(`p${i}.example.net`, null)
    const ok = await mgr.call(ext(col1, '/workspaces'), 'POST', {
      domain: net.B.domain,
      fingerprint: fingerprintB,
    })
    expect(ok.status).toBe(200)
    await dropFakePeers()
    await (net.A.env.DB as D1Database)
      .prepare('DELETE FROM federation_peers WHERE domain = ?1')
      .bind(net.B.domain)
      .run()
  })

  it('lets a non-admin only request a workspace, which never becomes trusted by itself', async () => {
    const before = net.log.length
    const res = await owner.json(ext(col1, '/workspaces'), 'POST', {
      domain: net.B.domain,
      fingerprint: fingerprintB,
    })
    peerOnA = res.workspace.id
    expect(res).toMatchObject({
      created: true,
      workspace: { domain: net.B.domain, state: 'awaitingInstanceAdmin', active: false },
    })
    // No pairing request left this instance and the other side knows nothing.
    expect(net.log.slice(before).some((l) => l.includes('/federation/v1/pair'))).toBe(false)
    expect((await adminB.json(`${fed}/admin/peers`)).data).toHaveLength(0)
    // The request can neither be approved by the requester nor used for sharing.
    expect(
      (
        await owner.call(`${fed}/admin/peers/${peerOnA}/approve`, 'POST', {
          fingerprint: fingerprintB,
        })
      ).status,
    ).toBe(403)
    const share = await owner.call(ext(col1), 'POST', {
      workspaceId: peerOnA,
      emails: [alice.email],
    })
    expect(share.status).toBe(400)
    // Asking again changes nothing and creates no second peer.
    const again = await owner.json(ext(col1, '/workspaces'), 'POST', {
      domain: net.B.domain,
      fingerprint: fingerprintB,
    })
    expect(again).toMatchObject({ created: false, workspace: { state: 'awaitingInstanceAdmin' } })
    // Instance admins see who asked.
    const peers = (await adminA.json(`${fed}/admin/peers`)).data
    expect(peers).toHaveLength(1)
    expect(peers[0]).toMatchObject({
      localApproved: false,
      requestedByEmail: owner.email,
      sharing: [],
    })
    // Another non-admin sees neither the request nor its fingerprint: only "awaiting admin".
    expect((await mgr.json(ext(col1))).workspaces).toEqual([])
    expect(
      await mgr.json(ext(col1, '/workspaces/lookup'), 'POST', { domain: net.B.domain }),
    ).toEqual({ domain: net.B.domain, fingerprint: null, workspace: null, awaitingAdmin: true })
    expect(
      await mgr.json(ext(col1, '/workspaces'), 'POST', {
        domain: net.B.domain,
        fingerprint: fingerprintB,
      }),
    ).toEqual({ created: false, workspace: null, awaitingAdmin: true })
    expect((await adminA.json(`${fed}/admin/peers`)).data).toHaveLength(1)
    // The requester sees their own request.
    expect((await owner.json(ext(col1))).workspaces).toEqual([
      expect.objectContaining({ id: peerOnA, state: 'awaitingInstanceAdmin' }),
    ])
  })

  it('limits workspace requests per user', async () => {
    let last = 0
    for (let i = 0; i < 6; i++) {
      last = (
        await owner.call(ext(col1, '/workspaces'), 'POST', {
          domain: net.B.domain,
          fingerprint: fingerprintB,
        })
      ).status
    }
    expect(last).toBe(429)
  })

  it('approves inline for an instance admin, and the remote side still approves', async () => {
    // An instance admin who manages a collection pairs from the dialog in one step.
    const adminOrg = await adminA.json('/api/organizations', 'POST', {
      name: 'Admin org',
      billingEmail: 'billing@example.com',
      key: '4.adminOrgKey',
      keys: { publicKey: 'orgPublic2', encryptedPrivateKey: '2.orgPrivate2' },
      collectionName: '2.adminCollection',
      planType: 0,
    })
    const adminCol = (await adminA.json('/api/sync')).collections[0].id
    const res = await adminA.json(
      `${fed}/organizations/${adminOrg.id}/collections/${adminCol}/external-access/workspaces`,
      'POST',
      { domain: net.B.domain, fingerprint: fingerprintB },
    )
    expect(res.workspace.id).toBe(peerOnA)
    expect(res.workspace.state).toBe('awaitingRemote')
    // B now lists the pending request, already approved by A, and its admin must approve it.
    const onB = (await adminB.json(`${fed}/admin/peers`)).data
    expect(onB).toHaveLength(1)
    expect(onB[0]).toMatchObject({
      domain: net.A.domain,
      remoteApproved: true,
      localApproved: false,
    })
    peerOnB = onB[0].id
    // The invited user's own instance cannot be activated by a non-admin either.
    expect(
      (
        await alice.call(`${fed}/admin/peers/${peerOnB}/approve`, 'POST', {
          fingerprint: '0000',
        })
      ).status,
    ).toBe(403)
    const descA = await (await net.A.fetch('/.well-known/cloudwarden-federation')).json<any>()
    const ap = await adminB.json(`${fed}/admin/peers/${peerOnB}/approve`, 'POST', {
      fingerprint: descA.fingerprint,
    })
    expect(ap.active).toBe(true)
    const state = await owner.json(ext(col1))
    expect(state.workspaces).toEqual([expect.objectContaining({ id: peerOnA, state: 'active' })])
  })

  it('invites to exactly the chosen collection with the chosen permission', async () => {
    const res = await owner.json(ext(col1), 'POST', {
      workspaceId: peerOnA,
      emails: [alice.email, owner.email, 'nobody@example.org'],
      readOnly: true,
      hidePasswords: true,
    })
    expect(res.data[0]).toMatchObject({ email: alice.email, ok: true, result: 'invited' })
    aliceMember = res.data[0].id
    // An address with an account on this instance is refused, the rest still go through.
    expect(res.data[1]).toMatchObject({ email: owner.email, ok: false })
    expect(res.data[2]).toMatchObject({ ok: true })
    await owner.call(`${fed}/organizations/${orgId}/members/${res.data[2].id}`, 'DELETE')

    const state = await owner.json(ext(col1))
    expect(state.grantees).toEqual([
      expect.objectContaining({
        id: aliceMember,
        email: alice.email,
        peerDomain: net.B.domain,
        status: 0,
        readOnly: true,
        hidePasswords: true,
        manage: false,
      }),
    ])
    // Role User, no access to everything, only this collection; nothing on the second one.
    const detail = await owner.json(
      `/api/organizations/${orgId}/users/${aliceMember}?includeGroups=true`,
    )
    expect(detail).toMatchObject({ type: 2, accessAll: false })
    expect(detail.collections.map((c: { id: string }) => c.id)).toEqual([col1])
    expect((await owner.json(ext(col2))).grantees).toEqual([])
    // The invitation reached the other instance.
    const inv = (await alice.json(`${fed}/invitations`)).data
    expect(inv).toHaveLength(1)
    expect(inv[0]).toMatchObject({ organizationName: 'Acme', status: 'pending', peerActive: true })
  })

  it('shows accepted people so an admin can confirm them', async () => {
    const inv = (await alice.json(`${fed}/invitations`)).data[0]
    expect((await alice.call(`${fed}/invitations/${inv.id}/accept`, 'POST')).status).toBe(200)
    const g = (await owner.json(ext(col1))).grantees[0]
    expect(g).toMatchObject({ status: 1, userId: alice.uuid })
    expect(
      (
        await owner.call(`/api/organizations/${orgId}/users/${aliceMember}/confirm`, 'POST', {
          key: '4.wrapped',
        })
      ).status,
    ).toBe(200)
    expect((await owner.json(ext(col1))).grantees[0].status).toBe(2)
  })

  it('adds or updates access of an existing federated member without a second invitation', async () => {
    const before = net.B.mail.sent.length
    const up = await owner.json(ext(col1), 'POST', {
      workspaceId: peerOnA,
      emails: [alice.email.toUpperCase()],
      manage: true,
    })
    expect(up.data[0]).toMatchObject({ ok: true, result: 'updated', id: aliceMember })
    expect(net.B.mail.sent.length).toBe(before)
    const add2 = await owner.json(ext(col2), 'POST', {
      workspaceId: peerOnA,
      emails: [alice.email],
    })
    expect(add2.data[0]).toMatchObject({ ok: true, result: 'updated', id: aliceMember })
    expect((await owner.json(ext(col1))).grantees[0]).toMatchObject({
      readOnly: false,
      hidePasswords: false,
      manage: true,
    })
    const put = await owner.call(ext(col2, `/${aliceMember}`), 'PUT', {
      readOnly: true,
      hidePasswords: false,
      manage: false,
    })
    expect(put.status).toBe(200)
    expect((await owner.json(ext(col2))).grantees[0]).toMatchObject({ readOnly: true })
    // Still one federated member.
    expect(await members()).toHaveLength(1)
    // Alice sees both collections on her own instance.
    await net.flush()
    const sync = await alice.json('/api/sync')
    expect(sync.collections.map((c: { id: string }) => c.id).sort()).toEqual([col1, col2].sort())
  })

  it('removes access on both sides, and the membership once nothing is left', async () => {
    const first = await owner.json(ext(col1, `/${aliceMember}`), 'DELETE')
    expect(first).toEqual({ removedMember: false })
    expect((await owner.json(ext(col1))).grantees).toEqual([])
    expect(await members()).toHaveLength(1)
    await net.flush()
    expect((await alice.json('/api/sync')).collections.map((c: { id: string }) => c.id)).toEqual([
      col2,
    ])
    // A grantee of another collection cannot be removed through this one.
    expect((await owner.call(ext(col1, `/${aliceMember}`), 'DELETE')).status).toBe(404)

    // Alice is confirmed: a collection manager only removes the grant, never the membership.
    const last = await owner.json(ext(col2, `/${aliceMember}`), 'DELETE')
    expect(last).toEqual({ removedMember: false })
    expect(await members()).toHaveLength(1)
    // Removing the person is a manage users action.
    expect(
      (await mgr.call(`${fed}/organizations/${orgId}/members/${aliceMember}`, 'DELETE')).status,
    ).toBe(403)
    expect(
      (await owner.call(`${fed}/organizations/${orgId}/members/${aliceMember}`, 'DELETE')).status,
    ).toBe(200)
    expect(await members()).toHaveLength(0)
    await net.flush()
    const profile = await alice.json('/api/accounts/profile')
    expect(profile.organizations).toEqual([])
    expect((await alice.json('/api/sync')).collections).toEqual([])
  })

  it('purges only unconfirmed memberships that the sharing flow created', async () => {
    const shared = await owner.json(ext(col1), 'POST', {
      workspaceId: peerOnA,
      emails: [bob.email],
    })
    const bobMember = shared.data[0].id
    expect(await owner.json(ext(col1, `/${bobMember}`), 'DELETE')).toEqual({ removedMember: true })
    expect(await members()).toHaveLength(0)
    // A person invited on the members page is not undone by a collection manager.
    const manual = await owner.json(`${fed}/organizations/${orgId}/members`, 'POST', {
      email: bob.email,
      peerId: peerOnA,
      type: 2,
      collections: [{ id: col1, readOnly: false, hidePasswords: false, manage: false }],
    })
    expect(await owner.json(ext(col1, `/${manual.id}`), 'DELETE')).toEqual({ removedMember: false })
    expect(await members()).toHaveLength(1)
    await owner.call(`${fed}/organizations/${orgId}/members/${manual.id}`, 'DELETE')
    expect(await members()).toHaveLength(0)
  })

  it('never auto-confirms people of other workspaces', async () => {
    const shared = await owner.json(ext(col1), 'POST', {
      workspaceId: peerOnA,
      emails: [bob.email],
    })
    const id = shared.data[0].id
    const inv = (await bob.json(`${fed}/invitations`)).data[0]
    expect((await bob.call(`${fed}/invitations/${inv.id}/accept`, 'POST')).status).toBe(200)
    const o = `/api/organizations/${orgId}/users`
    expect(
      (await owner.call(`/api/organizations/${orgId}/policies/18`, 'PUT', { enabled: true }))
        .status,
    ).toBe(200)
    try {
      const pending = await owner.json(`${o}/pending-auto-confirm`)
      expect(pending.data.map((r: { id: string }) => r.id)).not.toContain(id)
      expect((await owner.call(`${o}/${id}/auto-confirm`, 'POST', { key: '4.k' })).status).toBe(400)
      const bulk = await owner.json(`${o}/bulk-auto-confirm`, 'POST', {
        keys: [{ id, key: '4.k' }],
      })
      expect(bulk.data[0].error).toMatch(/manually/)
      expect((await owner.json(ext(col1))).grantees[0].status).toBe(1)
    } finally {
      await owner.call(`/api/organizations/${orgId}/policies/18`, 'PUT', { enabled: false })
    }
    // The manual confirm still works.
    expect((await owner.call(`${o}/${id}/confirm`, 'POST', { key: '4.wrapped' })).status).toBe(200)
  })

  it('shows a collection-only external member only themselves in the member directory', async () => {
    const bobMember = (await members())[0].id
    const idn = await loadIdentity(net.B.env as never)
    const send = async (path: string) => {
      const url = `${net.A.base}/federation/v1/members/${bob.uuid}/proxy${path}`
      const headers = new Headers({ 'cloudwarden-federated-user': bob.uuid })
      await signRequest('GET', url, headers, new Uint8Array(), idn.instanceId, idn.privateKey)
      return net.A.fetch(new URL(url).pathname, { method: 'GET', headers })
    }
    const mine = await send(`/api/organizations/${orgId}/users/mini-details`)
    expect(mine.status).toBe(200)
    expect((await mine.json<any>()).data.map((r: { id: string }) => r.id)).toEqual([bobMember])
    // Local members still get the directory.
    expect(
      (await owner.json(`/api/organizations/${orgId}/users/mini-details`)).data.length,
    ).toBeGreaterThan(2)
    // Giving them access to everything lifts the restriction.
    await owner.call(`/api/organizations/${orgId}/users/${bobMember}`, 'PUT', {
      type: 2,
      accessAll: true,
      collections: [],
      groups: [],
    })
    const wide = await send(`/api/organizations/${orgId}/users/mini-details`)
    expect((await wide.json<any>()).data.length).toBeGreaterThan(1)
    await owner.call(`/api/organizations/${orgId}/users/${bobMember}`, 'PUT', {
      type: 2,
      accessAll: false,
      collections: [{ id: col1, readOnly: false, hidePasswords: false, manage: false }],
      groups: [],
    })
  })

  it('lets only people with manage users invite new external people, unless an admin allows managers', async () => {
    const before = await mgr.json(ext(col1))
    expect(before).toMatchObject({ canInvite: false, canChangeInviteSetting: false })
    expect(await owner.json(ext(col1))).toMatchObject({
      canInvite: true,
      canChangeInviteSetting: true,
    })
    const denied = await mgr.json(ext(col1), 'POST', {
      workspaceId: peerOnA,
      emails: [alice.email],
    })
    expect(denied.data[0]).toMatchObject({ ok: false })
    expect(denied.data[0].error).toMatch(/manage users/)
    expect(await members()).toHaveLength(1)
    // Existing federated members can still be granted, changed and have access removed.
    const upd = await mgr.json(ext(col1), 'POST', {
      workspaceId: peerOnA,
      emails: [bob.email],
      readOnly: true,
    })
    expect(upd.data[0]).toMatchObject({ ok: true, result: 'updated' })
    // The switch belongs to owners and admins.
    const settings = `${fed}/organizations/${orgId}/settings`
    expect(await mgr.json(settings)).toEqual({
      collectionManagersMayInvite: false,
      canChange: false,
    })
    expect((await mgr.call(settings, 'PUT', { collectionManagersMayInvite: true })).status).toBe(
      403,
    )
    expect(await owner.json(settings, 'PUT', { collectionManagersMayInvite: true })).toEqual({
      collectionManagersMayInvite: true,
    })
    const allowed = await mgr.json(ext(col1), 'POST', {
      workspaceId: peerOnA,
      emails: [alice.email],
    })
    expect(allowed.data[0]).toMatchObject({ ok: true, result: 'invited' })
    await owner.json(settings, 'PUT', { collectionManagersMayInvite: false })
    await owner.call(`${fed}/organizations/${orgId}/members/${allowed.data[0].id}`, 'DELETE')
  })

  it('refuses ids that belong to another organisation or collection', async () => {
    const bobMember = (await members()).find((m: { email: string }) => m.email === bob.email).id
    const orgPath = (o: string, col: string, rest = '') =>
      `${fed}/organizations/${o}/collections/${col}/external-access${rest}`
    // Not a member of the other organisation: nothing about it is revealed.
    for (const [method, rest, body] of [
      ['GET', '', undefined],
      ['POST', '', { workspaceId: peerOnA, emails: [alice.email] }],
      ['POST', '/workspaces/lookup', { domain: net.B.domain }],
      ['POST', '/workspaces', { domain: net.B.domain, fingerprint: fingerprintB }],
      ['PUT', `/${bobMember}`, { readOnly: true }],
      ['DELETE', `/${bobMember}`, undefined],
    ] as const) {
      expect((await owner.call(orgPath(org2, org2Col, rest), method, body)).status).toBe(404)
    }
    // Own organisation, another organisation's collection.
    expect((await owner.call(orgPath(orgId, org2Col))).status).toBe(404)
    expect((await owner.call(orgPath(orgId, org2Col, `/${bobMember}`), 'DELETE')).status).toBe(404)
    // The other organisation's owner cannot reach this organisation's member through theirs.
    expect((await owner2.call(orgPath(org2, org2Col, `/${bobMember}`), 'DELETE')).status).toBe(404)
    expect(
      (await owner2.call(orgPath(org2, org2Col, `/${bobMember}`), 'PUT', { manage: true })).status,
    ).toBe(404)
    expect((await owner2.call(orgPath(orgId, col1))).status).toBe(404)
    expect(
      (
        await owner2.call(`${fed}/organizations/${orgId}/settings`, 'PUT', {
          collectionManagersMayInvite: true,
        })
      ).status,
    ).toBe(404)
    // A collection the person does not hold: not found through the other collection.
    expect(
      (await owner.call(orgPath(orgId, col2, `/${bobMember}`), 'PUT', { manage: true })).status,
    ).toBe(404)
    // Nothing changed.
    expect((await owner.json(orgPath(orgId, col1))).grantees[0]).toMatchObject({ id: bobMember })
    expect((await owner.json(orgPath(orgId, col2))).grantees).toEqual([])
  })

  it('rate limits changing and removing access like sharing', async () => {
    const bobMember = (await members()).find((m: { email: string }) => m.email === bob.email).id
    let put = 0
    for (let i = 0; i < 61; i++) {
      put = (await mgr2.call(ext(col1, `/${bobMember}`), 'PUT', { readOnly: true })).status
    }
    expect(put).toBe(429)
    expect((await mgr2.call(ext(col1, `/${bobMember}`), 'DELETE')).status).toBe(429)
    expect(await members()).toHaveLength(1)
  })

  it('reports shared people on the trusted workspaces list', async () => {
    const res = await owner.json(ext(col1), 'POST', { workspaceId: peerOnA, emails: [bob.email] })
    expect(res.data[0]).toMatchObject({ ok: true, result: 'updated' })
    const peers = (await adminA.json(`${fed}/admin/peers`)).data
    expect(peers[0].sharing).toEqual([
      { organizationId: orgId, organizationName: 'Acme', people: 1, collections: 1 },
    ])
    const list = await owner.json(`${fed}/organizations/${orgId}/members`)
    expect(list.data[0]).toMatchObject({ email: bob.email, collectionIds: [col1] })
    // Suspending the workspace stops new sharing.
    await adminA.call(`${fed}/admin/peers/${peerOnA}/suspend`, 'POST')
    const res2 = await owner.call(ext(col1), 'POST', {
      workspaceId: peerOnA,
      emails: [alice.email],
    })
    expect(res2.status).toBe(400)
  })
})
