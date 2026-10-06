// Incoming pairing without a second admin approval (TASKS #381): a valid signed pairing request
// activates the peer on the receiving side unless an admin setting asks for approval, blocked
// domains are refused, and an automatically trusted peer still cannot reach users who never
// accepted an invitation. Two instances in one workerd (test/federation-helpers.ts).
import { beforeAll, describe, expect, it } from 'vitest'
import { getPeer, peerFetch } from '../src/federation/peers'
import { receiveInvitation } from '../src/federation/replica'
import { type Net, twoInstances, type User, userOn } from './federation-helpers'
import { freezeRateLimitWindow } from './helpers'

const fed = '/api/cloudwarden/federation'

let net: Net
let adminA: User
let adminB: User
let alice: User

const fingerprintOf = async (inst: Net['A']) =>
  ((await (await inst.fetch('/.well-known/cloudwarden-federation')).json()) as any)
    .fingerprint as string

/** A (the sharer) adds B and approves it; returns A's peer id. */
async function sharerPairs() {
  const added = await adminA.json(`${fed}/admin/peers`, 'POST', { domain: net.B.domain })
  const res = await adminA.call(`${fed}/admin/peers/${added.id}/approve`, 'POST', {
    fingerprint: await fingerprintOf(net.B),
  })
  return { id: added.id as string, res }
}

const peersOf = async (admin: User) => (await admin.json(`${fed}/admin/peers`)).data as any[]

async function unpairAll() {
  for (const p of await peersOf(adminA)) await adminA.call(`${fed}/admin/peers/${p.id}`, 'DELETE')
  for (const p of await peersOf(adminB)) await adminB.call(`${fed}/admin/peers/${p.id}`, 'DELETE')
}

beforeAll(async () => {
  net = await twoInstances()
  adminA = await userOn(net.A, 'admin-a@example.com', { verified: true })
  adminB = await userOn(net.B, 'admin-b@example.org', { verified: true })
  alice = await userOn(net.B, 'alice@example.org', { publicKey: 'alice-public-key-b64' })
}, 120_000)

describe('incoming pairing', { timeout: 120_000 }, () => {
  it('activates the receiving side automatically by default, with an audit event', async () => {
    const { res } = await sharerPairs()
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ active: true, acceptedAutomatically: false })
    const onB = await peersOf(adminB)
    expect(onB).toHaveLength(1)
    expect(onB[0]).toMatchObject({
      domain: net.A.domain,
      status: 'active',
      active: true,
      localApproved: true,
      acceptedAutomatically: true,
      approvedByEmail: null,
    })
    const events = (await adminB.json(`${fed}/admin/events`)).data as {
      name: string
      peer: string
    }[]
    expect(events).toContainEqual(
      expect.objectContaining({ name: 'PeerAutoAccepted', peer: net.A.domain }),
    )
    // The sharer's own side was approved by its admin, not automatically.
    const onA = await peersOf(adminA)
    expect(onA[0]).toMatchObject({
      active: true,
      acceptedAutomatically: false,
      approvedByEmail: adminA.email,
    })
  })

  it('gives an automatically trusted peer no reach into users who never accepted an invitation', async () => {
    const [peerA] = await peersOf(adminA)
    const peer = (await getPeer(net.A.env as never, peerA.id)) as NonNullable<
      Awaited<ReturnType<typeof getPeer>>
    >
    // Claiming a user of B as a member is refused: there is no stand-in or accepted invitation.
    const claim = await peerFetch(
      net.A.env as never,
      peer,
      `/federation/v1/members/${alice.uuid}/organizations`,
      {
        body: {},
        user: alice.uuid,
      },
    )
    expect([400, 403, 404]).toContain(claim.status)
    // An invitation is only a pending row that the user has to accept.
    const invite = await peerFetch(net.A.env as never, peer, '/federation/v1/invitations', {
      body: {
        memberId: crypto.randomUUID(),
        organizationId: crypto.randomUUID(),
        organizationName: 'Intruder',
        email: alice.email,
      },
    })
    expect(invite.status).toBe(200)
    const profile = await alice.json('/api/accounts/profile')
    expect(profile.organizations).toEqual([])
    const sync = await alice.json('/api/sync')
    expect(sync.profile.organizations).toEqual([])
    const list = await alice.json(`${fed}/invitations`)
    expect(list.data).toHaveLength(1)
    expect(list.data[0].status).toBe('pending')
    // Declining leaves nothing behind.
    await alice.call(`${fed}/invitations/${list.data[0].id}/decline`, 'POST')
  })

  it('refuses a blocked domain and lets an admin unblock it', async () => {
    const [onB] = await peersOf(adminB)
    // Removing with "block" stops the workspace from pairing again at once.
    expect((await adminB.call(`${fed}/admin/peers/${onB.id}?block=true`, 'DELETE')).status).toBe(
      200,
    )
    expect((await adminB.json(`${fed}/admin/settings`)).blockedDomains).toEqual([
      expect.objectContaining({ domain: net.A.domain }),
    ])
    expect(await peersOf(adminA)).toHaveLength(0)
    const again = await sharerPairs()
    expect(again.res.status).toBeGreaterThanOrEqual(400)
    expect(await peersOf(adminB)).toHaveLength(0)
    // B's own admin cannot add a blocked domain either.
    const addBlocked = await adminB.call(`${fed}/admin/peers`, 'POST', { domain: net.A.domain })
    expect(addBlocked.status).toBe(400)
    const events = (await adminB.json(`${fed}/admin/events`)).data as { name: string }[]
    expect(events.map((e) => e.name)).toContain('PeerBlocked')

    await adminB.call(`${fed}/admin/blocked/${net.A.domain}`, 'DELETE')
    expect((await adminB.json(`${fed}/admin/settings`)).blockedDomains).toEqual([])
    await unpairAll()
    const ok = await sharerPairs()
    expect(ok.res.status).toBe(200)
    expect(await peersOf(adminB)).toHaveLength(1)
  })

  it('keeps the incoming peer pending when the admin setting asks for approval', async () => {
    await unpairAll()
    expect(
      await adminB.json(`${fed}/admin/settings`, 'PUT', { requireIncomingApproval: true }),
    ).toMatchObject({ requireIncomingApproval: true })
    const { res } = await sharerPairs()
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ active: false })
    const [onB] = await peersOf(adminB)
    expect(onB).toMatchObject({
      status: 'pending',
      localApproved: false,
      remoteApproved: true,
      acceptedAutomatically: false,
    })
    // Only an instance admin approves it, after checking the fingerprint.
    expect(
      (await alice.call(`${fed}/admin/peers/${onB.id}/approve`, 'POST', { fingerprint: '0000' }))
        .status,
    ).toBe(403)
    const ap = await adminB.json(`${fed}/admin/peers/${onB.id}/approve`, 'POST', {
      fingerprint: await fingerprintOf(net.A),
    })
    expect(ap).toMatchObject({ active: true, acceptedAutomatically: false })
    expect((await peersOf(adminB))[0].approvedByEmail).toBe(adminB.email)
    expect((await adminB.json(`${fed}/admin/events`)).data.map((e: any) => e.name)).toContain(
      'IncomingApprovalChanged',
    )
    // Only instance admins read or change the setting.
    expect((await alice.call(`${fed}/admin/settings`)).status).toBe(403)
    expect(
      (await alice.call(`${fed}/admin/settings`, 'PUT', { requireIncomingApproval: false })).status,
    ).toBe(403)
    await adminB.json(`${fed}/admin/settings`, 'PUT', { requireIncomingApproval: false })
  })

  it('limits pairing requests per address and the number of automatic peers', async () => {
    await unpairAll()
    const restore = freezeRateLimitWindow()
    try {
      let last = 0
      for (let i = 0; i < 12; i++) {
        last = (
          await net.B.fetch('/federation/v1/pair', {
            method: 'POST',
            headers: { 'CF-Connecting-IP': '198.51.100.7', 'content-type': 'application/json' },
            body: '{}',
          })
        ).status
      }
      expect(last).toBe(429)
    } finally {
      restore()
    }
    // Beyond the cap of automatic peers, new requests wait for an admin.
    const db = net.B.env.DB as D1Database
    for (let i = 0; i < 25; i++) {
      await db
        .prepare(
          "INSERT INTO federation_peers (uuid, instance_id, domain, public_key, fingerprint, protocol_version, status, local_approved, remote_approved, accepted_automatically, incoming, created_at, updated_at) VALUES (?1, ?1, ?2, 'k', 'f', 1, 'active', 1, 1, 1, 1, 0, 0)",
        )
        .bind(crypto.randomUUID(), `auto${i}.example.net`)
        .run()
    }
    const { res } = await sharerPairs()
    expect(res.status).toBe(200)
    expect((await peersOf(adminB)).find((p) => p.domain === net.A.domain)).toMatchObject({
      status: 'pending',
      localApproved: false,
      acceptedAutomatically: false,
    })
    await db.prepare("DELETE FROM federation_peers WHERE domain LIKE 'auto%.example.net'").run()
  })
})

describe('follow-ups to incoming trust', { timeout: 120_000 }, () => {
  const run = (sql: string, ...args: unknown[]) =>
    (net.B.env.DB as D1Database)
      .prepare(sql)
      .bind(...args)
      .run()

  it('cancels what is queued behind an automatically trusted peer when it is dropped', async () => {
    await unpairAll()
    const owner = await userOn(net.B, 'queue-owner@example.org')
    const org = await owner.json('/api/organizations', 'POST', {
      name: 'Queue',
      billingEmail: 'billing@example.org',
      key: '4.ownerOrgKey',
      keys: { publicKey: 'orgPublic', encryptedPrivateKey: '2.orgPrivate' },
      collectionName: '2.defaultCollection',
      planType: 0,
    })
    const col = (await owner.json('/api/sync')).collections[0].id
    const queue = (peerId: string, status: string) =>
      run(
        'INSERT INTO federation_queued_shares (uuid, peer_uuid, peer_domain, organization_uuid, collection_uuid, email, requested_by, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0)',
        crypto.randomUUID(),
        peerId,
        net.A.domain,
        org.id,
        col,
        `${status}@example.com`,
        owner.uuid,
        status,
      )
    const statuses = async () =>
      Object.fromEntries(
        (
          (
            await (net.B.env.DB as D1Database)
              .prepare('SELECT email, status FROM federation_queued_shares')
              .all()
          ).results as { email: string; status: string }[]
        ).map((r) => [r.email, r.status]),
      )
    // A pairs with B, so B holds an inbound-only (automatic) peer; unpairing from A drops it on B.
    await run('DELETE FROM federation_removed_domains')
    await sharerPairs()
    let [onB] = await peersOf(adminB)
    expect(onB).toMatchObject({ active: true, acceptedAutomatically: true })
    await queue(onB.id, 'queued')
    await queue(onB.id, 'retry')
    const mails = net.B.mail.sent.length
    const [onA] = await peersOf(adminA)
    expect((await adminA.call(`${fed}/admin/peers/${onA.id}`, 'DELETE')).status).toBe(200)
    await net.flush()
    expect(await peersOf(adminB)).toHaveLength(0)
    expect(await statuses()).toEqual({
      'queued@example.com': 'declined',
      'retry@example.com': 'declined',
    })
    expect(net.B.mail.sent.slice(mails).some((m) => m.to === owner.email)).toBe(true)
    // Removing it on B's side cancels in the same way.
    await run('DELETE FROM federation_queued_shares')
    await unpairAll()
    await run('DELETE FROM federation_removed_domains')
    await sharerPairs()
    ;[onB] = await peersOf(adminB)
    await queue(onB.id, 'queued')
    expect((await adminB.call(`${fed}/admin/peers/${onB.id}?block=true`, 'DELETE')).status).toBe(
      200,
    )
    expect(await statuses()).toEqual({ 'queued@example.com': 'declined' })
    await adminB.call(`${fed}/admin/blocked/${net.A.domain}`, 'DELETE')
    await unpairAll()
  })

  it('lets an approved peer claim an organisation id held by an unapproved peer', async () => {
    await unpairAll()
    await run('DELETE FROM federation_invitations')
    await run('DELETE FROM federation_removed_domains')
    await sharerPairs()
    const [auto] = await peersOf(adminB)
    expect(auto.acceptedAutomatically).toBe(true)
    const org = crypto.randomUUID()
    const keep = crypto.randomUUID()
    const approved = crypto.randomUUID()
    await run(
      "INSERT INTO federation_peers (uuid, instance_id, domain, public_key, fingerprint, protocol_version, status, local_approved, remote_approved, accepted_automatically, approved_by, created_at, updated_at) VALUES (?1, ?1, 'approved.example.net', 'k', 'f', 1, 'active', 1, 1, 0, ?2, 0, 0)",
      approved,
      adminB.uuid,
    )
    const replica = (peerId: string, orgId: string) =>
      run(
        "INSERT INTO federation_replica_orgs (user_uuid, organization_uuid, peer_uuid, profile_json, collections_json, policies_json, revision_date, synced_at) VALUES (?1, ?2, ?3, '{}', '[]', '[]', 0, 0)",
        alice.uuid,
        orgId,
        peerId,
      )
    const invitation = (peerId: string, orgId: string) =>
      run(
        "INSERT INTO federation_invitations (uuid, peer_uuid, remote_member_uuid, organization_uuid, organization_name, user_uuid, status, created_at, updated_at) VALUES (?1, ?2, ?1, ?3, 'n', ?4, 'accepted', 0, 0)",
        crypto.randomUUID(),
        peerId,
        orgId,
        alice.uuid,
      )
    // The unapproved peer squats the id (accepted invitation plus replica); the approved peer
    // already holds another organisation for the same user.
    await invitation(auto.id, org)
    await replica(auto.id, org)
    await invitation(approved, keep)
    await replica(approved, keep)
    const peer = (await getPeer(net.B.env as never, approved)) as NonNullable<
      Awaited<ReturnType<typeof getPeer>>
    >
    const work: Promise<unknown>[] = []
    await receiveInvitation(
      net.B.env as never,
      peer,
      {
        memberId: crypto.randomUUID(),
        organizationId: org,
        organizationName: 'Legit',
        email: alice.email,
      },
      (w) => void work.push(w),
    )
    await Promise.all(work)
    const rows = async (table: string) =>
      (
        await (net.B.env.DB as D1Database)
          .prepare(`SELECT peer_uuid, organization_uuid FROM ${table} ORDER BY organization_uuid`)
          .all()
      ).results as { peer_uuid: string; organization_uuid: string }[]
    const reps = await rows('federation_replica_orgs')
    expect(reps).toEqual([{ peer_uuid: approved, organization_uuid: keep }])
    const invs = await rows('federation_invitations')
    expect(invs.filter((r) => r.organization_uuid === org)).toEqual([
      { peer_uuid: approved, organization_uuid: org },
    ])
    expect(invs.some((r) => r.organization_uuid === keep)).toBe(true)
    // The claim is pending for the user again, from the approved peer only.
    const pending = (await alice.json(`${fed}/invitations`)).data as any[]
    expect(pending.filter((i) => i.status === 'pending')).toHaveLength(1)
    await run('DELETE FROM federation_peers WHERE uuid = ?1', approved)
    await unpairAll()
  })
})
