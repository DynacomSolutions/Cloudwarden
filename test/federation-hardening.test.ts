// Hardening of automatic trust (TASKS #381, #382): an automatically trusted peer is inbound only
// until an instance admin approves it; invitations from unapproved peers are quiet, bounded and
// sanitised; blocks by suffix, instance and fingerprint; tombstones for removed domains; separate
// caps; queue retries. Two instances in one workerd (test/federation-helpers.ts).
import { beforeAll, describe, expect, it } from 'vitest'
import { getPeer, type Peer } from '../src/federation/peers'
import { cleanPeerText, receiveInvitation } from '../src/federation/replica'
import { flushQueuedShares } from '../src/federation/sharing'
import { type Net, twoInstances, type User, userOn } from './federation-helpers'

const fed = '/api/cloudwarden/federation'

let net: Net
let adminA: User
let adminB: User
let ownerB: User
let mgrB: User
let carol: User
let alice: User
let orgB: string
let colB: string
let fpA: string
let fpB: string
let idA: string

const peersOf = async (admin: User) => (await admin.json(`${fed}/admin/peers`)).data as any[]
const dbB = () => net.B.env.DB as D1Database
const dbA = () => net.A.env.DB as D1Database
const peerOnB = async () => (await peersOf(adminB))[0]
const ext = (col: string, rest = '') =>
  `${fed}/organizations/${orgB}/collections/${col}/external-access${rest}`
const events = async (admin: User) =>
  ((await admin.json(`${fed}/admin/events`)).data as { name: string; peer: string }[]).map(
    (e) => e.name,
  )

async function unpairAll() {
  for (const p of await peersOf(adminA)) await adminA.call(`${fed}/admin/peers/${p.id}`, 'DELETE')
  for (const p of await peersOf(adminB)) await adminB.call(`${fed}/admin/peers/${p.id}`, 'DELETE')
  await dbB().prepare('DELETE FROM federation_removed_domains').run()
  await dbA().prepare('DELETE FROM federation_removed_domains').run()
}

/** A (the sharer) adds and approves B: B trusts A automatically, for incoming traffic only. */
async function sharerPairs() {
  // Many pairings in one test file would meet the per-minute pairing limits.
  await dbB().prepare("DELETE FROM admin_rate_limits WHERE key LIKE 'fedpair%'").run()
  const added = await adminA.json(`${fed}/admin/peers`, 'POST', { domain: net.B.domain })
  return {
    id: added.id as string,
    res: await adminA.call(`${fed}/admin/peers/${added.id}/approve`, 'POST', { fingerprint: fpB }),
  }
}

/** A real Peer row for B's view of an instance, as the signed routes would load it. */
const fakePeer = async (domain: string, approved: boolean): Promise<Peer> => {
  const uuid = crypto.randomUUID()
  await dbB()
    .prepare(
      "INSERT INTO federation_peers (uuid, instance_id, domain, public_key, fingerprint, protocol_version, status, local_approved, remote_approved, accepted_automatically, approved_by, incoming, created_at, updated_at) VALUES (?1, ?1, ?2, 'k', 'f', 1, 'active', 1, 1, ?3, ?4, 1, 0, 0)",
    )
    .bind(uuid, domain, approved ? 0 : 1, approved ? null : null)
    .run()
  return (await getPeer(net.B.env as never, uuid)) as Peer
}

beforeAll(async () => {
  net = await twoInstances()
  adminA = await userOn(net.A, 'admin-a@example.com', { verified: true })
  adminB = await userOn(net.B, 'admin-b@example.org', { verified: true })
  ownerB = await userOn(net.B, 'owner-b@example.org')
  mgrB = await userOn(net.B, 'mgr-b@example.org')
  carol = await userOn(net.A, 'carol@example.com', { publicKey: 'carol-public-key' })
  alice = await userOn(net.B, 'alice@example.org', { publicKey: 'alice-public-key' })
  const org = await ownerB.json('/api/organizations', 'POST', {
    name: 'Beta',
    billingEmail: 'billing@example.org',
    key: '4.betaKey',
    keys: { publicKey: 'betaPublic', encryptedPrivateKey: '2.betaPrivate' },
    collectionName: '2.betaCollection',
    planType: 0,
  })
  orgB = org.id
  colB = (await ownerB.json('/api/sync')).collections[0].id
  const d = async (i: Net['A']) =>
    (await (await i.fetch('/.well-known/cloudwarden-federation')).json()) as any
  fpA = (await d(net.A)).fingerprint
  fpB = (await d(net.B)).fingerprint
  idA = (await d(net.A)).instanceId
}, 120_000)

describe('an automatically trusted peer is inbound only', { timeout: 180_000 }, () => {
  let wsOnB: string
  let queuedId: string

  it('is trusted for incoming traffic but not for sending, until an admin approves it', async () => {
    const { res } = await sharerPairs()
    expect(res.status).toBe(200)
    const onB = await peerOnB()
    expect(onB).toMatchObject({
      domain: net.A.domain,
      active: true,
      acceptedAutomatically: true,
      inboundOnly: true,
      incoming: true,
      approvedByEmail: null,
    })
    wsOnB = onB.id
    // Not offered to organisation admins for inviting, and refused by the invite endpoint.
    expect((await ownerB.json(`${fed}/status`)).peers).toEqual([])
    const invite = await ownerB.call(`${fed}/organizations/${orgB}/members`, 'POST', {
      email: carol.email,
      peerId: wsOnB,
      type: 2,
      collections: [],
    })
    expect(invite.status).toBe(400)
    expect(
      await dbA().prepare('SELECT count(*) AS n FROM federation_invitations').first<any>(),
    ).toEqual({ n: 0 })
  })

  it('shows it to collection managers as waiting for an admin, and queues shares behind it', async () => {
    const st = await ownerB.json(ext(colB))
    expect(st.workspaces).toEqual([
      expect.objectContaining({
        id: wsOnB,
        state: 'awaitingInstanceAdmin',
        active: false,
        inboundOnly: true,
      }),
    ])
    net.log.length = 0
    const res = await ownerB.json(ext(colB), 'POST', { workspaceId: wsOnB, emails: [carol.email] })
    expect(res.data[0]).toMatchObject({ ok: true, result: 'queued' })
    queuedId = res.data[0].id
    expect(net.log.filter((l) => l.includes('/federation/v1/invitations'))).toEqual([])
    expect(
      await dbA().prepare('SELECT count(*) AS n FROM federation_invitations').first<any>(),
    ).toEqual({ n: 0 })
    // The admin sees what waits behind it.
    expect((await peersOf(adminB))[0].queued).toEqual([
      expect.objectContaining({ organizationName: 'Beta', people: 1, collections: 1 }),
    ])
    // A non-admin cannot approve it.
    expect(
      (await ownerB.call(`${fed}/admin/peers/${wsOnB}/approve`, 'POST', { fingerprint: fpA }))
        .status,
    ).toBe(403)
  })

  it('needs the fingerprint to approve, then sends what was queued', async () => {
    const wrong = await adminB.call(`${fed}/admin/peers/${wsOnB}/approve`, 'POST', {
      fingerprint: '0000',
    })
    expect(wrong.status).toBe(400)
    const ap = await adminB.json(`${fed}/admin/peers/${wsOnB}/approve`, 'POST', {
      fingerprint: fpA,
    })
    expect(ap).toMatchObject({ active: true, inboundOnly: false })
    await net.flush()
    expect(await ownerB.json(ext(colB))).toMatchObject({ queued: [] })
    const sent = await dbA()
      .prepare('SELECT count(*) AS n FROM federation_invitations')
      .first<any>()
    expect(sent.n).toBe(1)
    expect((await peersOf(adminB))[0]).toMatchObject({
      inboundOnly: false,
      approvedByEmail: adminB.email,
    })
    expect((await ownerB.json(`${fed}/status`)).peers).toEqual([
      expect.objectContaining({ id: wsOnB }),
    ])
    expect(queuedId).toBeTruthy()
  })
})

describe('invitations from workspaces nobody approved', { timeout: 180_000 }, () => {
  const org = () => crypto.randomUUID()
  const mem = () => crypto.randomUUID()
  let auto: Peer
  const run = async (peer: Peer, body: any) => {
    const work: Promise<unknown>[] = []
    const out = await receiveInvitation(net.B.env as never, peer, body, (w) => void work.push(w))
    return { out, work }
  }
  const pendingFor = async (u: User) =>
    (await alice.json(`${fed}/invitations`)).data.length + (u === alice ? 0 : 0)

  beforeAll(async () => {
    await unpairAll()
    await sharerPairs()
    auto = (await getPeer(net.B.env as never, (await peerOnB()).id)) as Peer
    await dbB().prepare('DELETE FROM federation_invitations').run()
  })

  it('answers at once, the same for known and unknown addresses, and does the work afterwards', async () => {
    const base = { organizationName: 'Org' }
    const known = await run(auto, {
      ...base,
      memberId: mem(),
      organizationId: org(),
      email: alice.email,
    })
    const unknown = await run(auto, {
      ...base,
      memberId: mem(),
      organizationId: org(),
      email: 'ghost@example.org',
    })
    expect(known.out).toEqual({ status: 'pending' })
    expect(unknown.out).toEqual(known.out)
    // Nothing was stored yet: the lookup and the inserts are deferred.
    expect(known.work).toHaveLength(1)
    expect(unknown.work).toHaveLength(1)
    await Promise.all([...known.work, ...unknown.work])
    expect(await pendingFor(alice)).toBe(1)
    await dbB().prepare('DELETE FROM federation_invitations').run()
  })

  it('sends no mail, labels the invitation unverified and cleans what the peer sent', async () => {
    const before = net.B.mail.sent.length
    const evil = `Acme\u0007‮   Bank\n${'x'.repeat(300)}`
    const { work } = await run(auto, {
      memberId: mem(),
      organizationId: org(),
      organizationName: evil,
      inviterEmail: 'not an email <script>',
      email: alice.email,
    })
    await Promise.all(work)
    expect(net.B.mail.sent.length).toBe(before)
    const [inv] = (await alice.json(`${fed}/invitations`)).data
    expect(inv.verified).toBe(false)
    expect(inv.organizationName.length).toBeLessThanOrEqual(100)
    // biome-ignore lint/suspicious/noControlCharactersInRegex: asserting they are gone
    expect(inv.organizationName).not.toMatch(/[\u0000-\u001f‮]/)
    expect(inv.organizationName.startsWith('Acme Bank')).toBe(true)
    expect(inv.inviterEmail).toBeNull()
    expect(cleanPeerText('a\tb\u0000c')).toBe('a b c')
    await dbB().prepare('DELETE FROM federation_invitations').run()
  })

  it('caps pending invitations per user and per peer', async () => {
    const all: Promise<unknown>[] = []
    for (let i = 0; i < 12; i++) {
      const r = await run(auto, {
        memberId: mem(),
        organizationId: org(),
        organizationName: `O${i}`,
        email: alice.email,
      })
      all.push(...r.work)
    }
    await Promise.all(all)
    expect(await pendingFor(alice)).toBe(10)
    // Per peer: fill it with rows of another user, then one more is refused.
    await dbB().prepare('DELETE FROM federation_invitations').run()
    for (let i = 0; i < 200; i++) {
      await dbB()
        .prepare(
          "INSERT INTO federation_invitations (uuid, peer_uuid, remote_member_uuid, organization_uuid, organization_name, user_uuid, status, created_at, updated_at) VALUES (?1, ?2, ?1, ?1, 'x', ?3, 'pending', 0, 0)",
        )
        .bind(crypto.randomUUID(), auto.uuid, mgrB.uuid)
        .run()
    }
    const r = await run(auto, {
      memberId: mem(),
      organizationId: org(),
      organizationName: 'late',
      email: alice.email,
    })
    await Promise.all(r.work)
    expect(await pendingFor(alice)).toBe(0)
    await dbB().prepare('DELETE FROM federation_invitations').run()
  })

  it('does not let an unapproved peer claim an organisation id, and yields to an approved one', async () => {
    const trusted = await fakePeer('approved.example.net', true)
    // fakePeer(…, true) means "approved": not automatic.
    expect(trusted.acceptedAutomatically).toBe(false)
    const X = org()
    const Y = org()
    // The approved peer claims X first: the unapproved one cannot take it.
    await Promise.all(
      (
        await run(trusted, {
          memberId: mem(),
          organizationId: X,
          organizationName: 'X',
          email: alice.email,
        })
      ).work,
    )
    await Promise.all(
      (
        await run(auto, {
          memberId: mem(),
          organizationId: X,
          organizationName: 'X2',
          email: alice.email,
        })
      ).work,
    )
    let rows = (await alice.json(`${fed}/invitations`)).data
    expect(rows.map((r: any) => r.organizationName)).toEqual(['X'])
    // The unapproved peer claims Y first: an approved peer's invitation replaces it.
    await Promise.all(
      (
        await run(auto, {
          memberId: mem(),
          organizationId: Y,
          organizationName: 'Y-unapproved',
          email: alice.email,
        })
      ).work,
    )
    await Promise.all(
      (
        await run(trusted, {
          memberId: mem(),
          organizationId: Y,
          organizationName: 'Y-approved',
          email: alice.email,
        })
      ).work,
    )
    rows = (await alice.json(`${fed}/invitations`)).data
    expect(rows.map((r: any) => r.organizationName).sort()).toEqual(['X', 'Y-approved'])
    // And mail is sent only for the approved peer.
    expect(net.B.mail.sent.some((m) => m.to === alice.email && /Y-approved/.test(m.subject))).toBe(
      true,
    )
    expect(net.B.mail.sent.some((m) => /Y-unapproved|X2/.test(m.subject))).toBe(false)
    await dbB().prepare('DELETE FROM federation_invitations').run()
    await dbB().prepare("DELETE FROM federation_peers WHERE domain = 'approved.example.net'").run()
  })
})

describe('block list, removal and caps', { timeout: 180_000 }, () => {
  it('blocks by suffix, instance and fingerprint, and removes matching peers', async () => {
    await unpairAll()
    await sharerPairs()
    expect(await peersOf(adminB)).toHaveLength(1)
    const bad = await adminB.call(`${fed}/admin/blocked`, 'POST', { domain: 'not a rule' })
    expect(bad.status).toBe(400)
    const rules = ['*.example.com', `instance:${idA}`, `fp:${fpA.replace(/:/g, '')}`]
    for (const rule of rules) {
      const res = await adminB.json(`${fed}/admin/blocked`, 'POST', { domain: rule })
      expect(res.blockedDomains.map((b: any) => b.domain)).toContain(rule.toLowerCase())
      // The matching peer was removed with the rule; the sharer's request is refused.
      expect(await peersOf(adminB)).toHaveLength(0)
      const again = await sharerPairs()
      expect(again.res.status).toBeGreaterThanOrEqual(400)
      expect(await peersOf(adminB)).toHaveLength(0)
      for (const p of await peersOf(adminA))
        await adminA.call(`${fed}/admin/peers/${p.id}`, 'DELETE')
      await adminB.call(`${fed}/admin/blocked/${encodeURIComponent(rule)}`, 'DELETE')
      expect((await adminB.json(`${fed}/admin/settings`)).blockedDomains).toEqual([])
      await dbB().prepare('DELETE FROM federation_removed_domains').run()
      await sharerPairs()
      expect(await peersOf(adminB)).toHaveLength(1)
    }
    expect(await events(adminB)).toContain('PeerBlocked')
  })

  it('checks blocks on every signed route, not only on pairing', async () => {
    const [p] = await peersOf(adminB)
    expect(p.active).toBe(true)
    await dbB()
      .prepare(
        "INSERT INTO federation_blocked_domains (domain, kind, created_at) VALUES ('*.example.com', 'domain', 0)",
      )
      .run()
    const peer = (await getPeer(net.A.env as never, (await peersOf(adminA))[0].id)) as Peer
    const { peerFetch } = await import('../src/federation/peers')
    const res = await peerFetch(net.A.env as never, peer, '/federation/v1/ping', { body: {} })
    expect(res.status).toBe(403)
    await dbB().prepare('DELETE FROM federation_blocked_domains').run()
  })

  it('blocks first when removing with a block, and remembers removals without one', async () => {
    const [p] = await peersOf(adminB)
    expect((await adminB.call(`${fed}/admin/peers/${p.id}?block=true`, 'DELETE')).status).toBe(200)
    const blocked = (await adminB.json(`${fed}/admin/settings`)).blockedDomains
    expect(blocked).toEqual([expect.objectContaining({ domain: net.A.domain, kind: 'domain' })])
    await adminB.call(`${fed}/admin/blocked/${net.A.domain}`, 'DELETE')
    await unpairAll()
    // Removed without a block: the next incoming request is no longer trusted automatically.
    await sharerPairs()
    const [first] = await peersOf(adminB)
    expect(first.acceptedAutomatically).toBe(true)
    await adminB.call(`${fed}/admin/peers/${first.id}`, 'DELETE')
    for (const x of await peersOf(adminA)) await adminA.call(`${fed}/admin/peers/${x.id}`, 'DELETE')
    await sharerPairs()
    const [second] = await peersOf(adminB)
    expect(second).toMatchObject({
      status: 'pending',
      active: false,
      acceptedAutomatically: false,
      incoming: true,
    })
    // Approving it clears the memory.
    await adminB.json(`${fed}/admin/peers/${second.id}/approve`, 'POST', { fingerprint: fpA })
    expect(
      (await dbB().prepare('SELECT count(*) AS n FROM federation_removed_domains').first<any>()).n,
    ).toBe(0)
    expect((await peersOf(adminB))[0]).toMatchObject({
      active: true,
      approvedByEmail: adminB.email,
    })
  })

  it('drops unapproved incoming requests after seven days', async () => {
    await unpairAll()
    await adminB.json(`${fed}/admin/settings`, 'PUT', { requireIncomingApproval: true })
    await sharerPairs()
    expect((await peersOf(adminB))[0].status).toBe('pending')
    await dbB()
      .prepare('UPDATE federation_peers SET created_at = ?1')
      .bind(Date.now() - 8 * 86_400_000)
      .run()
    expect(await peersOf(adminB)).toHaveLength(0)
    await adminB.json(`${fed}/admin/settings`, 'PUT', { requireIncomingApproval: false })
  })

  it('keeps separate caps for admin-added peers, automatic peers and waiting incoming requests', async () => {
    await unpairAll()
    const row = (i: number, kind: 'added' | 'pending' | 'auto') =>
      dbB()
        .prepare(
          "INSERT INTO federation_peers (uuid, instance_id, domain, public_key, fingerprint, protocol_version, status, local_approved, remote_approved, accepted_automatically, incoming, created_at, updated_at) VALUES (?1, ?1, ?2, 'k', 'f', 1, ?3, ?4, 1, ?5, ?6, 0, 0)",
        )
        .bind(
          crypto.randomUUID(),
          `${kind}${i}.example.net`,
          kind === 'auto' ? 'active' : 'pending',
          kind === 'auto' ? 1 : 0,
          kind === 'auto' ? 1 : 0,
          kind === 'added' ? 0 : 1,
        )
        .run()
    // 20 peers an admin added do not count against incoming requests.
    for (let i = 0; i < 20; i++) await row(i, 'added')
    await sharerPairs()
    expect((await peersOf(adminB)).find((p) => p.domain === net.A.domain)).toMatchObject({
      active: true,
      acceptedAutomatically: true,
    })
    await unpairAll()
    // 25 automatic peers: further requests wait, and 20 waiting requests close the door.
    for (let i = 0; i < 25; i++) await row(i, 'auto')
    await sharerPairs()
    expect((await peersOf(adminB)).find((p) => p.domain === net.A.domain)).toMatchObject({
      status: 'pending',
    })
    await dbB().prepare("DELETE FROM federation_peers WHERE domain LIKE '%.example.net'").run()
    await unpairAll()
    await adminB.json(`${fed}/admin/settings`, 'PUT', { requireIncomingApproval: true })
    for (let i = 0; i < 20; i++) await row(i, 'pending')
    const full = await sharerPairs()
    // A's approval reaches B's /pair, which refuses: too many requests wait.
    expect(full.res.status).toBeGreaterThanOrEqual(400)
    await dbB().prepare("DELETE FROM federation_peers WHERE domain LIKE '%.example.net'").run()
    await adminB.json(`${fed}/admin/settings`, 'PUT', { requireIncomingApproval: false })
  })

  it('lists automatically trusted peers for review when approval becomes required', async () => {
    await unpairAll()
    await sharerPairs()
    const res = await adminB.json(`${fed}/admin/settings`, 'PUT', { requireIncomingApproval: true })
    expect(res).toMatchObject({ requireIncomingApproval: true, reviewPeers: 1 })
    expect((await peersOf(adminB))[0]).toMatchObject({
      inboundOnly: true,
      acceptedAutomatically: true,
    })
    await adminB.json(`${fed}/admin/settings`, 'PUT', { requireIncomingApproval: false })
  })
})

describe('queued shares that fail for a passing reason', { timeout: 180_000 }, () => {
  it('stay as retry, attributed to the requester with no client address, and are sent later', async () => {
    await unpairAll()
    // B is the sharer here: its admin approved A, and a share to carol is queued by hand.
    const wsAdded = await adminB.json(`${fed}/admin/peers`, 'POST', { domain: net.A.domain })
    await adminB.json(`${fed}/admin/peers/${wsAdded.id}/approve`, 'POST', { fingerprint: fpA })
    await net.flush()
    const queuedId = crypto.randomUUID()
    await dbB()
      .prepare(
        "INSERT INTO federation_queued_shares (uuid, peer_uuid, peer_domain, organization_uuid, collection_uuid, email, requested_by, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', ?8, ?8)",
      )
      .bind(queuedId, wsAdded.id, net.A.domain, orgB, colB, carol.email, ownerB.uuid, Date.now())
      .run()
    const peer = (await getPeer(net.B.env as never, wsAdded.id)) as Peer
    const ctx = { env: net.B.env, var: {}, req: { header: () => 'should-not-be-read' } } as never
    // The peer does not resolve for a moment.
    net.dns.set(net.A.domain, { A: [], AAAA: [] })
    await flushQueuedShares(ctx, peer)
    const row = await dbB()
      .prepare('SELECT status, attempts FROM federation_queued_shares WHERE uuid = ?1')
      .bind(queuedId)
      .first<any>()
    expect(row).toEqual({ status: 'retry', attempts: 1 })
    const ev = await dbB()
      .prepare('SELECT acting_user_uuid AS a, ip_address AS ip FROM events WHERE event_type = 9130')
      .first<any>()
    expect(ev.a).toBe(ownerB.uuid)
    expect(ev.ip).toContain('peer:')
    expect(JSON.stringify(ev)).not.toContain('should-not-be-read')
    // Back up: the next look of an admin retries it and the invitation is sent.
    net.dns.delete(net.A.domain)
    await adminB.json(`${fed}/admin/peers`)
    await net.flush()
    expect(
      await dbB()
        .prepare('SELECT count(*) AS n FROM federation_queued_shares WHERE uuid = ?1')
        .bind(queuedId)
        .first<any>(),
    ).toEqual({ n: 0 })
    expect(
      (await dbA().prepare('SELECT count(*) AS n FROM federation_invitations').first<any>()).n,
    ).toBe(1)
  })
})
