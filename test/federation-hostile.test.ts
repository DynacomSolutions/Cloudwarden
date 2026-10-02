// A hostile hosting peer (TASKS #304 review): whatever it sends, the serving side keeps only the
// organisations the user accepted from it, rebuilt from allowlists.
import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it } from 'vitest'
import { acceptFederatedInvite } from '../src/federation/hosting'
import {
  federatedProfileOrgs,
  federatedPush,
  federatedSyncData,
  receiveInvitation,
  syncUserFromPeer,
} from '../src/federation/replica'

const EVIL = 'evil.example.org'
const id = () => crypto.randomUUID()
const X = id()
const Y = id()
const C1 = id()
const K1 = id()
const K2 = id()
const K3 = id()
const Z = id()
const P1 = id()
const P2 = id()
const P3 = id()
let LOCAL: string
const requested: string[] = []

const json = (v: unknown) => Response.json(v)
const evil = {
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url)
    if (url.hostname === 'cloudflare-dns.com') {
      return json({ Status: 0, Answer: [{ type: 1, data: [8, 8, 8, 8].join('.') }] })
    }
    requested.push(url.pathname)
    const p = url.pathname
    if (p.endsWith('/organizations')) {
      return json({
        organizations: [X, LOCAL, Y, 'not-a-uuid'].map((o) => ({
          id: o,
          status: 2,
          revisionDate: 1,
        })),
      })
    }
    if (p.endsWith(`/organizations/${X}/index`)) {
      return json({
        profile: {
          id: LOCAL,
          userId: id(),
          name: 'Evil',
          key: '4.k',
          status: 2,
          type: 2,
          keyConnectorEnabled: true,
          keyConnectorUrl: 'https://evil.example.org/kc',
          ssoBound: true,
          useSso: true,
          userIsManagedByOrganization: true,
          resetPasswordEnrolled: true,
          permissions: { manageResetPassword: true, accessEventLogs: true },
        },
        collections: [{ id: C1, organizationId: LOCAL, name: '2.c', readOnly: false }],
        policies: [
          { id: P1, organizationId: X, type: 4, enabled: true },
          { id: P2, organizationId: LOCAL, type: 1, enabled: true },
          { id: P3, organizationId: X, type: 1, enabled: true, data: { minLength: 12 } },
        ],
        ciphers: [
          { id: K1, digest: 'a' },
          { id: K2, digest: 'b' },
          { id: Z, digest: 'c' },
        ],
      })
    }
    if (p.endsWith(`/organizations/${X}/ciphers`)) {
      return json({
        ciphers: [
          { id: K1, digest: 'a', json: { id: K1, organizationId: X, collectionIds: [C1, id()] } },
          { id: K2, digest: 'b', json: { id: id(), organizationId: X } },
          { id: K3, digest: 'd', json: { id: K3, organizationId: X } },
          { id: Z, digest: 'c', json: { id: Z, organizationId: X } },
        ],
      })
    }
    return json({ message: 'unexpected' })
  },
}

const benv = {
  ...env,
  DOMAIN: 'https://serving.example.com',
  FEDERATION_ENABLED: 'true',
  FEDERATION_TRANSPORT: evil,
} as never
const db = env.DB
let user: any
let peerUuid: string

beforeAll(async () => {
  const { default: app } = await import('../src/index')
  const reg = await app.fetch(
    new Request('https://serving.example.com/identity/accounts/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'victim@example.com',
        name: 'v',
        masterPasswordHash: 'h',
        key: '2.k',
        keys: { publicKey: 'pk', encryptedPrivateKey: '2.pk' },
        kdf: 0,
        kdfIterations: 600000,
      }),
    }),
    benv,
  )
  expect(reg.status).toBe(200)
  user = await db.prepare("SELECT * FROM users WHERE email = 'victim@example.com'").first()
  user = { ...user, uuid: user.uuid, publicKey: user.public_key }
  LOCAL = id()
  await db
    .prepare(
      "INSERT INTO organizations (uuid, name, billing_email, created_at, updated_at) VALUES (?1, 'Local', 'b@example.com', 0, 0)",
    )
    .bind(LOCAL)
    .run()
  const peer = (uuid: string, domain: string) =>
    db
      .prepare(
        "INSERT INTO federation_peers (uuid, instance_id, domain, public_key, fingerprint, protocol_version, status, local_approved, remote_approved, created_at, updated_at) VALUES (?1, ?1, ?2, 'k', 'f', 1, 'active', 1, 1, 0, 0)",
      )
      .bind(uuid, domain)
      .run()
  peerUuid = id()
  const other = id()
  await peer(peerUuid, EVIL)
  await peer(other, 'other.example.org')
  const invite = (peerId: string, org: string) =>
    db
      .prepare(
        "INSERT INTO federation_invitations (uuid, peer_uuid, remote_member_uuid, organization_uuid, organization_name, user_uuid, status, created_at, updated_at) VALUES (?1, ?2, ?1, ?3, 'n', ?4, 'accepted', 0, 0)",
      )
      .bind(id(), peerId, org, user.uuid)
      .run()
  // The user accepted X from the evil peer and Y from another peer; the evil peer also claims
  // an invitation for the local organisation, which must not matter.
  await invite(peerUuid, X)
  await invite(peerUuid, LOCAL)
  await invite(other, Y)
  await db
    .prepare(
      "INSERT INTO federation_replica_orgs (user_uuid, organization_uuid, peer_uuid, profile_json, collections_json, policies_json, revision_date, synced_at) VALUES (?1, ?2, ?3, ?4, '[]', '[]', 0, 0)",
    )
    .bind(user.uuid, Y, other, JSON.stringify({ id: Y, name: 'Y' }))
    .run()
  await db
    .prepare(
      "INSERT INTO federation_replica_ciphers (user_uuid, cipher_uuid, organization_uuid, json, digest, updated_at) VALUES (?1, ?2, ?3, ?4, 'z', 0)",
    )
    .bind(user.uuid, Z, Y, JSON.stringify({ id: Z, organizationId: Y, name: 'owned by Y' }))
    .run()
})

describe('hostile hosting peer', () => {
  it('keeps only bound organisations and rebuilds everything from allowlists', async () => {
    const peer = await db
      .prepare('SELECT * FROM federation_peers WHERE uuid = ?1')
      .bind(peerUuid)
      .first<any>()
    await syncUserFromPeer(benv, user, {
      ...peer,
      uuid: peer.uuid,
      domain: peer.domain,
      status: 'active',
      localApproved: true,
      remoteApproved: true,
    })
    // Neither the local organisation nor another peer's organisation was even asked for.
    expect(requested.some((p) => p.includes(LOCAL) || p.includes(Y))).toBe(false)

    const orgs = (await federatedProfileOrgs(benv, user.uuid)) as any[]
    const x = orgs.find((o) => o.id === X)
    expect(orgs.map((o) => o.id).sort()).toEqual([X, Y].sort())
    expect(x).toMatchObject({
      id: X,
      userId: user.uuid,
      keyConnectorEnabled: false,
      keyConnectorUrl: null,
      ssoBound: false,
      useSso: false,
      userIsManagedByOrganization: false,
      resetPasswordEnrolled: false,
    })
    expect(x.permissions.manageResetPassword).toBe(false)
    expect(x.permissions.accessEventLogs).toBe(true)
    expect(orgs.find((o) => o.id === Y).name).toBe('Y')

    const data = (await federatedSyncData(benv, user.uuid)) as any
    expect(data.policies.map((p: any) => p.id)).toEqual([P3])
    expect(data.collections).toEqual([expect.objectContaining({ id: C1, organizationId: X })])
    const k1 = data.ciphers.find((c: any) => c.id === K1)
    expect(k1.collectionIds).toEqual([C1])
    // Mismatched, unrequested and foreign ids were dropped; Y's item is untouched.
    expect(data.ciphers.find((c: any) => c.id === K2)).toBeUndefined()
    expect(data.ciphers.find((c: any) => c.id === K3)).toBeUndefined()
    expect(data.ciphers.find((c: any) => c.id === Z)).toMatchObject({
      organizationId: Y,
      name: 'owned by Y',
    })
    const yRow = await db
      .prepare('SELECT peer_uuid FROM federation_replica_orgs WHERE organization_uuid = ?1')
      .bind(Y)
      .first<any>()
    expect(yRow.peer_uuid).not.toBe(peerUuid)
  })

  it('turns peer events into sync pushes only, with rebuilt payloads', () => {
    expect(federatedPush({ type: 11, payload: { UserId: 'x' } }, user.uuid)).toBeNull()
    expect(federatedPush({ type: 15, payload: { Id: X } }, user.uuid)).toBeNull()
    expect(
      federatedPush({ type: 0, payload: { Id: 'bad', OrganizationId: X } }, user.uuid),
    ).toBeNull()
    const ok = federatedPush(
      { type: 0, payload: { Id: K1, OrganizationId: X, CollectionIds: [C1, 'x'], Extra: 1 } },
      user.uuid,
    )
    expect(ok?.payload).toEqual(
      expect.objectContaining({
        Id: K1,
        UserId: user.uuid,
        OrganizationId: X,
        CollectionIds: [C1],
      }),
    )
    expect(ok?.payload).not.toHaveProperty('Extra')
    expect(federatedPush({ type: 5, payload: { UserId: 'x' } }, user.uuid)?.payload.UserId).toBe(
      user.uuid,
    )
  })

  it('answers invitations with pending without revealing accounts or taking local ids', async () => {
    const peer = await db
      .prepare('SELECT * FROM federation_peers WHERE uuid = ?1')
      .bind(peerUuid)
      .first<any>()
    const p = { ...peer, uuid: peer.uuid, domain: peer.domain }
    const before = await db.prepare('SELECT count(*) AS n FROM federation_invitations').first<any>()
    const base = { memberId: id(), organizationName: 'n' }
    expect(
      await receiveInvitation(benv, p, {
        ...base,
        organizationId: id(),
        email: 'nobody@example.com',
      }),
    ).toEqual({ status: 'pending' })
    expect(
      await receiveInvitation(benv, p, {
        ...base,
        memberId: id(),
        organizationId: LOCAL,
        email: 'victim@example.com',
      }),
    ).toEqual({ status: 'pending' })
    const after = await db.prepare('SELECT count(*) AS n FROM federation_invitations').first<any>()
    expect(after.n).toBe(before.n)
  })
})

describe('stand-in key change on a new acceptance', () => {
  it('moves other confirmed memberships back to accepted', async () => {
    const peer = await db
      .prepare('SELECT * FROM federation_peers WHERE uuid = ?1')
      .bind(peerUuid)
      .first<any>()
    const p = { ...peer, uuid: peer.uuid, domain: peer.domain }
    const org1 = id()
    const org2 = id()
    for (const o of [org1, org2]) {
      await db
        .prepare(
          "INSERT INTO organizations (uuid, name, billing_email, created_at, updated_at) VALUES (?1, 'O', 'b@example.com', 0, 0)",
        )
        .bind(o)
        .run()
    }
    const member = async (org: string) => {
      const m = id()
      await db
        .prepare(
          "INSERT INTO users_organizations (uuid, organization_uuid, email, access_all, akey, status, atype, access_secrets_manager, created_at, updated_at) VALUES (?1, ?2, 'remote@example.org', 0, '', 0, 2, 0, 0, 0)",
        )
        .bind(m, org)
        .run()
      await db
        .prepare(
          "INSERT INTO federation_members (organization_user_uuid, peer_uuid, remote_email, created_at) VALUES (?1, ?2, 'remote@example.org', 0)",
        )
        .bind(m, peerUuid)
        .run()
      return m
    }
    const remote = id()
    const m1 = await member(org1)
    await acceptFederatedInvite(benv, p, m1, {
      userId: remote,
      email: 'remote@example.org',
      publicKey: 'key-one-key-one-',
    })
    await db
      .prepare("UPDATE users_organizations SET status = 2, akey = '4.k' WHERE uuid = ?1")
      .bind(m1)
      .run()
    const m2 = await member(org2)
    await acceptFederatedInvite(benv, p, m2, {
      userId: remote,
      email: 'remote@example.org',
      publicKey: 'key-two-key-two-',
    })
    const row = await db
      .prepare('SELECT status, akey FROM users_organizations WHERE uuid = ?1')
      .bind(m1)
      .first<any>()
    expect(row).toEqual({ status: 1, akey: '' })
  })
})
