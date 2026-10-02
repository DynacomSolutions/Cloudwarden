// Federated organisations between two instances (TASKS #308): pairing, invitation, acceptance,
// confirmation, replica sync, forwarded writes, push propagation, revocation and unpairing.
import { beforeAll, describe, expect, it } from 'vitest'
import { loadIdentity } from '../src/federation/identity'
import { signRequest } from '../src/federation/signature'
import { cipherBody, type Net, pair, twoInstances, type User, userOn } from './federation-helpers'

let net: Net
let adminA: User
let adminB: User
let owner: User
let alice: User
let orgId: string
let collectionId: string
let memberId: string
let peerOnA: string
let peerOnB: string

const fed = '/api/cloudwarden/federation'

async function syncOf(u: User) {
  return u.json('/api/sync')
}

beforeAll(async () => {
  net = await twoInstances()
  adminA = await userOn(net.A, 'admin-a@example.com', { verified: true })
  adminB = await userOn(net.B, 'admin-b@example.org', { verified: true })
  owner = await userOn(net.A, 'owner@example.com')
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
  collectionId = (await syncOf(owner)).collections[0].id
}, 120_000)

describe('federation between two instances', { timeout: 120_000 }, () => {
  it('publishes a descriptor and pairs only after both admins approve the fingerprint', async () => {
    const d = await (await net.A.fetch('/.well-known/cloudwarden-federation')).json<any>()
    expect(d).toMatchObject({
      protocol: 'cloudwarden-federation',
      version: 1,
      domain: 'vault.example.com',
      algorithm: 'ed25519',
    })
    expect(d.fingerprint).toMatch(/^([0-9A-F]{4}:){15}[0-9A-F]{4}$/)

    // Only instance admins manage peers.
    const denied = await owner.call(`${fed}/admin/peers`, 'POST', { domain: net.B.domain })
    expect(denied.status).toBe(403)

    // A wrong fingerprint is refused.
    const added = await adminA.json(`${fed}/admin/peers`, 'POST', { domain: net.B.domain })
    expect(added.status).toBe('pending')
    const wrong = await adminA.call(`${fed}/admin/peers/${added.id}/approve`, 'POST', {
      fingerprint: '0000',
    })
    expect(wrong.status).toBe(400)
    await adminA.call(`${fed}/admin/peers/${added.id}`, 'DELETE')

    ;({ peerOnA, peerOnB } = await pair(net, adminA, adminB))
    const peersA = await adminA.json(`${fed}/admin/peers`)
    const peersB = await adminB.json(`${fed}/admin/peers`)
    expect(peersA.data[0]).toMatchObject({ domain: net.B.domain, status: 'active', active: true })
    expect(peersB.data[0]).toMatchObject({ domain: net.A.domain, status: 'active', active: true })
    const check = await adminA.json(`${fed}/admin/peers/${peerOnA}/check`, 'POST')
    expect(check.ok).toBe(true)
  })

  it('invites a user of the peer, who accepts on their own instance', async () => {
    // A user that does not exist on the peer is refused by the peer.
    const nobody = await owner.call(`${fed}/organizations/${orgId}/members`, 'POST', {
      email: 'nobody@example.org',
      peerId: peerOnA,
      type: 2,
      collections: [],
    })
    expect(nobody.status).toBe(404)

    const inv = await owner.json(`${fed}/organizations/${orgId}/members`, 'POST', {
      email: alice.email,
      peerId: peerOnA,
      type: 2,
      collections: [{ id: collectionId, readOnly: false, hidePasswords: false, manage: false }],
    })
    memberId = inv.id
    expect(inv).toMatchObject({ status: 0, peer: net.B.domain })
    expect(net.B.mail.sent.some((m) => m.to === alice.email && /Acme/.test(m.subject))).toBe(true)

    const list = await alice.json(`${fed}/invitations`)
    expect(list.data).toHaveLength(1)
    expect(list.data[0]).toMatchObject({
      organizationName: 'Acme',
      peerDomain: net.A.domain,
      status: 'pending',
    })
    const acc = await alice.call(`${fed}/invitations/${list.data[0].id}/accept`, 'POST')
    expect(acc.status).toBe(200)

    const members = await owner.json(`${fed}/organizations/${orgId}/members`)
    expect(members.data[0]).toMatchObject({
      email: alice.email,
      status: 1,
      userId: alice.uuid,
      peerDomain: net.B.domain,
    })
    // The org shows as accepted (no key yet) in alice's profile on her own instance.
    const profile = await alice.json('/api/accounts/profile')
    expect(profile.organizations).toEqual([
      expect.objectContaining({ id: orgId, status: 1, key: null }),
    ])
  })

  it('confirms with the remote public key and the same user id (fingerprint phrase matches)', async () => {
    const pk = await owner.json(`/api/users/${alice.uuid}/public-key`)
    expect(pk).toMatchObject({ userId: alice.uuid, publicKey: 'alice-public-key-b64' })
    const before = net.log.length
    const conf = await owner.call(`/api/organizations/${orgId}/users/${memberId}/confirm`, 'POST', {
      key: '4.wrapped',
    })
    expect(conf.status).toBe(200)
    await net.flush()
    // The confirmation reached the peer as a signed event.
    expect(net.log.slice(before)).toContain(`POST https://${net.B.domain}/federation/v1/events`)
    const profile = await alice.json('/api/accounts/profile')
    expect(profile.organizations[0]).toMatchObject({
      id: orgId,
      status: 2,
      key: '4.wrapped',
      userId: alice.uuid,
    })
  })

  it('syncs organisation items into the user sync and pushes changes', async () => {
    const created = await owner.json('/api/ciphers/create', 'POST', {
      cipher: cipherBody(orgId, '2.hostedItem'),
      collectionIds: [collectionId],
    })
    await net.flush()
    const s = await syncOf(alice)
    expect(s.collections.map((c: { id: string }) => c.id)).toContain(collectionId)
    const item = s.ciphers.find((c: { id: string }) => c.id === created.id)
    expect(item).toMatchObject({ name: '2.hostedItem', organizationId: orgId, edit: true })
    expect(s.profile.organizations[0].id).toBe(orgId)
  })

  it('forwards writes, keeps folders local and applies them on the hosting side', async () => {
    const folder = await alice.json('/api/folders', 'POST', { name: '2.folder' })
    const ciphers = (await syncOf(alice)).ciphers
    const id = ciphers[0].id
    const put = await alice.call(`/api/ciphers/${id}`, 'PUT', {
      ...cipherBody(orgId, '2.editedOnB'),
      folderId: folder.id,
      lastKnownRevisionDate: ciphers[0].revisionDate,
    })
    expect(put.status).toBe(200)
    expect((await put.json<any>()).folderId).toBe(folder.id)
    // The hosting side holds the new value; the folder never left B.
    const onA = await owner.json(`/api/ciphers/${id}`)
    expect(onA.name).toBe('2.editedOnB')
    expect(onA.folderId).toBeNull()
    const s = await syncOf(alice)
    expect(s.ciphers.find((c: { id: string }) => c.id === id)).toMatchObject({
      name: '2.editedOnB',
      folderId: folder.id,
    })

    // A stale revision is refused by the hosting side.
    const stale = await alice.call(`/api/ciphers/${id}`, 'PUT', {
      ...cipherBody(orgId, '2.stale'),
      lastKnownRevisionDate: '2000-01-01T00:00:00.000Z',
    })
    expect(stale.status).toBe(400)

    // Create through B into the federated organisation.
    const made = await alice.call('/api/ciphers/create', 'POST', {
      cipher: cipherBody(orgId, '2.madeOnB'),
      collectionIds: [collectionId],
    })
    expect(made.status).toBe(200)
    const madeId = (await made.json<any>()).id
    expect((await owner.json(`/api/ciphers/${madeId}`)).name).toBe('2.madeOnB')

    // Bulk soft delete and restore of a federated item.
    expect((await alice.call('/api/ciphers/delete', 'PUT', { ids: [madeId] })).status).toBe(200)
    expect((await owner.json(`/api/ciphers/${madeId}`)).deletedDate).not.toBeNull()
    const restored = await alice.json('/api/ciphers/restore', 'PUT', { ids: [madeId] })
    expect(restored.data[0].id).toBe(madeId)
  })

  it('uploads and downloads attachments of federated items through the own server', async () => {
    const id = (await syncOf(alice)).ciphers.find(
      (c: { organizationId: string }) => c.organizationId === orgId,
    ).id
    const bytes = new Uint8Array(50_000).map((_, i) => i % 251)
    const slot = await alice.json(`/api/ciphers/${id}/attachment/v2`, 'POST', {
      fileName: '2.fname',
      key: '2.fkey',
      fileSize: bytes.length,
    })
    // The client is sent back to its own server, never to the hosting instance.
    expect(slot.url).toBe(`${net.B.base}/api/ciphers/${id}/attachment/${slot.attachmentId}`)
    const fd = new FormData()
    fd.append('data', new Blob([bytes]), '2.enc-name')
    const up = await net.B.fetch(new URL(slot.url).pathname, {
      method: 'POST',
      headers: { authorization: `Bearer ${alice.token}` },
      body: fd,
    })
    expect(up.status).toBe(200)
    const meta = await alice.json(`/api/ciphers/${id}/attachment/${slot.attachmentId}`)
    expect(meta.url.startsWith(`${net.B.base}/federation/attachments/`)).toBe(true)
    const dl = await net.B.fetch(new URL(meta.url).pathname + new URL(meta.url).search)
    expect(dl.status).toBe(200)
    expect(new Uint8Array(await dl.arrayBuffer())).toEqual(bytes)
    // The owner on the hosting side sees the same attachment.
    const ownerItem = (await syncOf(owner)).ciphers.find((c: { id: string }) => c.id === id)
    expect(ownerItem.attachments[0].id).toBe(slot.attachmentId)
    const s = await syncOf(alice)
    expect(s.ciphers.find((c: { id: string }) => c.id === id).attachments[0].url).toContain(
      '/federation/attachments/',
    )
  })

  it('enforces permissions on the hosting side', async () => {
    const upd = await owner.call(`/api/organizations/${orgId}/users/${memberId}`, 'PUT', {
      type: 2,
      accessAll: false,
      collections: [{ id: collectionId, readOnly: true, hidePasswords: false, manage: false }],
      groups: [],
    })
    expect(upd.status).toBe(200)
    await net.flush()
    const s = await syncOf(alice)
    const item = s.ciphers[0]
    expect(item.edit).toBe(false)
    const denied = await alice.call(`/api/ciphers/${item.id}`, 'PUT', {
      ...cipherBody(orgId, '2.denied'),
      lastKnownRevisionDate: item.revisionDate,
    })
    expect(denied.status).toBeGreaterThanOrEqual(400)
    expect((await owner.json(`/api/ciphers/${item.id}`)).name).not.toBe('2.denied')
    const create = await alice.call('/api/ciphers/create', 'POST', {
      cipher: cipherBody(orgId, '2.nope'),
      collectionIds: [collectionId],
    })
    expect(create.status).toBe(403)
  })

  it('asks for a new confirmation when the user replaces their key pair at home', async () => {
    await (net.B.env.DB as D1Database)
      .prepare('UPDATE users SET public_key = ?1 WHERE uuid = ?2')
      .bind('alice-new-public-key', alice.uuid)
      .run()
    await owner.json('/api/ciphers/create', 'POST', {
      cipher: cipherBody(orgId, '2.trigger'),
      collectionIds: [collectionId],
    })
    await net.flush()
    const members = await owner.json(`${fed}/organizations/${orgId}/members`)
    expect(members.data[0].status).toBe(1)
    expect((await owner.json(`/api/users/${alice.uuid}/public-key`)).publicKey).toBe(
      'alice-new-public-key',
    )
    expect((await alice.json('/api/accounts/profile')).organizations[0]).toMatchObject({
      status: 1,
      key: null,
    })
    const conf = await owner.call(`/api/organizations/${orgId}/users/${memberId}/confirm`, 'POST', {
      key: '4.rewrapped',
    })
    expect(conf.status).toBe(200)
    await net.flush()
    expect((await alice.json('/api/accounts/profile')).organizations[0]).toMatchObject({
      status: 2,
      key: '4.rewrapped',
    })
  })

  it('refuses features that are not federated', async () => {
    const r = await alice.call(
      `/api/organizations/${orgId}/users/${memberId}/reset-password-enrollment`,
      'PUT',
      { resetPasswordKey: 'x', masterPasswordHash: 'y' },
    )
    expect(r.status).toBe(400)
    expect((await r.json<any>()).message).toMatch(
      /not available for organisations hosted on another instance/,
    )
  })

  it('hides federated organisations while the peer is suspended', async () => {
    await adminB.call(`${fed}/admin/peers/${peerOnB}/suspend`, 'POST')
    expect((await syncOf(alice)).profile.organizations).toHaveLength(0)
    const read = await alice.call(`/api/organizations/${orgId}/collections`)
    expect(read.status).toBe(503)
    await adminB.call(`${fed}/admin/peers/${peerOnB}/resume`, 'POST')
    expect((await syncOf(alice)).profile.organizations).toHaveLength(1)
  })

  it('purges the replica when the member is removed on the hosting side', async () => {
    const del = await owner.call(`/api/organizations/${orgId}/users/${memberId}`, 'DELETE')
    expect(del.status).toBe(200)
    await net.flush()
    const s = await syncOf(alice)
    expect(s.profile.organizations).toHaveLength(0)
    expect(
      s.ciphers.filter((c: { organizationId: string | null }) => c.organizationId === orgId),
    ).toHaveLength(0)
    expect(s.collections).toHaveLength(0)
  })

  it('rejects unsigned, tampered, replayed and unknown-key requests', async () => {
    const url = `${net.B.base}/federation/v1/ping`
    const unsigned = await net.B.fetch('/federation/v1/ping', { method: 'POST', body: '{}' })
    expect(unsigned.status).toBe(401)

    const id = await loadIdentity(net.A.env as never)
    const body = new TextEncoder().encode('{}')
    const headers = new Headers({ 'content-type': 'application/json' })
    await signRequest('POST', url, headers, body, id.instanceId, id.privateKey)
    const first = await net.B.fetch('/federation/v1/ping', { method: 'POST', headers, body })
    expect(first.status).toBe(200)
    const replay = await net.B.fetch('/federation/v1/ping', { method: 'POST', headers, body })
    expect(replay.status).toBe(401)
    expect((await replay.json<any>()).message).toMatch(/Replayed/)

    const h2 = new Headers({ 'content-type': 'application/json' })
    await signRequest('POST', url, h2, body, id.instanceId, id.privateKey)
    const tampered = await net.B.fetch('/federation/v1/ping', {
      method: 'POST',
      headers: h2,
      body: '{"x":1}',
    })
    expect(tampered.status).toBe(401)

    const h3 = new Headers({ 'content-type': 'application/json' })
    await signRequest('POST', url, h3, body, id.instanceId, id.privateKey, Date.now() - 3600_000)
    const old = await net.B.fetch('/federation/v1/ping', { method: 'POST', headers: h3, body })
    expect(old.status).toBe(401)

    const other = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
      'sign',
      'verify',
    ])) as CryptoKeyPair
    const h4 = new Headers({ 'content-type': 'application/json' })
    await signRequest('POST', url, h4, body, id.instanceId, other.privateKey)
    expect(
      (await net.B.fetch('/federation/v1/ping', { method: 'POST', headers: h4, body })).status,
    ).toBe(401)
    const h5 = new Headers({ 'content-type': 'application/json' })
    await signRequest(
      'POST',
      url,
      h5,
      body,
      '00000000-0000-0000-0000-000000000000',
      other.privateKey,
    )
    expect(
      (await net.B.fetch('/federation/v1/ping', { method: 'POST', headers: h5, body })).status,
    ).toBe(403)
  })

  it('keeps forwarded requests inside the cipher and organisation allowlist', async () => {
    const id = await loadIdentity(net.B.env as never)
    const send = async (path: string, method = 'GET') => {
      const url = `${net.A.base}/federation/v1/members/${alice.uuid}/proxy${path}`
      const headers = new Headers({ 'cloudwarden-federated-user': alice.uuid })
      await signRequest(method, url, headers, new Uint8Array(), id.instanceId, id.privateKey)
      return net.A.fetch(new URL(url).pathname, { method, headers })
    }
    for (const path of [
      '/api/accounts/profile',
      '/api/ciphers/%2e%2e/accounts/profile',
      '/api/ciphers/x%2F..%2F..%2Faccounts/profile',
      '/api/sync',
      '/api/ciphers',
      '/identity/accounts/prelogin',
    ]) {
      const res = await send(path)
      // 401: the runtime normalised the URL, so it no longer matches what was signed.
      expect([400, 401, 403]).toContain(res.status)
    }
    expect((await send('/api/ciphers/x%2F..%2F..%2Faccounts/profile')).status).toBe(400)
    expect((await send('/api/accounts/profile')).status).toBe(403)
  })

  it('refuses peers on private addresses, IP literals and non-https targets', async () => {
    net.dns.set('internal.example.com', { A: ['127.0.0.1'] })
    const priv = await adminA.call(`${fed}/admin/peers`, 'POST', { domain: 'internal.example.com' })
    expect(priv.status).toBe(400)
    expect((await priv.json<any>()).message).toMatch(/private or reserved/)
    net.dns.set('v6.example.com', { AAAA: ['::1'] })
    expect(
      (await adminA.call(`${fed}/admin/peers`, 'POST', { domain: 'v6.example.com' })).status,
    ).toBe(400)
    for (const domain of ['127.0.0.1', 'localhost', 'http://vault.example.net:8080', 'a..b']) {
      expect((await adminA.call(`${fed}/admin/peers`, 'POST', { domain })).status).toBe(400)
    }
  })

  it('unpairing removes stand-in accounts on the hosting side and replicas on the serving side', async () => {
    // Bring alice back so there is something to purge.
    const inv = await owner.json(`${fed}/organizations/${orgId}/members`, 'POST', {
      email: alice.email,
      peerId: peerOnA,
      type: 2,
      accessAll: true,
    })
    const list = await alice.json(`${fed}/invitations`)
    const pending = list.data.find((i: { status: string }) => i.status === 'pending')
    await alice.call(`${fed}/invitations/${pending.id}/accept`, 'POST')
    expect((await syncOf(alice)).profile.organizations).toHaveLength(1)
    expect((await owner.json(`${fed}/organizations/${orgId}/members`)).data[0].id).toBe(inv.id)

    expect((await adminA.call(`${fed}/admin/peers/${peerOnA}`, 'DELETE')).status).toBe(200)
    await net.flush()
    expect((await syncOf(alice)).profile.organizations).toHaveLength(0)
    expect((await adminB.json(`${fed}/admin/peers`)).data).toHaveLength(0)
    expect((await owner.json(`${fed}/organizations/${orgId}/members`)).data).toHaveLength(0)
    expect((await owner.call(`/api/users/${alice.uuid}/public-key`)).status).toBe(404)
    const events = await adminA.json(`${fed}/admin/events`)
    const names = events.data.map((e: { name: string }) => e.name)
    expect(names).toEqual(
      expect.arrayContaining([
        'PeerAdded',
        'PeerApproved',
        'MemberInvited',
        'InvitationAccepted',
        'PeerRemoved',
      ]),
    )
  })
})
