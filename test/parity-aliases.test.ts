import { SELF } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'
import { toB64u, utf8 } from '../src/auth/crypto'
import { authed, BASE, createSession } from './helpers'
import { actor, addMember, createOrg, loginCipher } from './org-helpers'

// Obsolete spellings that the official server still routes (TASKS #231). Each must reach the
// handler of its current route, not the `:id` wildcard.

describe('obsolete cipher routes', () => {
  it('POST /api/ciphers/move moves personal and organisation items', async () => {
    const owner = await actor('alias-move-owner@example.com')
    const { id, defaultCollectionId } = await createOrg(owner)
    const own = await owner.json('/api/ciphers', 'POST', loginCipher('2.own'))
    const shared = await owner.json('/api/ciphers/create', 'POST', {
      cipher: loginCipher('2.shared', { organizationId: id }),
      collectionIds: [defaultCollectionId],
    })
    const folder = await owner.json('/api/folders', 'POST', { name: '2.folder' })
    const res = await owner.call('/api/ciphers/move', 'POST', {
      ids: [own.id, shared.id],
      folderId: folder.id,
    })
    expect(res.status).toBe(204)
    const sync = await owner.json('/api/sync')
    for (const cipherId of [own.id, shared.id])
      expect(sync.ciphers.find((c: any) => c.id === cipherId).folderId).toBe(folder.id)
    // An unknown id is a plain 404, not a cipher update with the id "move".
    const missing = await owner.call('/api/ciphers/move', 'POST', {
      ids: [crypto.randomUUID()],
      folderId: null,
    })
    expect(missing.status).toBe(404)
  })

  it('POST /api/ciphers/share shares items with an organisation', async () => {
    const owner = await actor('alias-share-owner@example.com')
    const { id, defaultCollectionId } = await createOrg(owner)
    const item = await owner.json('/api/ciphers', 'POST', loginCipher('2.mine'))
    const shared = await owner.json('/api/ciphers/share', 'POST', {
      ciphers: [{ ...loginCipher('2.mine-org', { organizationId: id }), id: item.id }],
      collectionIds: [defaultCollectionId],
    })
    expect(shared.data).toHaveLength(1)
    expect(shared.data[0]).toMatchObject({ id: item.id, organizationId: id })
  })

  it('POST delete-admin soft-deletes in bulk and one by one', async () => {
    const owner = await actor('alias-del-owner@example.com')
    const { id, defaultCollectionId } = await createOrg(owner)
    const make = (name: string) =>
      owner.json('/api/ciphers/create', 'POST', {
        cipher: loginCipher(name, { organizationId: id }),
        collectionIds: [defaultCollectionId],
      })
    const [a, b] = [await make('2.a'), await make('2.b')]
    const bulk = await owner.call('/api/ciphers/delete-admin', 'POST', {
      ids: [a.id],
      organizationId: id,
    })
    expect(bulk.status).toBe(200)
    expect((await owner.json(`/api/ciphers/${a.id}/admin`)).deletedDate).not.toBeNull()
    const one = await owner.call(`/api/ciphers/${b.id}/delete-admin`, 'POST')
    expect(one.status).toBe(200)
    expect((await owner.json(`/api/ciphers/${b.id}/admin`)).deletedDate).not.toBeNull()
  })

  it('GET full-details answers like details', async () => {
    const owner = await actor('alias-full-owner@example.com')
    const { id, defaultCollectionId } = await createOrg(owner)
    const own = await owner.json('/api/ciphers', 'POST', loginCipher('2.own'))
    const shared = await owner.json('/api/ciphers/create', 'POST', {
      cipher: loginCipher('2.shared', { organizationId: id }),
      collectionIds: [defaultCollectionId],
    })
    for (const item of [own, shared]) {
      expect(await owner.json(`/api/ciphers/${item.id}/full-details`)).toEqual(
        await owner.json(`/api/ciphers/${item.id}/details`),
      )
    }
    expect((await owner.call(`/api/ciphers/${crypto.randomUUID()}/full-details`)).status).toBe(404)
  })

  it('POST attachment delete-admin reaches the attachment delete', async () => {
    const owner = await actor('alias-att-owner@example.com')
    const item = await owner.json('/api/ciphers', 'POST', loginCipher('2.att'))
    const res = await owner.call(
      `/api/ciphers/${item.id}/attachment/${crypto.randomUUID()}/delete-admin`,
      'POST',
    )
    expect(res.status).toBe(404)
    expect(((await res.json()) as { message: string }).message).toMatch(/attachment/i)
  })

  it('does not let the wildcard answer an unknown POST id for a personal item', async () => {
    const owner = await actor('alias-wild-owner@example.com')
    const res = await owner.call(`/api/ciphers/${crypto.randomUUID()}`, 'POST', loginCipher())
    expect(res.status).toBe(404)
  })
})

describe('obsolete device and info routes', () => {
  it('POST /api/devices/{id} updates a device like PUT', async () => {
    const s = await createSession('alias-dev@example.com')
    const list = (await (await authed('/api/devices', s.access_token)).json()) as any
    const device = list.data[0]
    const res = await authed(`/api/devices/${device.id}`, s.access_token, 'POST', {
      type: device.type,
      name: 'renamed',
      identifier: device.identifier,
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ id: device.id, name: 'renamed' })
  })

  it('POST /api/devices/{identifier}/keys trusts a device like PUT', async () => {
    const s = await createSession('alias-keys@example.com')
    const res = await authed('/api/devices/device-1/keys', s.access_token, 'POST', {
      encryptedUserKey: '4.user',
      encryptedPublicKey: '2.public',
      encryptedPrivateKey: '2.private',
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ identifier: 'device-1', isTrusted: true })
  })

  it('GET knowndevice/{email}/{identifier} answers without authentication', async () => {
    await createSession('alias-known@example.com')
    const known = (email: string, id: string) =>
      SELF.fetch(`${BASE}/api/devices/knowndevice/${encodeURIComponent(email)}/${id}`)
    expect(await (await known('alias-known@example.com', 'device-1')).json()).toBe(true)
    expect(await (await known('alias-known@example.com', 'other')).json()).toBe(false)
    expect(await (await known('nobody@example.com', 'device-1')).json()).toBe(false)
    // The header form keeps working next to the path form.
    const header = await SELF.fetch(`${BASE}/api/devices/knowndevice`, {
      headers: {
        'X-Request-Email': toB64u(utf8('alias-known@example.com')),
        'X-Device-Identifier': 'device-1',
      },
    })
    expect(await header.json()).toBe(true)
  })

  it('GET now answers like alive on every service prefix', async () => {
    for (const path of ['/now', '/api/now', '/identity/now']) {
      const res = await SELF.fetch(`${BASE}${path}`)
      expect(res.status, path).toBe(200)
      expect(Number.isNaN(Date.parse((await res.json()) as string)), path).toBe(false)
    }
  })
})

describe('obsolete integration routes', () => {
  it('POST .../delete removes an integration and a configuration', async () => {
    const owner = await actor('alias-integ@example.com')
    const { id } = await createOrg(owner, 'Alias Org')
    const base = `/api/organizations/${id}/integrations`
    const make = async () =>
      owner.json(base, 'POST', {
        type: 5,
        configuration: JSON.stringify({
          Uri: 'https://hec.example.com:8088/services/collector/event',
          Scheme: 'Splunk',
          Token: 'alias-token',
          Service: 'vault',
        }),
      })
    const integ = await make()
    const cfg = await owner.json(`${base}/${integ.id}/configurations`, 'POST', {
      eventType: 1700,
      filters: '{"groups":[]}',
      template: '{"event":#EventMessage#}',
    })
    expect(
      (await owner.call(`${base}/${integ.id}/configurations/${cfg.id}/delete`, 'POST')).status,
    ).toBe(204)
    expect(await owner.json(`${base}/${integ.id}/configurations`)).toHaveLength(0)
    expect((await owner.call(`${base}/${integ.id}/delete`, 'POST')).status).toBe(204)
    expect(await owner.json(base)).toHaveLength(0)
  })
})

describe('obsolete sponsorship routes', () => {
  it('answer like the current deletes: 400 with the self-hosted explanation', async () => {
    const owner = await actor('alias-sponsor@example.com')
    const { id } = await createOrg(owner)
    for (const path of [
      `/api/organization/sponsorship/${id}/delete`,
      `/api/organization/sponsorship/self-hosted/${id}/delete`,
      `/api/organization/sponsorship/sponsored/${id}/remove`,
    ]) {
      const res = await owner.call(path, 'POST')
      expect(res.status, path).toBe(400)
      expect(((await res.json()) as { message: string }).message, path).toMatch(
        /sponsorships are not available/,
      )
    }
    const member = await actor('alias-sponsor-stranger@example.com')
    expect(
      (await member.call(`/api/organization/sponsorship/${id}/delete`, 'POST')).status,
    ).not.toBe(400)
  })
})

describe('membership of an organisation does not change alias routing', () => {
  it('a plain member moves a personal item through POST', async () => {
    const owner = await actor('alias-m-owner@example.com')
    const member = await actor('alias-m-member@example.com')
    const { id } = await createOrg(owner)
    await addMember(owner, id, member, { type: 2 })
    const item = await member.json('/api/ciphers', 'POST', loginCipher('2.mem'))
    expect(
      (await member.call('/api/ciphers/move', 'POST', { ids: [item.id], folderId: null })).status,
    ).toBe(204)
  })
})
