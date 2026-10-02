import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'
import { authed, BASE, createSession } from './helpers'
import { actor, addMember, createOrg, loginCipher } from './org-helpers'

const personal = { type: 2, name: '2.note', secureNote: { type: 0 } }

it('archives and unarchives personal items, singly and in bulk', async () => {
  const s = await createSession('arc-personal@example.com')
  const make = async (name: string) =>
    (await (
      await authed('/api/ciphers', s.access_token, 'POST', { ...personal, name })
    ).json()) as {
      id: string
      archivedDate: string | null
    }
  const a = await make('2.a')
  const b = await make('2.b')
  expect(a.archivedDate).toBeNull()

  const one = await authed(`/api/ciphers/${a.id}/archive`, s.access_token, 'PUT')
  expect(one.status).toBe(200)
  const archived = (await one.json()) as { id: string; archivedDate: string }
  expect(archived.id).toBe(a.id)
  expect(Date.parse(archived.archivedDate)).toBeGreaterThan(0)

  // Archiving again keeps the original date.
  const again = (await (
    await authed(`/api/ciphers/${a.id}/archive`, s.access_token, 'PUT')
  ).json()) as { archivedDate: string }
  expect(again.archivedDate).toBe(archived.archivedDate)

  const sync = (await (await authed('/api/sync', s.access_token)).json()) as {
    ciphers: { id: string; archivedDate: string | null }[]
  }
  expect(sync.ciphers.find((c) => c.id === a.id)?.archivedDate).toBe(archived.archivedDate)
  expect(sync.ciphers.find((c) => c.id === b.id)?.archivedDate).toBeNull()

  const bulk = await authed('/api/ciphers/archive', s.access_token, 'PUT', { ids: [a.id, b.id] })
  expect(bulk.status).toBe(200)
  const list = (await bulk.json()) as {
    object: string
    data: { id: string; archivedDate: string }[]
  }
  expect(list.object).toBe('list')
  expect(list.data.map((c) => c.id).sort()).toEqual([a.id, b.id].sort())
  expect(list.data.every((c) => c.archivedDate)).toBe(true)

  const un = (await (
    await authed('/api/ciphers/unarchive', s.access_token, 'PUT', { ids: [a.id, b.id] })
  ).json()) as { data: { archivedDate: string | null }[] }
  expect(un.data.every((c) => c.archivedDate === null)).toBe(true)
  const single = (await (
    await authed(`/api/ciphers/${a.id}/unarchive`, s.access_token, 'PUT')
  ).json()) as { archivedDate: string | null }
  expect(single.archivedDate).toBeNull()

  // An ordinary edit never changes the archive state.
  await authed(`/api/ciphers/${a.id}/archive`, s.access_token, 'PUT')
  const edited = (await (
    await authed(`/api/ciphers/${a.id}`, s.access_token, 'PUT', { ...personal, name: '2.renamed' })
  ).json()) as { archivedDate: string | null; name: string }
  expect(edited.name).toBe('2.renamed')
  expect(edited.archivedDate).toBeTruthy()
})

it("refuses to archive items that are not the caller's", async () => {
  const mine = await createSession('arc-mine@example.com')
  const theirs = await createSession('arc-theirs@example.com')
  const c = (await (
    await authed('/api/ciphers', theirs.access_token, 'POST', personal)
  ).json()) as {
    id: string
  }
  expect((await authed(`/api/ciphers/${c.id}/archive`, mine.access_token, 'PUT')).status).toBe(404)
  expect(
    (await authed('/api/ciphers/archive', mine.access_token, 'PUT', { ids: [c.id] })).status,
  ).toBe(404)
  expect(
    (await authed(`/api/ciphers/${crypto.randomUUID()}/archive`, mine.access_token, 'PUT')).status,
  ).toBe(404)
  // Unauthenticated.
  expect((await SELF.fetch(`${BASE}/api/ciphers/archive`, { method: 'PUT' })).status).toBe(401)
})

it('imports an archived item with its archive date', async () => {
  const s = await createSession('arc-import@example.com')
  const when = '2026-01-02T03:04:05.000Z'
  const res = await authed('/api/ciphers/import', s.access_token, 'POST', {
    folders: [],
    folderRelationships: [],
    ciphers: [{ ...personal, archivedDate: when }],
  })
  expect(res.status).toBe(200)
  const sync = (await (await authed('/api/sync', s.access_token)).json()) as {
    ciphers: { archivedDate: string }[]
  }
  expect(sync.ciphers[0]?.archivedDate).toBe(when)
})

it('keeps favourite, archive and folder per member for organisation items', async () => {
  const owner = await actor('arc-owner@example.com')
  const member = await actor('arc-member@example.com')
  const { id: orgId, defaultCollectionId } = await createOrg(owner)
  const memberId = await addMember(owner, orgId, member, {
    type: 2,
    collections: [
      { id: defaultCollectionId, readOnly: false, hidePasswords: false, manage: false },
    ],
  })
  expect(memberId).toBeTruthy()
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.shared', { organizationId: orgId }),
    collectionIds: [defaultCollectionId],
  })
  const view = async (who: typeof owner) =>
    (await who.json('/api/sync')).ciphers.find((c: any) => c.id === item.id)

  expect(await view(owner)).toMatchObject({ favorite: false, archivedDate: null })

  // The member favourites it through a full update; the owner's copy is unchanged.
  const updated = await member.json(`/api/ciphers/${item.id}`, 'PUT', {
    ...loginCipher('2.shared', { organizationId: orgId }),
    favorite: true,
  })
  expect(updated.favorite).toBe(true)
  expect(await view(member)).toMatchObject({ favorite: true })
  expect(await view(owner)).toMatchObject({ favorite: false })
  expect((await owner.json(`/api/ciphers/${item.id}`)).favorite).toBe(false)

  // The owner favourites it through the partial endpoint.
  const partial = await owner.json(`/api/ciphers/${item.id}/partial`, 'PUT', {
    favorite: true,
    folderId: null,
  })
  expect(partial.favorite).toBe(true)
  // The member's edit without a favourite flag changes nothing for them.
  await member.json(
    `/api/ciphers/${item.id}`,
    'PUT',
    loginCipher('2.shared2', { organizationId: orgId }),
  )
  expect(await view(member)).toMatchObject({ favorite: true, name: '2.shared2' })
  // The member unfavourites; the owner keeps theirs.
  await member.json(`/api/ciphers/${item.id}/partial`, 'PUT', { favorite: false, folderId: null })
  expect(await view(member)).toMatchObject({ favorite: false })
  expect(await view(owner)).toMatchObject({ favorite: true })

  // Archive is per member too.
  const arch = await member.json(`/api/ciphers/${item.id}/archive`, 'PUT')
  expect(arch).toMatchObject({ id: item.id, organizationId: orgId })
  expect(arch.archivedDate).toBeTruthy()
  expect((await view(member)).archivedDate).toBe(arch.archivedDate)
  expect((await view(owner)).archivedDate).toBeNull()
  const bulk = await owner.json('/api/ciphers/archive', 'PUT', { ids: [item.id] })
  expect(bulk.data[0].archivedDate).toBeTruthy()
  await member.json('/api/ciphers/unarchive', 'PUT', { ids: [item.id] })
  expect((await view(member)).archivedDate).toBeNull()
  expect((await view(owner)).archivedDate).toBeTruthy()

  // Folders are private to each member.
  const folder = await member.json('/api/folders', 'POST', { name: '2.mine' })
  await member.json(`/api/ciphers/${item.id}/partial`, 'PUT', {
    favorite: false,
    folderId: folder.id,
  })
  expect((await view(member)).folderId).toBe(folder.id)
  expect((await view(owner)).folderId).toBeNull()

  // A member who cannot see the item cannot archive it.
  const stranger = await actor('arc-stranger@example.com')
  expect((await stranger.call(`/api/ciphers/${item.id}/archive`, 'PUT')).status).toBe(404)
})

it("moves a personal item into an organisation keeping the owner's favourite and archive", async () => {
  const owner = await actor('arc-share@example.com')
  const { id: orgId, defaultCollectionId } = await createOrg(owner)
  const mine = await owner.json('/api/ciphers', 'POST', {
    ...loginCipher('2.mine'),
    favorite: true,
  })
  await owner.json(`/api/ciphers/${mine.id}/archive`, 'PUT')
  const shared = await owner.json(`/api/ciphers/${mine.id}/share`, 'PUT', {
    cipher: { ...loginCipher('2.mine', { organizationId: orgId }), favorite: true },
    collectionIds: [defaultCollectionId],
  })
  expect(shared).toMatchObject({ organizationId: orgId, favorite: true })
  expect(shared.archivedDate).toBeTruthy()
})

it('deletes folders in bulk and all at once', async () => {
  const s = await createSession('arc-folders@example.com')
  const mk = async (name: string) =>
    (await (await authed('/api/folders', s.access_token, 'POST', { name })).json()) as {
      id: string
    }
  const [a, b, c] = [await mk('2.a'), await mk('2.b'), await mk('2.c')] as { id: string }[]
  const item = (await (
    await authed('/api/ciphers', s.access_token, 'POST', { ...personal, folderId: a?.id })
  ).json()) as { id: string; folderId: string }
  expect(item.folderId).toBe(a?.id)

  const stranger = await createSession('arc-folders2@example.com')
  expect(
    (await authed('/api/folders', stranger.access_token, 'DELETE', { ids: [a?.id] })).status,
  ).toBe(404)

  const del = await authed('/api/folders', s.access_token, 'DELETE', { ids: [a?.id, b?.id] })
  expect(del.status).toBe(200)
  const left = (await (await authed('/api/folders', s.access_token)).json()) as {
    data: { id: string }[]
  }
  expect(left.data.map((f) => f.id)).toEqual([c?.id])
  const kept = (await (await authed(`/api/ciphers/${item.id}`, s.access_token)).json()) as {
    folderId: string | null
  }
  expect(kept.folderId).toBeNull()

  expect((await authed('/api/folders/all', s.access_token, 'DELETE')).status).toBe(200)
  const none = (await (await authed('/api/folders', s.access_token)).json()) as { data: unknown[] }
  expect(none.data).toEqual([])
})
