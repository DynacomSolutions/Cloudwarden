import { expect, it } from 'vitest'
import { actor, addMember, createOrg, loginCipher } from './org-helpers'

const personalFolderless = (sync: any) => sync.ciphers.filter((c: any) => !c.organizationId)

it('gives members collection access with read-only and hide-password flags', async () => {
  const owner = await actor('col-owner@example.com')
  const member = await actor('col-member@example.com')
  const { id } = await createOrg(owner)
  const memberId = await addMember(owner, id, member, { type: 2 })

  const created = await owner.json(`/api/organizations/${id}/collections`, 'POST', {
    name: '2.shared',
    users: [{ id: memberId, readOnly: true, hidePasswords: true, manage: false }],
    groups: [],
  })
  expect(created).toMatchObject({ name: '2.shared', organizationId: id })

  // The member sees the new collection with their flags and nothing else.
  const mine = await member.json('/api/collections')
  expect(mine.data).toHaveLength(1)
  expect(mine.data[0]).toMatchObject({
    id: created.id,
    readOnly: true,
    hidePasswords: true,
    manage: false,
  })
  expect((await member.json('/api/sync')).collections).toHaveLength(1)

  // Owner view includes who has access.
  const details = await owner.json(`/api/organizations/${id}/collections/details`)
  const shared = details.data.find((c: any) => c.id === created.id)
  expect(shared.users).toEqual([
    { id: memberId, readOnly: true, hidePasswords: true, manage: false },
  ])
  expect((await owner.json(`/api/organizations/${id}/collections/${created.id}/users`))[0].id).toBe(
    memberId,
  )

  // Create an item in the collection; the member reads it but cannot edit or delete it.
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.orgitem', { organizationId: id }),
    collectionIds: [created.id],
  })
  expect(item).toMatchObject({ organizationId: id, collectionIds: [created.id], edit: true })
  const seen = (await member.json('/api/sync')).ciphers.find((c: any) => c.id === item.id)
  expect(seen).toMatchObject({
    organizationId: id,
    edit: false,
    viewPassword: false,
    collectionIds: [created.id],
    name: '2.orgitem',
  })
  expect((await member.call(`/api/ciphers/${item.id}`)).status).toBe(200)
  expect(
    (
      await member.call(
        `/api/ciphers/${item.id}`,
        'PUT',
        loginCipher('2.hacked', { organizationId: id }),
      )
    ).status,
  ).toBe(403)
  expect((await member.call(`/api/ciphers/${item.id}`, 'DELETE')).status).toBe(403)

  // Granting write access lets the member edit.
  const put = await owner.call(`/api/organizations/${id}/collections/${created.id}`, 'PUT', {
    name: '2.shared',
    users: [{ id: memberId, readOnly: false, hidePasswords: false, manage: false }],
  })
  expect(put.status).toBe(200)
  const edited = await member.call(
    `/api/ciphers/${item.id}`,
    'PUT',
    loginCipher('2.edited', { organizationId: id }),
  )
  expect(edited.status).toBe(200)
  expect(((await edited.json()) as any).name).toBe('2.edited')
  expect((await owner.json(`/api/ciphers/${item.id}`)).name).toBe('2.edited')

  // Soft delete and restore by the member, then hard delete.
  expect((await member.call(`/api/ciphers/${item.id}/delete`, 'PUT')).status).toBe(200)
  expect((await member.json(`/api/ciphers/${item.id}`)).deletedDate).not.toBeNull()
  expect((await member.json(`/api/ciphers/${item.id}/restore`, 'PUT')).deletedDate).toBeNull()
  expect((await member.call(`/api/ciphers/${item.id}`, 'DELETE')).status).toBe(200)
  expect((await owner.call(`/api/ciphers/${item.id}`)).status).toBe(404)

  // Removing access hides the collection; deleting it is an owner-only action.
  expect(
    (await member.call(`/api/organizations/${id}/collections/${created.id}`, 'DELETE')).status,
  ).toBe(403)
  expect(
    (await owner.call(`/api/organizations/${id}/collections/${created.id}`, 'DELETE')).status,
  ).toBe(200)
  expect((await member.json('/api/sync')).collections).toHaveLength(0)
})

it('shares a personal item with an organisation atomically and exposes it to members', async () => {
  const owner = await actor('share-owner@example.com')
  const member = await actor('share-member@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  const memberId = await addMember(owner, id, member, {
    type: 2,
    collections: [
      { id: defaultCollectionId, readOnly: false, hidePasswords: false, manage: false },
    ],
  })

  const personal = await member.json('/api/ciphers', 'POST', loginCipher('2.mine'))
  expect(personal.organizationId).toBeNull()
  const shared = await member.json(`/api/ciphers/${personal.id}/share`, 'PUT', {
    cipher: loginCipher('2.reencrypted', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  expect(shared).toMatchObject({
    id: personal.id,
    organizationId: id,
    name: '2.reencrypted',
    collectionIds: [defaultCollectionId],
    edit: true,
  })

  // It left the personal vault and is now an organisation item for both of them.
  const msync = await member.json('/api/sync')
  expect(personalFolderless(msync)).toHaveLength(0)
  expect(msync.ciphers.map((c: any) => c.id)).toEqual([personal.id])
  const osync = await owner.json('/api/sync')
  expect(osync.ciphers.map((c: any) => c.id)).toEqual([personal.id])

  // Sharing again, sharing into a collection the user cannot write, or without collections fails.
  const again = await member.call(`/api/ciphers/${personal.id}/share`, 'PUT', {
    cipher: loginCipher('2.x', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  expect(again.status).toBe(404)
  const second = await member.json('/api/ciphers', 'POST', loginCipher('2.second'))
  expect(
    (
      await member.call(`/api/ciphers/${second.id}/share`, 'PUT', {
        cipher: loginCipher('2.y', { organizationId: id }),
        collectionIds: [],
      })
    ).status,
  ).toBe(400)
  const readonly = await owner.json(`/api/organizations/${id}/collections`, 'POST', {
    name: '2.ro',
    users: [{ id: memberId, readOnly: true }],
  })
  expect(
    (
      await member.call(`/api/ciphers/${second.id}/share`, 'PUT', {
        cipher: loginCipher('2.y', { organizationId: id }),
        collectionIds: [readonly.id],
      })
    ).status,
  ).toBe(403)
  // The failed shares changed nothing.
  expect((await member.json(`/api/ciphers/${second.id}`)).organizationId).toBeNull()

  // Bulk share is all or nothing.
  const third = await member.json('/api/ciphers', 'POST', loginCipher('2.third'))
  const bulk = await member.call('/api/ciphers/share', 'PUT', {
    ciphers: [
      { ...loginCipher('2.third-org', { organizationId: id }), id: third.id },
      { ...loginCipher('2.second-org', { organizationId: id }), id: crypto.randomUUID() },
    ],
    collectionIds: [defaultCollectionId],
  })
  expect(bulk.status).toBe(404)
  expect((await member.json(`/api/ciphers/${third.id}`)).organizationId).toBeNull()
  const ok = await member.json('/api/ciphers/share', 'PUT', {
    ciphers: [
      { ...loginCipher('2.third-org', { organizationId: id }), id: third.id },
      { ...loginCipher('2.second-org', { organizationId: id }), id: second.id },
    ],
    collectionIds: [defaultCollectionId],
  })
  expect(ok.data).toHaveLength(2)
  expect((await owner.json('/api/sync')).ciphers).toHaveLength(3)

  // Updating the collections of an item keeps the ones the caller cannot write to.
  const v2 = await owner.json(`/api/ciphers/${third.id}/collections_v2`, 'PUT', {
    collectionIds: [defaultCollectionId, readonly.id],
  })
  expect(v2.unavailable).toBe(false)
  expect(v2.cipher.collectionIds.sort()).toEqual([defaultCollectionId, readonly.id].sort())
  const adminList = await owner.json(`/api/ciphers/organization-details?organizationId=${id}`)
  expect(adminList.data).toHaveLength(3)
  expect((await member.call(`/api/ciphers/organization-details?organizationId=${id}`)).status).toBe(
    403,
  )
  const assigned = await member.json(
    `/api/ciphers/organization-details/assigned?organizationId=${id}`,
  )
  expect(assigned.data.length).toBeGreaterThan(0)
})

it('bumps the revision date of members when shared data changes', async () => {
  const owner = await actor('rev-owner@example.com')
  const member = await actor('rev-member@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  await addMember(owner, id, member, {
    type: 2,
    collections: [{ id: defaultCollectionId, readOnly: false }],
  })
  const before = await member.json('/api/accounts/revision-date')
  await new Promise((r) => setTimeout(r, 5))
  await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.new', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  expect(await member.json('/api/accounts/revision-date')).toBeGreaterThan(before)
})

it('applies group collection access and access-all groups', async () => {
  const owner = await actor('grp-owner@example.com')
  const member = await actor('grp-member@example.com')
  const all = await actor('grp-all@example.com')
  const { id } = await createOrg(owner)
  const memberId = await addMember(owner, id, member, { type: 2 })
  const allId = await addMember(owner, id, all, { type: 2 })
  const col = await owner.json(`/api/organizations/${id}/collections`, 'POST', { name: '2.grpcol' })
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.grpitem', { organizationId: id }),
    collectionIds: [col.id],
  })
  expect((await member.json('/api/sync')).ciphers).toHaveLength(0)

  const group = await owner.json(`/api/organizations/${id}/groups`, 'POST', {
    name: 'Team',
    accessAll: false,
    collections: [{ id: col.id, readOnly: true, hidePasswords: false, manage: false }],
    users: [memberId],
  })
  expect(group).toMatchObject({
    name: 'Team',
    organizationId: id,
    accessAll: false,
    object: 'group',
  })
  expect(await owner.json(`/api/organizations/${id}/groups/${group.id}/users`)).toEqual([memberId])
  const details = await owner.json(`/api/organizations/${id}/groups/${group.id}/details`)
  expect(details.collections).toEqual([
    { id: col.id, readOnly: true, hidePasswords: false, manage: false },
  ])
  expect((await owner.json(`/api/organizations/${id}/users/${memberId}`)).groups).toEqual([
    group.id,
  ])

  const synced = await member.json('/api/sync')
  expect(synced.collections.map((c: any) => c.id)).toEqual([col.id])
  expect(synced.ciphers[0]).toMatchObject({ id: item.id, edit: false, viewPassword: true })

  // Changing the group's grant to writable flows through to the member.
  const upd = await owner.call(`/api/organizations/${id}/groups/${group.id}`, 'PUT', {
    name: 'Team',
    collections: [{ id: col.id, readOnly: false, hidePasswords: false, manage: false }],
    users: [memberId],
  })
  expect(upd.status).toBe(200)
  expect((await member.json('/api/sync')).ciphers[0].edit).toBe(true)

  // An access-all group reaches every collection.
  const wide = await owner.json(`/api/organizations/${id}/groups`, 'POST', {
    name: 'Everyone',
    accessAll: true,
    users: [allId],
  })
  expect((await all.json('/api/sync')).ciphers).toHaveLength(1)
  expect((await owner.json(`/api/organizations/${id}/groups`)).data).toHaveLength(2)

  // Member-side group assignment endpoint and deletion remove access.
  expect(
    (await owner.call(`/api/organizations/${id}/users/${memberId}/groups`, 'PUT', { groupIds: [] }))
      .status,
  ).toBe(200)
  expect((await member.json('/api/sync')).ciphers).toHaveLength(0)
  expect((await owner.call(`/api/organizations/${id}/groups/${wide.id}`, 'DELETE')).status).toBe(
    200,
  )
  expect((await all.json('/api/sync')).ciphers).toHaveLength(0)
  expect((await owner.call(`/api/organizations/${id}/groups/${group.id}`)).status).toBe(200)
  expect((await owner.call(`/api/organizations/${id}/groups/${crypto.randomUUID()}`)).status).toBe(
    404,
  )
})

it('lets admins use the admin cipher endpoints for items outside their collections', async () => {
  const owner = await actor('adm-owner@example.com')
  const admin = await actor('adm-admin@example.com')
  const user = await actor('adm-user@example.com')
  const { id } = await createOrg(owner)
  await addMember(owner, id, admin, { type: 1 })
  await addMember(owner, id, user, { type: 2 })
  const col = await owner.json(`/api/organizations/${id}/collections`, 'POST', {
    name: '2.private',
  })
  const made = await admin.json('/api/ciphers/admin', 'POST', {
    cipher: loginCipher('2.adm', { organizationId: id }),
    collectionIds: [col.id],
  })
  expect(made.organizationId).toBe(id)
  expect(
    (
      await user.call('/api/ciphers/admin', 'POST', {
        cipher: loginCipher('2.u', { organizationId: id }),
        collectionIds: [col.id],
      })
    ).status,
  ).toBe(403)
  expect((await user.call(`/api/ciphers/${made.id}`)).status).toBe(404)
  expect((await user.call(`/api/ciphers/${made.id}/admin`)).status).toBe(403)

  expect(
    (
      await admin.json(
        `/api/ciphers/${made.id}/admin`,
        'PUT',
        loginCipher('2.adm2', { organizationId: id }),
      )
    ).name,
  ).toBe('2.adm2')
  expect(
    (await admin.call('/api/ciphers/delete-admin', 'PUT', { ids: [made.id], organizationId: id }))
      .status,
  ).toBe(200)
  const restored = await admin.json('/api/ciphers/restore-admin', 'PUT', {
    ids: [made.id],
    organizationId: id,
  })
  expect(restored.data[0].deletedDate).toBeNull()
  expect(
    (await admin.call(`/api/ciphers/${made.id}/collections-admin`, 'PUT', { collectionIds: [] }))
      .status,
  ).toBe(200)
  expect((await admin.call(`/api/ciphers/${made.id}/admin`, 'DELETE')).status).toBe(200)
})

it('moves organisation items into private folders without affecting other members', async () => {
  const owner = await actor('fold-owner@example.com')
  const member = await actor('fold-member@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  await addMember(owner, id, member, { type: 2, collections: [{ id: defaultCollectionId }] })
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.f', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  const folder = await member.json('/api/folders', 'POST', { name: '2.folder' })
  expect(
    (await member.call('/api/ciphers/move', 'PUT', { ids: [item.id], folderId: folder.id })).status,
  ).toBe(204)
  expect((await member.json(`/api/ciphers/${item.id}`)).folderId).toBe(folder.id)
  expect((await owner.json(`/api/ciphers/${item.id}`)).folderId).toBeNull()
  // Bulk delete accepts organisation items.
  expect((await member.call('/api/ciphers/delete', 'PUT', { ids: [item.id] })).status).toBe(200)
  expect((await member.json(`/api/ciphers/${item.id}`)).deletedDate).not.toBeNull()
})

it('imports into an organisation', async () => {
  const owner = await actor('imp-owner@example.com')
  const { id } = await createOrg(owner)
  const res = await owner.call(`/api/ciphers/import-organization?organizationId=${id}`, 'POST', {
    ciphers: [
      loginCipher('2.a', { organizationId: id }),
      loginCipher('2.b', { organizationId: id }),
    ],
    collections: [{ name: '2.imported' }],
    collectionRelationships: [{ key: 0, value: 0 }],
  })
  expect(res.status).toBe(200)
  const sync = await owner.json('/api/sync')
  expect(sync.ciphers).toHaveLength(2)
  expect(sync.collections).toHaveLength(2)
})
