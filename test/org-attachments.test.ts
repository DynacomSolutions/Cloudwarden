import { SELF } from 'cloudflare:test'
import { expect, it } from 'vitest'
import { BASE, createSession } from './helpers'
import { type Actor, actor, addMember, createOrg, loginCipher } from './org-helpers'

const upload = (
  url: string,
  token: string,
  bytes: Uint8Array,
  fields: Record<string, string> = {},
) => {
  const fd = new FormData()
  for (const [k, v] of Object.entries(fields)) fd.append(k, v)
  fd.append('data', new Blob([bytes]), '2.enc-name')
  return SELF.fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: fd,
  })
}

const reserve = async (who: Actor, cipherId: string, size: number, admin = false) => {
  const res = await who.call(`/api/ciphers/${cipherId}/attachment/v2`, 'POST', {
    fileName: '2.fname',
    key: '2.fkey',
    fileSize: size,
    adminRequest: admin,
  })
  return { status: res.status, body: (await res.json()) as { attachmentId: string; url: string } }
}

it('stores attachments on organisation items with collection permissions', async () => {
  const owner = await actor('oa-owner@example.com')
  const writer = await actor('oa-writer@example.com')
  const reader = await actor('oa-reader@example.com')
  const { id: orgId, defaultCollectionId } = await createOrg(owner)
  const grant = (readOnly: boolean) => [
    { id: defaultCollectionId, readOnly, hidePasswords: false, manage: false },
  ]
  await addMember(owner, orgId, writer, { type: 2, collections: grant(false) })
  await addMember(owner, orgId, reader, { type: 2, collections: grant(true) })
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.orgitem', { organizationId: orgId }),
    collectionIds: [defaultCollectionId],
  })

  // A member with write access uploads through the v2 flow.
  const slot = await reserve(writer, item.id, 4)
  expect(slot.status).toBe(200)
  expect((await upload(slot.body.url, writer.token, new Uint8Array([1, 2, 3, 4]))).status).toBe(200)

  // A read-only member cannot add one but can read it.
  expect((await reserve(reader, item.id, 4)).status).toBe(403)
  const meta = await reader.json(`/api/ciphers/${item.id}/attachment/${slot.body.attachmentId}`)
  expect(meta).toMatchObject({ object: 'attachment', size: '4' })
  const dl = await SELF.fetch(meta.url)
  expect(new Uint8Array(await dl.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3, 4]))

  // Everyone with access sees it in sync, and the organisation revision moved.
  const seen = (await reader.json('/api/sync')).ciphers.find((c: any) => c.id === item.id)
  expect(seen.attachments.map((a: any) => a.id)).toEqual([slot.body.attachmentId])
  expect(seen.organizationId).toBe(orgId)

  // A read-only member cannot delete it.
  expect(
    (await reader.call(`/api/ciphers/${item.id}/attachment/${slot.body.attachmentId}`, 'DELETE'))
      .status,
  ).toBe(403)
  // Someone outside the collection sees nothing.
  const outsider = await actor('oa-outsider@example.com')
  expect(
    (await outsider.call(`/api/ciphers/${item.id}/attachment/${slot.body.attachmentId}`)).status,
  ).toBe(404)

  // The writer deletes it and the cipher in the response is the organisation item.
  const del = await writer.json(
    `/api/ciphers/${item.id}/attachment/${slot.body.attachmentId}`,
    'DELETE',
  )
  expect(del.cipher).toMatchObject({ id: item.id, organizationId: orgId, attachments: null })
})

it('serves the admin attachment routes to organisation managers', async () => {
  const owner = await actor('oa-admin-owner@example.com')
  const member = await actor('oa-admin-member@example.com')
  const { id: orgId, defaultCollectionId } = await createOrg(owner)
  await addMember(owner, orgId, member, { type: 2, collections: [] })
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.orgitem', { organizationId: orgId }),
    collectionIds: [defaultCollectionId],
  })
  const slot = await reserve(owner, item.id, 2, true)
  expect(slot.status).toBe(200)
  expect((await upload(slot.body.url, owner.token, new Uint8Array([9, 9]))).status).toBe(200)

  const meta = await owner.json(
    `/api/ciphers/${item.id}/attachment/${slot.body.attachmentId}/admin`,
  )
  expect(meta).toMatchObject({ id: slot.body.attachmentId, size: '2' })
  // A plain member is not a manager.
  expect(
    (await member.call(`/api/ciphers/${item.id}/attachment/${slot.body.attachmentId}/admin`))
      .status,
  ).toBe(403)
  expect((await reserve(member, item.id, 2, true)).status).toBe(403)

  const del = await owner.json(
    `/api/ciphers/${item.id}/attachment/${slot.body.attachmentId}/admin`,
    'DELETE',
  )
  expect(del.cipher.attachments).toBeNull()
})

it('replaces an attachment when it is re-encrypted for sharing', async () => {
  const s = await createSession('oa-share@example.com')
  const owner = await actor('oa-share-owner@example.com')
  const { id: orgId } = await createOrg(owner)
  const c = await owner.json('/api/ciphers', 'POST', loginCipher('2.mine'))
  const slot = await reserve(owner, c.id, 3)
  await upload(slot.body.url, owner.token, new Uint8Array([1, 1, 1]))

  const res = await upload(
    `${BASE}/api/ciphers/${c.id}/attachment/${slot.body.attachmentId}/share?organizationId=${orgId}`,
    owner.token,
    new Uint8Array([7, 7, 7, 7, 7]),
    { key: '4.newkey' },
  )
  expect(res.status).toBe(200)
  const meta = await owner.json(`/api/ciphers/${c.id}/attachment/${slot.body.attachmentId}`)
  expect(meta).toMatchObject({ size: '5', key: '4.newkey' })
  const dl = await SELF.fetch(meta.url)
  expect(new Uint8Array(await dl.arrayBuffer())).toEqual(new Uint8Array([7, 7, 7, 7, 7]))

  // Not the caller's item, or no organisation named.
  expect(
    (
      await upload(
        `${BASE}/api/ciphers/${c.id}/attachment/${slot.body.attachmentId}/share?organizationId=${orgId}`,
        s.access_token,
        new Uint8Array([1]),
      )
    ).status,
  ).toBe(404)
  expect(
    (
      await upload(
        `${BASE}/api/ciphers/${c.id}/attachment/${slot.body.attachmentId}/share`,
        owner.token,
        new Uint8Array([1]),
      )
    ).status,
  ).toBe(400)
})
