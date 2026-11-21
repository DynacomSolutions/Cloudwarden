import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { expect, it, vi } from 'vitest'
import { BASE } from './helpers'
import { actor, addMember, createOrg, loginCipher, mailbox } from './org-helpers'

// Each test makes dozens of requests; a loaded CI host needs more than the 120 s default.
vi.setConfig({ testTimeout: 600_000 })

const upload = (url: string, token: string, bytes: Uint8Array, fields: Record<string, string>) => {
  const fd = new FormData()
  for (const [k, v] of Object.entries(fields)) fd.append(k, v)
  fd.append('data', new Blob([bytes]), '2.enc-name')
  return SELF.fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: fd,
  })
}

it('serves collections/access before the collection id route', async () => {
  const owner = await actor('ox-col-owner@example.com')
  const member = await actor('ox-col-member@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  const memberId = await addMember(owner, id, member, {
    type: 2,
    collections: [{ id: defaultCollectionId, readOnly: true, hidePasswords: false, manage: false }],
  })
  const own = await owner.json(`/api/organizations/${id}/collections/access`)
  expect(own).toMatchObject({ object: 'list', continuationToken: null })
  const row = own.data.find((c: any) => c.id === defaultCollectionId)
  expect(row).toMatchObject({
    object: 'collectionAccessDetails',
    organizationId: id,
    hasEnabledAccessRule: false,
    unmanaged: false,
    manage: true,
  })
  expect(row.users).toContainEqual({
    id: memberId,
    readOnly: true,
    hidePasswords: false,
    manage: false,
  })
  // Same rows as the details route, so the two cannot drift apart.
  const details = await owner.json(`/api/organizations/${id}/collections/details`)
  expect(own.data.map((c: any) => c.id)).toEqual(details.data.map((c: any) => c.id))
  // A member without Manage access to a collection does not see it, like the details route.
  expect((await member.json(`/api/organizations/${id}/collections/access`)).data).toEqual([])
  // An outsider is refused.
  const stranger = await actor('ox-col-stranger@example.com')
  expect((await stranger.call(`/api/organizations/${id}/collections/access`)).status).toBe(404)
  // The id route still serves ids.
  expect(
    (await owner.call(`/api/organizations/${id}/collections/${defaultCollectionId}`)).status,
  ).toBe(200)
})

it('lists only login items of an organisation for members who manage all items', async () => {
  const owner = await actor('ox-login-owner@example.com')
  const member = await actor('ox-login-member@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  await addMember(owner, id, member, { type: 2 })
  const login = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.login', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  const note = await owner.json('/api/ciphers/create', 'POST', {
    cipher: {
      type: 2,
      name: '2.note',
      key: '2.k',
      secureNote: { type: 0 },
      organizationId: id,
    },
    collectionIds: [defaultCollectionId],
  })
  const all = await owner.json(`/api/ciphers/organization-details?organizationId=${id}`)
  expect(all.data.map((c: any) => c.id).sort()).toEqual([login.id, note.id].sort())
  const logins = await owner.json(`/api/ciphers/organization-details/logins?organizationId=${id}`)
  expect(logins).toMatchObject({ object: 'list' })
  expect(logins.data.map((c: any) => c.id)).toEqual([login.id])
  expect(logins.data[0].type).toBe(1)
  // Same authorisation as organization-details.
  expect(
    (await member.call(`/api/ciphers/organization-details/logins?organizationId=${id}`)).status,
  ).toBe(403)
  const stranger = await actor('ox-login-stranger@example.com')
  expect(
    (await stranger.call(`/api/ciphers/organization-details/logins?organizationId=${id}`)).status,
  ).toBe(404)
})

it('uploads an attachment as an organisation administrator and downloads it by token', async () => {
  const owner = await actor('ox-att-owner@example.com')
  const writer = await actor('ox-att-writer@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  await addMember(owner, id, writer, {
    type: 2,
    collections: [
      { id: defaultCollectionId, readOnly: false, hidePasswords: false, manage: false },
    ],
  })
  const item = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.attitem', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  const bytes = new Uint8Array([9, 8, 7, 6, 5])
  // The admin route needs the right to manage every item; a collection writer lacks it.
  const denied = await upload(
    `${BASE}/api/ciphers/${item.id}/attachment-admin`,
    writer.token,
    bytes,
    {
      key: '2.attkey',
    },
  )
  expect(denied.status).toBe(403)
  const res = await upload(`${BASE}/api/ciphers/${item.id}/attachment-admin`, owner.token, bytes, {
    key: '2.attkey',
  })
  expect(res.status).toBe(200)
  const body = (await res.json()) as { id: string; attachments: { id: string; url: string }[] }
  expect(body.id).toBe(item.id)
  expect(body.attachments).toHaveLength(1)

  // The path download and the token download serve the same bytes.
  const url = new URL(body.attachments[0]?.url as string)
  const token = url.searchParams.get('token') as string
  const viaPath = await SELF.fetch(url.toString())
  expect(new Uint8Array(await viaPath.arrayBuffer())).toEqual(bytes)
  const viaToken = await SELF.fetch(`${BASE}/api/ciphers/attachment/download?token=${token}`)
  expect(viaToken.status).toBe(200)
  expect(new Uint8Array(await viaToken.arrayBuffer())).toEqual(bytes)
  // No sign-in is needed, but a token is.
  expect((await SELF.fetch(`${BASE}/api/ciphers/attachment/download`)).status).toBe(401)
  expect((await SELF.fetch(`${BASE}/api/ciphers/attachment/download?token=x.y.z`)).status).toBe(401)
  // A token of another audience (a Send file) does not open an attachment.
  const { signBlobToken } = await import('../src/vault/blobs')
  const other = await signBlobToken(env, 'send-file', `${item.id}/${body.attachments[0]?.id}`)
  expect((await SELF.fetch(`${BASE}/api/ciphers/attachment/download?token=${other}`)).status).toBe(
    401,
  )
  // A signed subject that is not an attachment of the right shape is refused.
  const bad = await signBlobToken(env, 'attachment', 'only-one-part')
  expect((await SELF.fetch(`${BASE}/api/ciphers/attachment/download?token=${bad}`)).status).toBe(
    401,
  )
})

it('answers the storage event hook like a server that keeps files locally', async () => {
  const post = (body: unknown) =>
    SELF.fetch(`${BASE}/api/ciphers/attachment/validate/azure`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: typeof body === 'string' ? body : JSON.stringify(body),
    })
  const handshake = await post([
    {
      eventType: 'Microsoft.EventGrid.SubscriptionValidationEvent',
      data: { validationCode: 'code-123' },
    },
  ])
  expect(handshake.status).toBe(200)
  expect(await handshake.json()).toEqual({ validationResponse: 'code-123' })
  // Other events are accepted and change nothing.
  const other = await post([{ eventType: 'Microsoft.Storage.BlobCreated', data: {} }])
  expect(other.status).toBe(200)
  expect(await other.text()).toBe('')
  expect((await post('not json')).status).toBe(400)
  expect((await post({ eventType: 'x' })).status).toBe(400)
  // A body above 64 KB is refused, by its declared length and by its real length.
  const big = JSON.stringify([{ eventType: 'x', data: 'a'.repeat(70_000) }])
  expect((await post(big)).status).toBe(413)
})

it('rate limits the anonymous storage event hook per address', async () => {
  const hit = () =>
    SELF.fetch(`${BASE}/api/ciphers/attachment/validate/azure`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '203.0.113.77' },
      body: '[]',
    })
  const codes: number[] = []
  for (let i = 0; i < 40; i++) codes.push((await hit()).status)
  expect(codes).toContain(429)
})

it('sends the invitation again through users/send-invite', async () => {
  const mb = mailbox()
  const owner = await actor('ox-inv-owner@example.com', mb)
  const member = await actor('ox-inv-member@example.com', mb)
  const { id } = await createOrg(owner)
  const inv = await owner.call(`/api/organizations/${id}/users/invite`, 'POST', {
    emails: ['ox-inv-new@example.com'],
    type: 2,
    collections: [],
    groups: [],
  })
  expect(inv.status).toBe(200)
  const users = await owner.json(`/api/organizations/${id}/users`)
  const invited = users.data.find((u: any) => u.email === 'ox-inv-new@example.com').id as string
  const confirmed = await addMember(owner, id, member, { type: 2 }, mb)
  const before = mb.sent.length
  const res = await owner.json(`/api/organizations/${id}/users/send-invite`, 'POST', {
    ids: [invited, confirmed],
  })
  expect(res).toMatchObject({ object: 'list', continuationToken: null })
  expect(res.data).toEqual([
    { object: 'organizationUserBulkResponse', id: invited, error: null },
    {
      object: 'organizationUserBulkResponse',
      id: confirmed,
      error: 'User has already accepted the invitation.',
    },
  ])
  expect(mb.sent.length).toBe(before + 1)
  expect(mb.sent[before]?.to).toBe('ox-inv-new@example.com')
  // Members cannot invite.
  expect(
    (await member.call(`/api/organizations/${id}/users/send-invite`, 'POST', { ids: [invited] }))
      .status,
  ).toBe(403)
})

it('refuses to complete Slack and Teams OAuth without an app, administrators only', async () => {
  const mb = mailbox()
  const owner = await actor('ox-int-owner@example.com', mb)
  const member = await actor('ox-int-member@example.com', mb)
  const { id } = await createOrg(owner)
  await addMember(owner, id, member, { type: 2 }, mb)
  for (const kind of ['slack', 'teams']) {
    const path = `/api/organizations/${id}/integrations/${kind}/complete`
    const res = await owner.call(path, 'POST', { code: 'c', state: 's' })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { message: string }).message).toContain(
      kind === 'slack' ? 'Slack' : 'Teams',
    )
    expect((await owner.call(path, 'POST', { code: 'c' })).status).toBe(400)
    expect((await member.call(path, 'POST', { code: 'c', state: 's' })).status).toBe(403)
  }
})

it('answers resend-self like the other sponsorship calls on a server without sponsorships', async () => {
  const owner = await actor('ox-spon-owner@example.com')
  const stranger = await actor('ox-spon-stranger@example.com')
  const { id } = await createOrg(owner)
  const path = `/api/organization/sponsorship/${id}/families-for-enterprise/resend-self`
  const res = await owner.call(path, 'POST')
  expect(res.status).toBe(400)
  expect(((await res.json()) as { message: string }).message).toContain('sponsorships')
  expect((await stranger.call(path, 'POST')).status).toBe(404)
})
