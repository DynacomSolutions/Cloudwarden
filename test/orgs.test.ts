import { SELF } from 'cloudflare:test'
import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { BASE, registerBody } from './helpers'
import { actor, addMember, createOrg, linkParams, type Mail, mailbox } from './org-helpers'

it('creates an organisation, shows it in the profile and sync, and updates it', async () => {
  const owner = await actor('org-owner@example.com')
  const { id, defaultCollectionId } = await createOrg(owner, 'Acme')

  const profile = await owner.json('/api/accounts/profile')
  expect(profile.organizations).toHaveLength(1)
  expect(profile.organizations[0]).toMatchObject({
    id,
    name: 'Acme',
    status: 2,
    type: 0,
    key: '4.ownerOrgKey',
    enabled: true,
    usePolicies: true,
    useGroups: true,
    useEvents: true,
    hasPublicAndPrivateKeys: true,
    userId: owner.uuid,
    object: 'profileOrganization',
  })

  const sync = await owner.json('/api/sync')
  expect(sync.collections).toHaveLength(1)
  expect(sync.collections[0]).toMatchObject({
    id: defaultCollectionId,
    organizationId: id,
    name: '2.defaultCollection',
    manage: true,
    readOnly: false,
  })

  const got = await owner.json(`/api/organizations/${id}`)
  expect(got).toMatchObject({ id, name: 'Acme', billingEmail: 'billing@example.com' })
  const upd = await owner.json(`/api/organizations/${id}`, 'PUT', {
    name: 'Acme Two',
    billingEmail: 'new@example.com',
  })
  expect(upd).toMatchObject({ name: 'Acme Two', billingEmail: 'new@example.com' })

  const keys = await owner.json(`/api/organizations/${id}/keys`)
  expect(keys).toMatchObject({ publicKey: 'orgPublic', privateKey: '2.orgPrivate' })

  // Deleting needs the master password.
  expect(
    (await owner.call(`/api/organizations/${id}`, 'DELETE', { masterPasswordHash: 'no' })).status,
  ).toBe(400)
  const del = await owner.call(`/api/organizations/${id}`, 'DELETE', {
    masterPasswordHash: 'client-derived-hash',
  })
  expect(del.status).toBe(200)
  expect((await owner.json('/api/accounts/profile')).organizations).toHaveLength(0)
  expect((await owner.call(`/api/organizations/${id}`)).status).toBe(404)
})

it('rejects an invalid organisation body', async () => {
  const owner = await actor('org-bad@example.com')
  expect((await owner.call('/api/organizations', 'POST', { name: 'x' })).status).toBe(400)
})

it('invites by email, accepts with the signed token, confirms and syncs', async () => {
  const mb = mailbox()
  const owner = await actor('inv-owner@example.com', mb)
  const member = await actor('inv-member@example.com', mb)
  const { id } = await createOrg(owner, 'Invite Co')

  const inv = await owner.call(`/api/organizations/${id}/users/invite`, 'POST', {
    emails: ['inv-member@example.com'],
    type: 2,
    accessAll: false,
    collections: [],
  })
  expect(inv.status).toBe(200)
  expect(mb.sent).toHaveLength(1)
  const msg = mb.sent[0] as Mail
  expect(msg.to).toBe('inv-member@example.com')
  expect(msg.text).toContain('https://vault.example.com/#/accept-organization?')
  const params = linkParams(msg)
  expect(params.get('organizationId')).toBe(id)
  expect(params.get('email')).toBe('inv-member@example.com')
  expect(params.get('organizationName')).toBe('Invite Co')
  const orgUserId = params.get('organizationUserId') as string
  const token = params.get('token') as string

  // The invited user is not in the profile until they accept.
  expect((await member.json('/api/accounts/profile')).organizations).toHaveLength(0)

  // Wrong user, bad token and a token for another member are all refused.
  const other = await actor('inv-other@example.com', mb)
  expect(
    (await other.call(`/api/organizations/${id}/users/${orgUserId}/accept`, 'POST', { token }))
      .status,
  ).toBe(400)
  expect(
    (
      await member.call(`/api/organizations/${id}/users/${orgUserId}/accept`, 'POST', {
        token: 'x.y.z',
      })
    ).status,
  ).toBe(400)

  // The policies list can be read with the token before accepting.
  const polUrl = (t: string) =>
    `${BASE}/api/organizations/${id}/policies/token?${new URLSearchParams({ email: 'inv-member@example.com', token: t, organizationUserId: orgUserId })}`
  expect((await SELF.fetch(polUrl(token))).status).toBe(200)
  expect((await SELF.fetch(polUrl('a.b.c'))).status).toBe(400)

  const accepted = await member.call(`/api/organizations/${id}/users/${orgUserId}/accept`, 'POST', {
    token,
  })
  expect(accepted.status).toBe(200)
  // Reusing the token fails.
  expect(
    (await member.call(`/api/organizations/${id}/users/${orgUserId}/accept`, 'POST', { token }))
      .status,
  ).toBe(400)

  // Accepted but not confirmed: the member has no key and sees nothing.
  const pre = await member.json('/api/accounts/profile')
  expect(pre.organizations[0]).toMatchObject({ status: 1, key: null })

  const keys = await owner.json(`/api/organizations/${id}/users/public-keys`, 'POST', {
    ids: [orgUserId],
  })
  expect(keys.data[0]).toMatchObject({ id: orgUserId, userId: member.uuid, key: 'public-key' })
  const conf = await owner.call(`/api/organizations/${id}/users/${orgUserId}/confirm`, 'POST', {
    key: '4.theirKey',
  })
  expect(conf.status).toBe(200)

  const post = await member.json('/api/accounts/profile')
  expect(post.organizations[0]).toMatchObject({ status: 2, key: '4.theirKey', type: 2 })

  const users = await owner.json(
    `/api/organizations/${id}/users?includeCollections=true&includeGroups=true`,
  )
  expect(users.data).toHaveLength(2)
  const row = users.data.find((u: any) => u.id === orgUserId)
  expect(row).toMatchObject({
    email: 'inv-member@example.com',
    status: 2,
    type: 2,
    userId: member.uuid,
  })
  expect(row.collections).toEqual([])
  expect(row.groups).toEqual([])
})

it('lets an unregistered address register while signups are closed after an invite', async () => {
  const mb = mailbox()
  const owner = await actor('closed-owner@example.com', mb)
  const { id } = await createOrg(owner)
  const inv = await owner.call(`/api/organizations/${id}/users/invite`, 'POST', {
    emails: ['closed-new@example.com'],
    type: 2,
  })
  expect(inv.status).toBe(200)
  const { withEnv } = await import('./helpers')
  const closed = { SIGNUPS_ALLOWED: 'false', EMAIL: mb.EMAIL, MAIL_FROM: mb.MAIL_FROM }
  // The invitation says who may register; the verification token proves the mailbox.
  const verification = await withEnv(
    closed,
    '/identity/accounts/register/send-verification-email',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'closed-new@example.com' }),
    },
  )
  expect(verification.status).toBe(204)
  const verifyMail = mb.sent[mb.sent.length - 1]
  const emailVerificationToken = new URLSearchParams(
    (/https?:\/\/\S+/.exec(verifyMail?.text ?? '')?.[0] ?? '').split('?')[1],
  ).get('token') as string
  const reg = await withEnv(closed, '/identity/accounts/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(registerBody('closed-new@example.com', { emailVerificationToken })),
  })
  expect(reg.status).toBe(200)

  // The new account can accept with the emailed token.
  const params = linkParams(mb.sent[0])
  const { login } = await import('./helpers')
  const s = (await (await login('closed-new@example.com')).json()) as { access_token: string }
  const { default: app } = await import('../src/index')
  const res = await app.fetch(
    new Request(
      `https://vault.example.com/api/organizations/${id}/users/${params.get('organizationUserId')}/accept`,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${s.access_token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: params.get('token') }),
      },
    ),
    env,
  )
  expect(res.status).toBe(200)
})

it('denies a plain user the management endpoints', async () => {
  const owner = await actor('deny-owner@example.com')
  const user = await actor('deny-user@example.com')
  const outsider = await actor('deny-outsider@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  await addMember(owner, id, user, { type: 2 })

  const denied = [
    ['GET', `/api/organizations/${id}`],
    ['PUT', `/api/organizations/${id}`, { name: 'x' }],
    ['GET', `/api/organizations/${id}/users`],
    ['POST', `/api/organizations/${id}/users/invite`, { emails: ['a@example.com'], type: 2 }],
    ['POST', `/api/organizations/${id}/collections`, { name: '2.new' }],
    ['DELETE', `/api/organizations/${id}/collections/${defaultCollectionId}`],
    ['GET', `/api/organizations/${id}/policies`],
    ['PUT', `/api/organizations/${id}/policies/0`, { enabled: true }],
    ['GET', `/api/organizations/${id}/groups`],
    ['GET', `/api/organizations/${id}/events`],
    ['DELETE', `/api/organizations/${id}`, { masterPasswordHash: 'client-derived-hash' }],
  ] as const
  for (const [method, path, body] of denied) {
    const res = await user.call(path, method, body)
    expect([path, res.status]).toEqual([path, 403])
  }
  // A plain user also cannot see a collection they were never given.
  expect(
    (await user.call(`/api/organizations/${id}/collections/${defaultCollectionId}`)).status,
  ).toBe(404)

  // Outsiders cannot even tell the organisation exists.
  for (const path of [
    `/api/organizations/${id}`,
    `/api/organizations/${id}/users`,
    `/api/organizations/${id}/keys`,
  ]) {
    expect((await outsider.call(path)).status).toBe(404)
  }
})

it('manages roles: update, revoke, restore, remove and the last owner guard', async () => {
  const owner = await actor('role-owner@example.com')
  const admin = await actor('role-admin@example.com')
  const user = await actor('role-user@example.com')
  const { id } = await createOrg(owner)
  const adminMember = await addMember(owner, id, admin, { type: 1 })
  const userMember = await addMember(owner, id, user, { type: 2 })

  // An admin can manage users but not owners.
  const ownerRow = (await owner.json(`/api/organizations/${id}/users`)).data.find(
    (u: any) => u.userId === owner.uuid,
  )
  expect(
    (await admin.call(`/api/organizations/${id}/users/${ownerRow.id}`, 'PUT', { type: 2 })).status,
  ).toBe(403)
  expect(
    (await admin.call(`/api/organizations/${id}/users/${ownerRow.id}/revoke`, 'PUT')).status,
  ).toBe(400)
  // The only owner cannot demote themselves.
  expect(
    (await owner.call(`/api/organizations/${id}/users/${ownerRow.id}`, 'PUT', { type: 1 })).status,
  ).toBe(400)
  // Only an owner can create owners.
  expect(
    (await admin.call(`/api/organizations/${id}/users/${userMember}`, 'PUT', { type: 0 })).status,
  ).toBe(403)

  const custom = await owner.call(`/api/organizations/${id}/users/${userMember}`, 'PUT', {
    type: 4,
    permissions: { accessEventLogs: true, createNewCollections: true },
  })
  expect(custom.status).toBe(200)
  const asCustom = await user.json('/api/accounts/profile')
  expect(asCustom.organizations[0]).toMatchObject({
    type: 4,
    permissions: { accessEventLogs: true, manageUsers: false },
  })
  expect((await user.call(`/api/organizations/${id}/events`)).status).toBe(200)
  expect((await user.call(`/api/organizations/${id}/users`)).status).toBe(200)
  expect((await user.call(`/api/organizations/${id}/policies`)).status).toBe(403)

  const revoked = await owner.call(`/api/organizations/${id}/users/${userMember}/revoke`, 'PUT')
  expect(revoked.status).toBe(200)
  expect((await user.json('/api/accounts/profile')).organizations[0].status).toBe(-1)
  expect((await user.call(`/api/organizations/${id}`)).status).toBe(404)
  const restored = await owner.call(`/api/organizations/${id}/users/${userMember}/restore`, 'PUT')
  expect(restored.status).toBe(200)
  expect((await user.json('/api/accounts/profile')).organizations[0].status).toBe(2)

  const bulk = await owner.json(`/api/organizations/${id}/users`, 'DELETE', {
    ids: [userMember, crypto.randomUUID()],
  })
  expect(bulk.data[0]).toMatchObject({ id: userMember, error: null })
  expect(bulk.data[1].error).toBeTruthy()
  expect((await user.json('/api/accounts/profile')).organizations).toHaveLength(0)

  const rm = await owner.call(`/api/organizations/${id}/users/${adminMember}`, 'DELETE')
  expect(rm.status).toBe(200)

  // Leaving as the last owner is refused, and so is deleting the account.
  expect((await owner.call(`/api/organizations/${id}/leave`, 'POST')).status).toBe(400)
  const del = await owner.call('/api/accounts', 'DELETE', {
    masterPasswordHash: 'client-derived-hash',
  })
  expect(del.status).toBe(400)
})

it('reinvites with a fresh email and rejects duplicate invitations', async () => {
  const mb = mailbox()
  const owner = await actor('re-owner@example.com', mb)
  const { id } = await createOrg(owner)
  const body = { emails: ['re-guest@example.com'], type: 2 }
  expect((await owner.call(`/api/organizations/${id}/users/invite`, 'POST', body)).status).toBe(200)
  expect((await owner.call(`/api/organizations/${id}/users/invite`, 'POST', body)).status).toBe(400)
  const orgUserId = linkParams(mb.sent[0]).get('organizationUserId')
  expect(
    (await owner.call(`/api/organizations/${id}/users/${orgUserId}/reinvite`, 'POST')).status,
  ).toBe(200)
  expect(mb.sent).toHaveLength(2)
  const bulk = await owner.json(`/api/organizations/${id}/users/reinvite`, 'POST', {
    ids: [orgUserId],
  })
  expect(bulk.data[0].error).toBeNull()
  expect(mb.sent).toHaveLength(3)
  // Revoking an invitation that was never accepted is refused.
  expect(
    (await owner.call(`/api/organizations/${id}/users/${orgUserId}/revoke`, 'PUT')).status,
  ).toBe(400)
})

it('serves self-host billing metadata for the member dialogs to member managers only', async () => {
  const owner = await actor('meta-owner@example.com')
  const user = await actor('meta-user@example.com')
  const { id } = await createOrg(owner, 'Meta')
  await addMember(owner, id, user)
  const path = `/api/organizations/${id}/billing/vnext/self-host/metadata`
  expect(await owner.json(path)).toEqual({
    object: 'organizationBillingMetadata',
    isOnSecretsManagerStandalone: false,
    organizationOccupiedSeats: 2,
  })
  expect((await user.call(path)).status).toBe(403)
})

// TASKS #385: the web client reloads the members list right after the invite dialog closes. The
// read must already contain the invited rows (new address and existing account) and must not be
// cacheable, in the same shape the Members page requests it.
it('lists freshly invited members at once, uncached, for new and existing accounts', async () => {
  const mb = mailbox()
  const owner = await actor('fresh-owner@example.com', mb)
  await actor('fresh-existing@example.com', mb)
  const { id } = await createOrg(owner, 'Fresh Co')

  const before = await owner.call(`/api/organizations/${id}/users?includeGroups=true`)
  expect(before.status).toBe(200)
  expect(((await before.json()) as { data: unknown[] }).data).toHaveLength(1)

  const inv = await owner.call(`/api/organizations/${id}/users/invite`, 'POST', {
    emails: ['fresh-new@example.com', 'fresh-existing@example.com'],
    type: 2,
  })
  expect(inv.status).toBe(200)

  const after = await owner.call(`/api/organizations/${id}/users?includeGroups=true`)
  expect(after.status).toBe(200)
  expect(after.headers.get('cache-control')).toContain('no-store')
  const rows = ((await after.json()) as { data: { email: string; status: number }[] }).data
  const invited = rows.filter((r) => r.status === 0).map((r) => r.email)
  expect(invited.sort()).toEqual(['fresh-existing@example.com', 'fresh-new@example.com'])
  expect(rows).toHaveLength(3)
})
