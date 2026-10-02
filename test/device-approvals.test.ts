import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { json } from './helpers'
import { type Actor, actor, addMember, createOrg, mail } from './org-helpers'

const adminRequest = (a: Actor, deviceIdentifier = 'tde-device', email = a.email) =>
  a.call('/api/auth-requests/admin-request', 'POST', {
    email,
    deviceIdentifier,
    publicKey: 'devicePublicKey',
    type: 2,
    accessCode: 'access-code',
  })

async function mailTo(to: string, from: number) {
  for (let i = 0; i < 200; i++) {
    if (mail.sent.slice(from).some((m) => m.to === to)) return
    await new Promise((r) => setTimeout(r, 10))
  }
  throw new Error(`no mail to ${to}`)
}

async function setup(prefix: string) {
  const owner = await actor(`${prefix}-owner@example.com`)
  const member = await actor(`${prefix}-member@example.com`)
  const { id: orgId } = await createOrg(owner)
  const memberId = await addMember(owner, orgId, member, { type: 2 })
  return { owner, member, orgId, memberId }
}

async function enrolled(prefix: string) {
  const s = await setup(prefix)
  await s.owner.json(`/api/organizations/${s.orgId}/policies/8`, 'PUT', {
    policy: { enabled: true, data: { autoEnrollEnabled: false } },
  })
  const r = await s.member.call(
    `/api/organizations/${s.orgId}/users/${s.member.uuid}/reset-password-enrollment`,
    'PUT',
    { resetPasswordKey: '4.recovery', masterPasswordHash: 'client-derived-hash' },
  )
  expect(r.status).toBe(200)
  return s
}

it('needs an enrolled membership to request admin approval', async () => {
  const { member } = await setup('da-none')
  expect((await adminRequest(member)).status).toBe(400)
  // The anonymous endpoint never creates admin requests.
  const anon = await json('/api/auth-requests/', {
    email: member.email,
    deviceIdentifier: 'x',
    publicKey: 'p',
    type: 2,
    accessCode: 'c',
  })
  expect(anon.status).toBe(400)
})

it('lists, approves and delivers an admin approval request', async () => {
  const { owner, member, orgId, memberId } = await enrolled('da-flow')
  // Another user's email is refused.
  expect((await adminRequest(member, 'tde-device', owner.email)).status).toBe(400)
  const before = mail.sent.length
  const res = await adminRequest(member)
  expect(res.status).toBe(200)
  const created = (await res.json()) as { id: string; requestApproved: unknown; key: unknown }
  expect(created.requestApproved).toBeNull()
  // Approvers are emailed (after the response).
  await mailTo(owner.email, before)

  // The user's own devices never see or answer admin requests.
  const pending = await member.json('/api/auth-requests/pending')
  expect(pending.data.find((r: { id: string }) => r.id === created.id)).toBeUndefined()
  const selfAnswer = await member.call(`/api/auth-requests/${created.id}`, 'PUT', {
    key: '4.self',
    deviceIdentifier: 'device-1',
    requestApproved: true,
  })
  expect(selfAnswer.status).toBe(404)

  const list = await owner.json(`/api/organizations/${orgId}/auth-requests`)
  expect(list.data).toHaveLength(1)
  expect(list.data[0]).toMatchObject({
    id: created.id,
    userId: member.uuid,
    organizationUserId: memberId,
    email: member.email,
    publicKey: 'devicePublicKey',
    requestDeviceIdentifier: 'tde-device',
  })
  expect(list.data[0].key).toBeUndefined()

  // Approving needs a key.
  const noKey = await owner.call(
    `/api/organizations/${orgId}/auth-requests/${created.id}`,
    'POST',
    {
      requestApproved: true,
    },
  )
  expect(noKey.status).toBe(400)
  const ok = await owner.call(`/api/organizations/${orgId}/auth-requests/${created.id}`, 'POST', {
    requestApproved: true,
    encryptedUserKey: '4.userKeyForDevice',
  })
  expect(ok.status).toBe(200)
  // The requesting device reads the answer.
  const polled = await member.json(`/api/auth-requests/${created.id}`)
  expect(polled).toMatchObject({
    requestApproved: true,
    key: '4.userKeyForDevice',
    isAnswered: true,
  })
  // It cannot be answered twice and is no longer listed.
  const twice = await owner.call(
    `/api/organizations/${orgId}/auth-requests/${created.id}`,
    'POST',
    {
      requestApproved: false,
    },
  )
  expect(twice.status).toBe(404)
  expect((await owner.json(`/api/organizations/${orgId}/auth-requests`)).data).toHaveLength(0)
  // An admin request can never be redeemed at the token endpoint as a login with device.
  const redeem = await (await import('./helpers')).login(member.email, 'access-code', {
    authRequest: created.id,
    deviceIdentifier: 'tde-device',
  })
  expect(redeem.status).toBe(400)

  const events = await owner.json(`/api/organizations/${orgId}/events`)
  const types = events.data.map((e: { type: number }) => e.type)
  expect(types).toContain(1010)
  expect(types).toContain(1513)
})

it('denies in bulk and answers through the bulk endpoint', async () => {
  const { owner, member, orgId } = await enrolled('da-bulk')
  const a = (await (await adminRequest(member, 'd1')).json()) as { id: string }
  const b = (await (await adminRequest(member, 'd2')).json()) as { id: string }
  const c = (await (await adminRequest(member, 'd3')).json()) as { id: string }
  expect(
    (await owner.call(`/api/organizations/${orgId}/auth-requests/deny`, 'POST', { ids: [a.id] }))
      .status,
  ).toBe(200)
  expect((await member.json(`/api/auth-requests/${a.id}`)).requestApproved).toBe(false)
  const bulk = await owner.json(`/api/organizations/${orgId}/auth-requests`, 'POST', [
    { id: b.id, approved: true, encryptedUserKey: '4.k' },
    { id: c.id, approved: true },
    { id: '00000000-0000-4000-8000-000000000000', approved: false },
  ])
  expect(bulk.data).toEqual([
    { id: b.id, error: null },
    { id: c.id, error: 'An encrypted user key is required to approve.' },
    { id: '00000000-0000-4000-8000-000000000000', error: 'Auth request not found.' },
  ])
  expect((await member.json(`/api/auth-requests/${b.id}`)).key).toBe('4.k')
  expect((await owner.json(`/api/organizations/${orgId}/auth-requests`)).data).toHaveLength(1)
  const events = await owner.json(`/api/organizations/${orgId}/events`)
  expect(events.data.map((e: { type: number }) => e.type)).toContain(1514)
})

it('keeps device approvals to authorised administrators of the right organisation', async () => {
  const { owner, member, orgId } = await enrolled('da-sec')
  const other = await actor('da-sec-other-owner@example.com')
  const { id: otherOrg } = await createOrg(other)
  const plainUser = await actor('da-sec-user@example.com')
  await addMember(owner, orgId, plainUser, { type: 2 })
  const admin = await actor('da-sec-admin@example.com')
  const adminId = await addMember(owner, orgId, admin, { type: 1 })

  const req = (await (await adminRequest(member)).json()) as { id: string }
  // Members without manageResetPassword and outsiders cannot list or answer.
  expect((await plainUser.call(`/api/organizations/${orgId}/auth-requests`)).status).toBe(403)
  expect((await other.call(`/api/organizations/${orgId}/auth-requests`)).status).toBe(404)
  const cross = await other.call(`/api/organizations/${otherOrg}/auth-requests/${req.id}`, 'POST', {
    requestApproved: true,
    encryptedUserKey: '4.evil',
  })
  // The other organisation has no recovery policy, and the request is not its member's anyway.
  expect([400, 404]).toContain(cross.status)
  await other.json(`/api/organizations/${otherOrg}/policies/8`, 'PUT', {
    policy: { enabled: true, data: {} },
  })
  const cross2 = await other.call(
    `/api/organizations/${otherOrg}/auth-requests/${req.id}`,
    'POST',
    {
      requestApproved: true,
      encryptedUserKey: '4.evil',
    },
  )
  expect(cross2.status).toBe(404)
  expect((await other.json(`/api/organizations/${otherOrg}/auth-requests`)).data).toHaveLength(0)

  // An admin's own request is invisible to other admins below owner rank... admins cannot approve
  // owners, and the owner request below only shows to owners.
  await admin.call(
    `/api/organizations/${orgId}/users/${admin.uuid}/reset-password-enrollment`,
    'PUT',
    {
      resetPasswordKey: '4.adminRecovery',
      masterPasswordHash: 'client-derived-hash',
    },
  )
  await owner.call(
    `/api/organizations/${orgId}/users/${owner.uuid}/reset-password-enrollment`,
    'PUT',
    {
      resetPasswordKey: '4.ownerRecovery',
      masterPasswordHash: 'client-derived-hash',
    },
  )
  const ownerReq = (await (await adminRequest(owner, 'owner-dev')).json()) as { id: string }
  const seenByAdmin = await admin.json(`/api/organizations/${orgId}/auth-requests`)
  expect(seenByAdmin.data.map((r: { id: string }) => r.id)).not.toContain(ownerReq.id)
  const adminApprovesOwner = await admin.call(
    `/api/organizations/${orgId}/auth-requests/${ownerReq.id}`,
    'POST',
    { requestApproved: true, encryptedUserKey: '4.evil' },
  )
  expect(adminApprovesOwner.status).toBe(404)
  // The admin's own request cannot be approved by themselves.
  const adminReq = (await (await adminRequest(admin, 'admin-dev')).json()) as { id: string }
  const selfApprove = await admin.call(
    `/api/organizations/${orgId}/auth-requests/${adminReq.id}`,
    'POST',
    {
      requestApproved: true,
      encryptedUserKey: '4.evil',
    },
  )
  expect(selfApprove.status).toBe(404)
  expect(adminId).toBeTruthy()

  // Revoked or withdrawn members drop out of the list.
  await member.call(
    `/api/organizations/${orgId}/users/${member.uuid}/reset-password-enrollment`,
    'PUT',
    {
      resetPasswordKey: '',
      masterPasswordHash: 'ignored',
    },
  )
  const after = await owner.json(`/api/organizations/${orgId}/auth-requests`)
  expect(after.data.map((r: { id: string }) => r.id)).not.toContain(req.id)
})

it('expires admin requests after seven days, not fifteen minutes', async () => {
  const { owner, member, orgId } = await enrolled('da-expiry')
  const req = (await (await adminRequest(member)).json()) as { id: string }
  const hour = 3600 * 1000
  await env.DB.prepare('UPDATE auth_requests SET created_at = ?1 WHERE uuid = ?2')
    .bind(Date.now() - hour, req.id)
    .run()
  expect((await owner.json(`/api/organizations/${orgId}/auth-requests`)).data).toHaveLength(1)
  await env.DB.prepare('UPDATE auth_requests SET created_at = ?1 WHERE uuid = ?2')
    .bind(Date.now() - 8 * 24 * hour, req.id)
    .run()
  expect((await owner.json(`/api/organizations/${orgId}/auth-requests`)).data).toHaveLength(0)
  const late = await owner.call(`/api/organizations/${orgId}/auth-requests/${req.id}`, 'POST', {
    requestApproved: true,
    encryptedUserKey: '4.k',
  })
  expect(late.status).toBe(404)
  expect((await member.json(`/api/auth-requests/${req.id}`)).isExpired).toBe(true)
})
