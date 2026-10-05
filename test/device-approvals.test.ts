import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { createDb, schema } from '../src/db'
import { freezeRateLimitWindow, json, waitFor } from './helpers'
import { type Actor, actor, addMember, createOrg, enableRecoveryPolicy, mail } from './org-helpers'

/** Enables SSO with trusted device decryption for an organisation (the admin approval context). */
const enableTde = (orgId: string, memberDecryptionType = 2) =>
  createDb(env.DB)
    .insert(schema.ssoConfigs)
    .values({
      organizationUuid: orgId,
      enabled: true,
      data: JSON.stringify({ memberDecryptionType }),
      createdAt: Date.now(),
      updatedAt: Date.now(),
    })
    .onConflictDoUpdate({
      target: schema.ssoConfigs.organizationUuid,
      set: { enabled: true, data: JSON.stringify({ memberDecryptionType }) },
    })

const adminRequest = (a: Actor, deviceIdentifier = 'tde-device', email = a.email) =>
  a.call('/api/auth-requests/admin-request', 'POST', {
    email,
    deviceIdentifier,
    publicKey: 'devicePublicKey',
    type: 2,
    accessCode: 'access-code',
  })

async function mailTo(to: string, from: number) {
  await waitFor(() => mail.sent.slice(from).some((m) => m.to === to), {
    message: `mail to ${to}`,
  })
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
  await enableRecoveryPolicy(s.owner, s.orgId)
  await enableTde(s.orgId)
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
  // One open admin request per user, so three requests need three enrolled members.
  const m2 = await actor('da-bulk-m2@example.com')
  const m3 = await actor('da-bulk-m3@example.com')
  for (const m of [m2, m3]) {
    await addMember(owner, orgId, m, { type: 2 })
    await m.call(`/api/organizations/${orgId}/users/${m.uuid}/reset-password-enrollment`, 'PUT', {
      resetPasswordKey: '4.recovery',
      masterPasswordHash: 'client-derived-hash',
    })
  }
  const a = (await (await adminRequest(member, 'd1')).json()) as { id: string }
  const b = (await (await adminRequest(m2, 'd2')).json()) as { id: string }
  const c = (await (await adminRequest(m3, 'd3')).json()) as { id: string }
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
  expect((await m2.json(`/api/auth-requests/${b.id}`)).key).toBe('4.k')
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
  await enableRecoveryPolicy(other, otherOrg)
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
  // Expired requests are gone for the requester too: nothing is delivered after expiry.
  expect((await member.call(`/api/auth-requests/${req.id}`)).status).toBe(404)
})

it('delivers an approved admin approval key once and never after expiry', async () => {
  const { owner, member, orgId } = await enrolled('da-once')
  const created = (await (await adminRequest(member)).json()) as { id: string }
  await owner.call(`/api/organizations/${orgId}/auth-requests/${created.id}`, 'POST', {
    requestApproved: true,
    encryptedUserKey: '4.userKeyForDevice',
  })
  const first = await member.json(`/api/auth-requests/${created.id}`)
  expect(first.key).toBe('4.userKeyForDevice')
  const second = await member.json(`/api/auth-requests/${created.id}`)
  expect(second).toMatchObject({ requestApproved: true, key: null })
  // The anonymous poll with the access code cannot fetch it again either.
  const polled = await json(
    `/api/auth-requests/${created.id}/response?code=access-code`,
    undefined,
    {
      method: 'GET',
    },
  )
  expect(((await polled.json()) as { key: unknown }).key).toBeNull()

  // An approved but unread request is not served once expired.
  const m2 = await actor('da-once-m2@example.com')
  await addMember(owner, orgId, m2, { type: 2 })
  await m2.call(`/api/organizations/${orgId}/users/${m2.uuid}/reset-password-enrollment`, 'PUT', {
    resetPasswordKey: '4.recovery',
    masterPasswordHash: 'client-derived-hash',
  })
  const r2 = (await (await adminRequest(m2)).json()) as { id: string }
  await owner.call(`/api/organizations/${orgId}/auth-requests/${r2.id}`, 'POST', {
    requestApproved: true,
    encryptedUserKey: '4.k2',
  })
  await env.DB.prepare('UPDATE auth_requests SET created_at = ?1 WHERE uuid = ?2')
    .bind(Date.now() - 8 * 24 * 3600 * 1000, r2.id)
    .run()
  expect((await m2.call(`/api/auth-requests/${r2.id}`)).status).toBe(404)
  const late = await json(`/api/auth-requests/${r2.id}/response?code=access-code`, undefined, {
    method: 'GET',
  })
  expect(late.status).toBe(404)
})

it('limits admin requests per user and keeps one open request', async () => {
  const restore = freezeRateLimitWindow()
  try {
    const { owner, member, orgId } = await enrolled('da-limit')
    const ids: string[] = []
    for (let i = 0; i < 5; i++) {
      const r = await adminRequest(member, `dev-${i}`)
      expect(r.status).toBe(200)
      ids.push(((await r.json()) as { id: string }).id)
    }
    expect((await adminRequest(member, 'dev-6')).status).toBe(429)
    // Only the latest request stays open; earlier ones were replaced.
    const list = await owner.json(`/api/organizations/${orgId}/auth-requests`)
    expect(list.data.map((r: { id: string }) => r.id)).toEqual([ids[4]])
    expect((await member.call(`/api/auth-requests/${ids[0]}`)).status).toBe(404)
  } finally {
    restore()
  }
})

it('needs trusted device decryption SSO, and refuses federated members', async () => {
  const noTde = await setup('da-notde')
  await enableRecoveryPolicy(noTde.owner, noTde.orgId)
  await noTde.member.call(
    `/api/organizations/${noTde.orgId}/users/${noTde.member.uuid}/reset-password-enrollment`,
    'PUT',
    { resetPasswordKey: '4.recovery', masterPasswordHash: 'client-derived-hash' },
  )
  // No SSO at all, then SSO with another decryption type: both refused.
  expect((await adminRequest(noTde.member)).status).toBe(400)
  await enableTde(noTde.orgId, 0)
  expect((await adminRequest(noTde.member)).status).toBe(400)
  await enableTde(noTde.orgId, 2)
  expect((await adminRequest(noTde.member)).status).toBe(200)

  // A federated membership or a stand-in account never asks for approval.
  const fed = await enrolled('da-fed')
  const now = Date.now()
  const peer = crypto.randomUUID()
  await env.DB.prepare(
    `INSERT INTO federation_peers (uuid, instance_id, domain, public_key, fingerprint, protocol_version, status, local_approved, remote_approved, created_at, updated_at)
     VALUES (?1, ?1, ?2, 'k', 'f', 1, 'active', 1, 1, ?3, ?3)`,
  )
    .bind(peer, `${peer}.example.com`, now)
    .run()
  await env.DB.prepare(
    `INSERT INTO federation_members (organization_user_uuid, peer_uuid, remote_email, created_at) VALUES (?1, ?2, 'r@example.com', ?3)`,
  )
    .bind(fed.memberId, peer, now)
    .run()
  expect((await adminRequest(fed.member)).status).toBe(400)
  const standIn = await enrolled('da-standin')
  await env.DB.prepare("UPDATE users SET password_hash = '!federated.x' WHERE uuid = ?1")
    .bind(standIn.member.uuid)
    .run()
  // The auth layer already turns stand-in accounts away from user routes.
  expect([400, 401]).toContain((await adminRequest(standIn.member)).status)
})

it('emails only confirmed approvers', async () => {
  const { owner, member, orgId } = await enrolled('da-mail')
  const pending = await actor('da-mail-pending@example.com')
  const pendingId = await addMember(owner, orgId, pending, { type: 1 })
  await env.DB.prepare('UPDATE users_organizations SET status = 1 WHERE uuid = ?1')
    .bind(pendingId)
    .run()
  const before = mail.sent.length
  expect((await adminRequest(member)).status).toBe(200)
  await mailTo(owner.email, before)
  expect(mail.sent.slice(before).some((m) => m.to === pending.email)).toBe(false)
})
