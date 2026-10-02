import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { authed, login } from './helpers'
import {
  type Actor,
  actor,
  addMember,
  createOrg,
  enableRecoveryPolicy,
  linkParams,
  mail,
} from './org-helpers'

const PASSWORD = 'client-derived-hash'
const RECOVERY_KEY = '4.recoveryKeyWrappedForOrg'

const enablePolicy = (owner: Actor, orgId: string, autoEnrollEnabled = false) =>
  enableRecoveryPolicy(owner, orgId, autoEnrollEnabled)

const enroll = (m: Actor, orgId: string, key: string | null = RECOVERY_KEY, hash = PASSWORD) =>
  m.call(`/api/organizations/${orgId}/users/${m.uuid}/reset-password-enrollment`, 'PUT', {
    resetPasswordKey: key,
    masterPasswordHash: hash,
  })

const nested = (email: string, hash: string, key: string) => ({
  authenticationData: {
    salt: email,
    kdf: { kdfType: 0, iterations: 600000 },
    masterPasswordAuthenticationHash: hash,
  },
  unlockData: {
    salt: email,
    kdf: { kdfType: 0, iterations: 600000 },
    masterKeyWrappedUserKey: key,
  },
})

async function setup(prefix: string, memberType = 2) {
  const owner = await actor(`${prefix}-owner@example.com`)
  const member = await actor(`${prefix}-member@example.com`)
  const { id: orgId } = await createOrg(owner)
  const memberId = await addMember(owner, orgId, member, { type: memberType })
  return { owner, member, orgId, memberId }
}

it('advertises account recovery and serves the org public key to joining members', async () => {
  const { owner, member, orgId } = await setup('ar-flags')
  const sync = await member.json('/api/sync')
  const profileOrg = sync.profile.organizations.find((o: { id: string }) => o.id === orgId)
  expect(profileOrg).toMatchObject({ useResetPassword: true, resetPasswordEnrolled: false })
  expect(sync.profile.forcePasswordReset).toBe(false)
  const keys = await member.json(`/api/organizations/${orgId}/keys`)
  expect(keys).toMatchObject({ publicKey: 'orgPublic', privateKey: '2.orgPrivate' })

  // An invited (not yet accepted) person gets the public key only.
  const invitee = await actor('ar-flags-invitee@example.com')
  await owner.call(`/api/organizations/${orgId}/users/invite`, 'POST', {
    emails: [invitee.email],
    type: 2,
    collections: [],
    groups: [],
  })
  const invitedKeys = await invitee.json(`/api/organizations/${orgId}/keys`)
  expect(invitedKeys).toMatchObject({ publicKey: 'orgPublic', privateKey: null })
  // A stranger gets nothing.
  const stranger = await actor('ar-flags-stranger@example.com')
  expect((await stranger.call(`/api/organizations/${orgId}/keys`)).status).toBe(404)
})

it('enrols, resets, forces a password change and clears the flag', async () => {
  const { owner, member, orgId, memberId } = await setup('ar-flow')

  // No policy: enrolment is refused.
  expect((await enroll(member, orgId)).status).toBe(400)
  await enablePolicy(owner, orgId)
  // Enrolment needs the master password.
  expect((await enroll(member, orgId, RECOVERY_KEY, 'wrong')).status).toBe(400)
  // Nobody enrols someone else.
  const other = await owner.call(
    `/api/organizations/${orgId}/users/${member.uuid}/reset-password-enrollment`,
    'PUT',
    { resetPasswordKey: RECOVERY_KEY, masterPasswordHash: PASSWORD },
  )
  expect(other.status).toBe(404)
  expect((await enroll(member, orgId)).status).toBe(200)

  const sync = await member.json('/api/sync')
  expect(
    sync.profile.organizations.find((o: { id: string }) => o.id === orgId).resetPasswordEnrolled,
  ).toBe(true)
  const listed = await owner.json(`/api/organizations/${orgId}/users`)
  expect(listed.data.find((m: { id: string }) => m.id === memberId).resetPasswordEnrolled).toBe(
    true,
  )

  const details = await owner.json(
    `/api/organizations/${orgId}/users/${memberId}/reset-password-details`,
  )
  expect(details).toMatchObject({
    object: 'organizationUserResetPasswordDetails',
    organizationUserId: memberId,
    kdf: 0,
    kdfIterations: 600000,
    masterPasswordSalt: member.email,
    resetPasswordKey: RECOVERY_KEY,
    encryptedPrivateKey: '2.orgPrivate',
  })
  const many = await owner.json(
    `/api/organizations/${orgId}/users/account-recovery-details`,
    'POST',
    {
      ids: [memberId],
    },
  )
  expect(many.data).toHaveLength(1)

  // The salt must be the member's email.
  const badSalt = await owner.call(
    `/api/organizations/${orgId}/users/${memberId}/recover-account`,
    'PUT',
    {
      resetMasterPassword: true,
      resetTwoFactor: false,
      ...nested(owner.email, 'temp-hash', '2.newKey'),
    },
  )
  expect(badSalt.status).toBe(400)

  const before = mail.sent.length
  const reset = await owner.call(
    `/api/organizations/${orgId}/users/${memberId}/recover-account`,
    'PUT',
    {
      resetMasterPassword: true,
      resetTwoFactor: false,
      ...nested(member.email, 'temp-hash', '2.newKey'),
    },
  )
  expect(reset.status).toBe(200)
  // The member's old session ends and the old password no longer works.
  expect((await authed('/api/sync', member.token)).status).toBe(401)
  expect((await login(member.email)).status).toBe(400)
  for (let i = 0; i < 200 && !mail.sent.slice(before).some((m) => m.to === member.email); i++) {
    await new Promise((r) => setTimeout(r, 10))
  }
  expect(mail.sent.slice(before).some((m) => m.to === member.email)).toBe(true)

  const tokenRes = await login(member.email, 'temp-hash')
  expect(tokenRes.status).toBe(200)
  const token = (await tokenRes.json()) as Record<string, unknown>
  expect(token.ForcePasswordReset).toBe(true)
  expect(token.Key).toBe('2.newKey')
  const profile = (await (
    await authed('/api/accounts/profile', token.access_token as string)
  ).json()) as {
    forcePasswordReset: boolean
  }
  expect(profile.forcePasswordReset).toBe(true)

  const update = await authed(
    '/api/accounts/update-temp-password',
    token.access_token as string,
    'PUT',
    { ...nested(member.email, 'final-hash', '2.finalKey'), masterPasswordHint: 'new hint' },
  )
  expect(update.status).toBe(200)
  const again = await login(member.email, 'final-hash')
  expect(again.status).toBe(200)
  const final = (await again.json()) as Record<string, unknown>
  expect(final.ForcePasswordReset).toBe(false)
  expect(final.Key).toBe('2.finalKey')
  // Without a pending reset the endpoint refuses.
  const twice = await authed(
    '/api/accounts/update-temp-password',
    final.access_token as string,
    'PUT',
    nested(member.email, 'x', '2.x'),
  )
  expect(twice.status).toBe(400)

  const events = await owner.json(`/api/organizations/${orgId}/events`)
  const types = events.data.map((e: { type: number }) => e.type)
  expect(types).toContain(1506)
  expect(types).toContain(1508)
})

it('resets two-step login through recover-account and accepts the legacy reset body', async () => {
  const { owner, member, orgId, memberId } = await setup('ar-2fa')
  await enablePolicy(owner, orgId)
  expect((await enroll(member, orgId)).status).toBe(200)
  await env.DB.prepare(
    "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data, last_used) VALUES ('00000000-0000-4000-8000-0000000000aa', ?1, 0, 1, '{}', 0)",
  )
    .bind(member.uuid)
    .run()
  const only2fa = await owner.call(
    `/api/organizations/${orgId}/users/${memberId}/recover-account`,
    'PUT',
    { resetMasterPassword: false, resetTwoFactor: true },
  )
  expect(only2fa.status).toBe(200)
  const left = await env.DB.prepare('SELECT count(*) AS n FROM twofactor WHERE user_uuid = ?1')
    .bind(member.uuid)
    .first<{ n: number }>()
  expect(left?.n).toBe(0)
  // The password is untouched and no change is forced.
  const tok = (await (await login(member.email)).json()) as Record<string, unknown>
  expect(tok.ForcePasswordReset).toBe(false)

  const nothing = await owner.call(
    `/api/organizations/${orgId}/users/${memberId}/recover-account`,
    'PUT',
    { resetMasterPassword: false, resetTwoFactor: false },
  )
  expect(nothing.status).toBe(400)

  const legacy = await owner.call(
    `/api/organizations/${orgId}/users/${memberId}/reset-password`,
    'PUT',
    { newMasterPasswordHash: 'legacy-hash', key: '2.legacyKey' },
  )
  expect(legacy.status).toBe(200)
  const t2 = (await (await login(member.email, 'legacy-hash')).json()) as Record<string, unknown>
  expect(t2.ForcePasswordReset).toBe(true)
  const events = await owner.json(`/api/organizations/${orgId}/events`)
  expect(events.data.map((e: { type: number }) => e.type)).toContain(1519)
})

it('only lets authorised administrators recover, and never their superiors', async () => {
  const owner = await actor('ar-sec-owner@example.com')
  const admin = await actor('ar-sec-admin@example.com')
  const user = await actor('ar-sec-user@example.com')
  const custom = await actor('ar-sec-custom@example.com')
  const plainCustom = await actor('ar-sec-custom2@example.com')
  const outsider = await actor('ar-sec-outsider@example.com')
  const { id: orgId } = await createOrg(owner)
  const adminId = await addMember(owner, orgId, admin, { type: 1 })
  const userId = await addMember(owner, orgId, user, { type: 2 })
  await addMember(owner, orgId, custom, {
    type: 4,
    permissions: { manageResetPassword: true },
  })
  await addMember(owner, orgId, plainCustom, { type: 4, permissions: { manageUsers: true } })
  const sync = await owner.json('/api/sync')
  const ownerMemberId = sync.profile.organizations.find((o: { id: string }) => o.id === orgId)
    .organizationUserId as string

  await enablePolicy(owner, orgId)
  for (const a of [owner, admin, user]) expect((await enroll(a, orgId)).status).toBe(200)

  const details = (a: Actor, id: string) =>
    a.call(`/api/organizations/${orgId}/users/${id}/reset-password-details`)
  const reset = (a: Actor, id: string) =>
    a.call(`/api/organizations/${orgId}/users/${id}/reset-password`, 'PUT', {
      newMasterPasswordHash: 'evil',
      key: '2.evil',
    })

  // Outsiders and members without the permission see nothing.
  expect((await details(outsider, userId)).status).toBe(404)
  expect((await details(user, adminId)).status).toBe(403)
  expect((await details(plainCustom, userId)).status).toBe(403)
  expect((await reset(plainCustom, userId)).status).toBe(403)
  expect((await reset(user, adminId)).status).toBe(403)
  // Admins cannot recover owners; custom members cannot recover admins or owners.
  expect((await details(admin, ownerMemberId)).status).toBe(403)
  expect((await reset(admin, ownerMemberId)).status).toBe(403)
  expect((await details(custom, adminId)).status).toBe(403)
  expect((await reset(custom, ownerMemberId)).status).toBe(403)
  // Nobody recovers themselves through the organisation.
  expect((await reset(admin, adminId)).status).toBe(400)
  // A custom member with the permission may recover a user.
  expect((await details(custom, userId)).status).toBe(200)
  // The bulk endpoint drops members the caller may not recover.
  const many = await admin.json(
    `/api/organizations/${orgId}/users/account-recovery-details`,
    'POST',
    {
      ids: [ownerMemberId, userId, adminId],
    },
  )
  expect(many.data.map((d: { organizationUserId: string }) => d.organizationUserId)).toEqual([
    userId,
  ])
  // Disabling the policy stops recovery even for enrolled members.
  await owner.json(`/api/organizations/${orgId}/policies/8`, 'PUT', { enabled: false, data: null })
  expect((await details(owner, userId)).status).toBe(400)
  expect((await reset(owner, userId)).status).toBe(400)
  // The password of the targets never changed.
  expect((await login(user.email)).status).toBe(200)
  expect((await login(owner.email)).status).toBe(200)
})

it('refuses to recover a member who is not enrolled', async () => {
  const { owner, orgId, memberId } = await setup('ar-notenrolled')
  await enablePolicy(owner, orgId)
  const r = await owner.call(`/api/organizations/${orgId}/users/${memberId}/reset-password-details`)
  expect(r.status).toBe(400)
})

it('enforces auto-enrolment on accept and blocks withdrawal', async () => {
  const owner = await actor('ar-auto-owner@example.com')
  const member = await actor('ar-auto-member@example.com')
  const { id: orgId } = await createOrg(owner)
  await enablePolicy(owner, orgId, true)
  const status = await owner.json(`/api/organizations/${orgId}/auto-enroll-status`)
  expect(status).toMatchObject({ id: orgId, resetPasswordEnabled: true })

  const before = mail.sent.length
  await owner.call(`/api/organizations/${orgId}/users/invite`, 'POST', {
    emails: [member.email],
    type: 2,
    collections: [],
    groups: [],
  })
  const params = linkParams(mail.sent[before])
  const id = params.get('organizationUserId') as string
  const noKey = await member.call(`/api/organizations/${orgId}/users/${id}/accept`, 'POST', {
    token: params.get('token'),
  })
  expect(noKey.status).toBe(400)
  const ok = await member.call(`/api/organizations/${orgId}/users/${id}/accept`, 'POST', {
    token: params.get('token'),
    resetPasswordKey: RECOVERY_KEY,
  })
  expect(ok.status).toBe(200)
  const listed = await owner.json(`/api/organizations/${orgId}/users`)
  expect(listed.data.find((m: { id: string }) => m.id === id).resetPasswordEnrolled).toBe(true)
  // Withdrawal (the client sends an empty key) is refused while auto-enrolment is on.
  expect((await enroll(member, orgId, '', 'ignored')).status).toBe(400)
  await enablePolicy(owner, orgId, false)
  expect((await enroll(member, orgId, '', 'ignored')).status).toBe(200)
  const after = await owner.json(`/api/organizations/${orgId}/users`)
  expect(after.data.find((m: { id: string }) => m.id === id).resetPasswordEnrolled).toBe(false)
})

it('re-wraps recovery keys during key rotation and withdraws them on the legacy rotation', async () => {
  const { owner, member, orgId, memberId } = await setup('ar-rotate')
  await enablePolicy(owner, orgId)
  expect((await enroll(member, orgId)).status).toBe(200)
  const rotation = (recovery: unknown) => ({
    oldMasterKeyAuthenticationHash: PASSWORD,
    accountUnlockData: {
      masterPasswordUnlockData: {
        kdfType: 0,
        kdfIterations: 600000,
        email: member.email,
        masterKeyAuthenticationHash: PASSWORD,
        masterKeyEncryptedUserKey: '2.rotatedUserKey',
      },
      passkeyUnlockData: [],
      emergencyAccessUnlockData: [],
      organizationAccountRecoveryUnlockData: recovery,
    },
    accountKeys: { userKeyEncryptedAccountPrivateKey: '2.pk2', accountPublicKey: 'public-key' },
    accountData: { ciphers: [], folders: [], sends: [] },
  })
  const missing = await authed(
    '/api/accounts/key-management/rotate-user-account-keys',
    member.token,
    'POST',
    rotation([]),
  )
  expect(missing.status).toBe(400)
  const ok = await authed(
    '/api/accounts/key-management/rotate-user-account-keys',
    member.token,
    'POST',
    rotation([
      {
        organizationId: orgId,
        resetPasswordKey: '4.rotatedRecovery',
        masterPasswordHash: 'ignored',
      },
    ]),
  )
  expect(ok.status).toBe(200)
  const d = await owner.json(`/api/organizations/${orgId}/users/${memberId}/reset-password-details`)
  expect(d.resetPasswordKey).toBe('4.rotatedRecovery')
})
