import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { authed, login, withEnv } from './helpers'
import { type Actor, actor, addMember, createOrg, enableRecoveryPolicy } from './org-helpers'

const PASSWORD = 'client-derived-hash'
const RECOVERY_KEY = '4.recoveryKeyWrappedForOrg'
const Revoked = -1
const Accepted = 1

const enroll = (m: Actor, orgId: string, key: string | null = RECOVERY_KEY, hash = PASSWORD) =>
  m.call(`/api/organizations/${orgId}/users/${m.uuid}/reset-password-enrollment`, 'PUT', {
    resetPasswordKey: key,
    masterPasswordHash: hash,
  })

const details = (a: Actor, orgId: string, id: string) =>
  a.call(`/api/organizations/${orgId}/users/${id}/reset-password-details`)

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

async function setup(prefix: string) {
  const owner = await actor(`${prefix}-owner@example.com`)
  const member = await actor(`${prefix}-member@example.com`)
  const { id: orgId } = await createOrg(owner)
  const memberId = await addMember(owner, orgId, member, { type: 2 })
  await enableRecoveryPolicy(owner, orgId)
  return { owner, member, orgId, memberId }
}

const setStatus = (memberId: string, status: number) =>
  env.DB.prepare('UPDATE users_organizations SET status = ?1 WHERE uuid = ?2')
    .bind(status, memberId)
    .run()

async function federate(memberId: string) {
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
    .bind(memberId, peer, now)
    .run()
}

it('recovers confirmed members only', async () => {
  const { owner, member, orgId, memberId } = await setup('ars-status')
  expect((await enroll(member, orgId)).status).toBe(200)
  expect((await details(owner, orgId, memberId)).status).toBe(200)
  for (const status of [Accepted, Revoked]) {
    await setStatus(memberId, status)
    expect((await details(owner, orgId, memberId)).status).toBe(400)
    const many = await owner.json(
      `/api/organizations/${orgId}/users/account-recovery-details`,
      'POST',
      { ids: [memberId] },
    )
    expect(many.data).toHaveLength(0)
  }
})

it('needs the single organisation policy for account recovery and keeps it on', async () => {
  const owner = await actor('ars-policy-owner@example.com')
  const { id: orgId } = await createOrg(owner)
  const put = (type: number, enabled: boolean) =>
    owner.call(`/api/organizations/${orgId}/policies/${type}`, 'PUT', { enabled, data: null })
  expect((await put(8, true)).status).toBe(400)
  expect((await put(3, true)).status).toBe(200)
  expect((await put(8, true)).status).toBe(200)
  expect((await put(3, false)).status).toBe(400)
  expect((await put(8, false)).status).toBe(200)
  expect((await put(3, false)).status).toBe(200)
})

it('refuses to recover members of another organisation unless that membership is revoked', async () => {
  const owner = await actor('ars-cross-owner@example.com')
  const otherOwner = await actor('ars-cross-other@example.com')
  const member = await actor('ars-cross-member@example.com')
  const { id: orgId } = await createOrg(owner)
  const { id: otherOrg } = await createOrg(otherOwner)
  const otherMember = await addMember(otherOwner, otherOrg, member, { type: 2 })
  const memberId = await addMember(owner, orgId, member, { type: 2 })
  await enableRecoveryPolicy(owner, orgId)
  expect((await enroll(member, orgId)).status).toBe(200)
  expect((await details(owner, orgId, memberId)).status).toBe(400)
  const reset = await owner.call(
    `/api/organizations/${orgId}/users/${memberId}/reset-password`,
    'PUT',
    { newMasterPasswordHash: 'evil', key: '2.evil' },
  )
  expect(reset.status).toBe(400)
  const many = await owner.json(
    `/api/organizations/${orgId}/users/account-recovery-details`,
    'POST',
    { ids: [memberId] },
  )
  expect(many.data).toHaveLength(0)
  expect((await login(member.email)).status).toBe(200)
  await setStatus(otherMember, Revoked)
  expect((await details(owner, orgId, memberId)).status).toBe(200)
})

it('keeps federated members and stand-in accounts out of account recovery', async () => {
  const { owner, member, orgId, memberId } = await setup('ars-fed')
  // Enrolment is refused for a federated membership.
  await federate(memberId)
  expect((await enroll(member, orgId)).status).toBe(400)

  // A membership enrolled before it was federated, and a stand-in account, cannot be recovered.
  await env.DB.prepare('DELETE FROM federation_members WHERE organization_user_uuid = ?1')
    .bind(memberId)
    .run()
  expect((await enroll(member, orgId)).status).toBe(200)
  expect((await details(owner, orgId, memberId)).status).toBe(200)
  await federate(memberId)
  expect((await details(owner, orgId, memberId)).status).toBe(400)
  await env.DB.prepare('DELETE FROM federation_members WHERE organization_user_uuid = ?1')
    .bind(memberId)
    .run()
  await env.DB.prepare("UPDATE users SET password_hash = '!federated.x' WHERE uuid = ?1")
    .bind(member.uuid)
    .run()
  expect((await details(owner, orgId, memberId)).status).toBe(400)
})

it('rate limits master password checks at enrolment', async () => {
  const { member, orgId } = await setup('ars-enrol-rl')
  let last = 0
  for (let i = 0; i < 25; i++) last = (await enroll(member, orgId, RECOVERY_KEY, 'wrong')).status
  expect(last).toBe(429)
})

it('rate limits the recovery routes', async () => {
  const { owner, orgId, memberId } = await setup('ars-route-rl')
  const res = await withEnv(
    { LOGIN_LIMITER: { limit: async () => ({ success: false }) } },
    `/api/organizations/${orgId}/users/${memberId}/reset-password-details`,
    { headers: { Authorization: `Bearer ${owner.token}`, 'CF-Connecting-IP': '203.0.113.9' } },
  )
  expect(res.status).toBe(429)
})

it('drops pending auth requests, rejects the temporary password and clears the flag on rotation', async () => {
  const { owner, member, orgId, memberId } = await setup('ars-after')
  expect((await enroll(member, orgId)).status).toBe(200)
  // A pending login-with-device request made with the old credentials.
  const created = await (await import('./helpers')).json('/api/auth-requests/', {
    email: member.email,
    deviceIdentifier: 'old-device',
    publicKey: 'p',
    type: 0,
    accessCode: 'c',
  })
  expect(created.status).toBe(200)
  const count = () =>
    env.DB.prepare('SELECT count(*) AS n FROM auth_requests WHERE user_uuid = ?1')
      .bind(member.uuid)
      .first<{ n: number }>()
  expect((await count())?.n).toBe(1)

  const recover = (hash: string) =>
    owner.call(`/api/organizations/${orgId}/users/${memberId}/recover-account`, 'PUT', {
      resetMasterPassword: true,
      resetTwoFactor: false,
      ...nested(member.email, hash, '2.newKey'),
    })
  expect((await recover('temp-hash')).status).toBe(200)
  expect((await count())?.n).toBe(0)

  const token = async (hash: string) =>
    ((await (await login(member.email, hash)).json()) as { access_token: string }).access_token
  // The temporary password cannot be kept.
  const same = await authed(
    '/api/accounts/update-temp-password',
    await token('temp-hash'),
    'PUT',
    nested(member.email, 'temp-hash', '2.k'),
  )
  expect(same.status).toBe(400)

  const flag = async () =>
    (
      await env.DB.prepare('SELECT force_password_reset AS f FROM users WHERE uuid = ?1')
        .bind(member.uuid)
        .first<{ f: number }>()
    )?.f
  expect(await flag()).toBe(1)
  // Changing the KDF replaces the password too and clears the flag.
  const kdf = await authed('/api/accounts/kdf', await token('temp-hash'), 'POST', {
    masterPasswordHash: 'temp-hash',
    ...nested(member.email, 'kdf-hash', '2.kdfKey'),
    authenticationData: {
      salt: member.email,
      kdf: { kdfType: 0, iterations: 650000 },
      masterPasswordAuthenticationHash: 'kdf-hash',
    },
    unlockData: {
      salt: member.email,
      kdf: { kdfType: 0, iterations: 650000 },
      masterKeyWrappedUserKey: '2.kdfKey',
    },
  })
  expect(kdf.status).toBe(200)
  expect(await flag()).toBe(0)

  // Key rotation with a new master password clears it as well.
  expect((await recover('temp2-hash')).status).toBe(200)
  expect(await flag()).toBe(1)
  const rotate = await authed(
    '/api/accounts/key-management/rotate-user-account-keys',
    await token('temp2-hash'),
    'POST',
    {
      oldMasterKeyAuthenticationHash: 'temp2-hash',
      accountUnlockData: {
        masterPasswordUnlockData: {
          kdfType: 0,
          kdfIterations: 650000,
          email: member.email,
          masterKeyAuthenticationHash: 'rot-hash',
          masterKeyEncryptedUserKey: '2.rotatedUserKey',
        },
        passkeyUnlockData: [],
        emergencyAccessUnlockData: [],
        organizationAccountRecoveryUnlockData: [
          { organizationId: orgId, resetPasswordKey: '4.rotated', masterPasswordHash: 'x' },
        ],
      },
      accountKeys: { userKeyEncryptedAccountPrivateKey: '2.pk2', accountPublicKey: 'public-key' },
      accountData: { ciphers: [], folders: [], sends: [] },
    },
  )
  expect(rotate.status).toBe(200)
  expect(await flag()).toBe(0)
})
