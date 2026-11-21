import { env } from 'cloudflare:workers'
import { expect, it, vi } from 'vitest'
import { authed, login } from './helpers'
import {
  type Actor,
  actor,
  addMember,
  createOrg,
  enableRecoveryPolicy,
  linkParams,
  mail,
  mailbox,
} from './org-helpers'

// Each test makes dozens of requests; a loaded CI host needs more than the 120 s default.
vi.setConfig({ testTimeout: 600_000 })

const PASSWORD = 'client-derived-hash'
const RECOVERY_KEY = '4.recoveryKeyWrappedForOrg'
const KDF = { kdfType: 0, iterations: 600000 }

const ROTATE = '/api/accounts/key-management/rotate-user-keys'

/** A `RotateUserKeysRequestModel` for a master password account. */
const rotation = (email: string, over: Record<string, unknown> = {}) => ({
  wrappedAccountCryptographicState: {
    publicKeyEncryptionKeyPair: { wrappedPrivateKey: '2.newPriv', publicKey: 'public-key' },
  },
  unlockData: { organizationAccountRecoveryUnlockData: [], passkeyUnlockData: [] },
  accountData: { ciphers: [], folders: [], sends: [] },
  unlockMethodData: {
    unlockMethod: 1,
    masterPasswordUnlockData: {
      kdf: KDF,
      masterKeyWrappedUserKey: '2.rotatedUserKey',
      salt: email,
    },
  },
  ...over,
})

/** Rotation sends a push after the batch, which needs an execution context: go through the worker. */
const rotate = (who: Actor, body: unknown) => authed(ROTATE, who.token, 'POST', body)

const enroll = (m: Actor, orgId: string) =>
  m.call(`/api/organizations/${orgId}/users/${m.uuid}/reset-password-enrollment`, 'PUT', {
    resetPasswordKey: RECOVERY_KEY,
    masterPasswordHash: PASSWORD,
  })

async function recoveryOrg(prefix: string) {
  const owner = await actor(`${prefix}-owner@example.com`)
  const member = await actor(`${prefix}-member@example.com`)
  const { id: orgId } = await createOrg(owner)
  await enableRecoveryPolicy(owner, orgId)
  const memberId = await addMember(owner, orgId, member, { type: 2 })
  expect((await enroll(member, orgId)).status).toBe(200)
  return { owner, member, orgId, memberId }
}

const memberRow = async (id: string) =>
  env.DB.prepare(
    'SELECT reset_password_key AS key, v2_upgrade_token AS token FROM users_organizations WHERE uuid = ?1',
  )
    .bind(id)
    .first<{ key: string | null; token: string | null }>()

it('serves PUT and POST verify-devices with the same proof', async () => {
  const user = await actor('km-verify@example.com')
  const put = (body: unknown) => user.call('/api/accounts/verify-devices', 'PUT', body)
  expect((await put({ verifyDevices: false })).status).toBe(400)
  expect((await put({ masterPasswordHash: 'wrong', verifyDevices: false })).status).toBe(400)
  expect((await put({ masterPasswordHash: PASSWORD, verifyDevices: false })).status).toBe(200)
  expect((await user.json('/api/accounts/profile')).verifyDevices).toBe(false)
  const post = await user.call('/api/accounts/verify-devices', 'POST', {
    masterPasswordHash: PASSWORD,
    verifyDevices: true,
  })
  expect(post.status).toBe(200)
  expect((await user.json('/api/accounts/profile')).verifyDevices).toBe(true)
  const anon = await authed('/api/accounts/verify-devices', 'bad-token', 'PUT', {
    masterPasswordHash: PASSWORD,
    verifyDevices: false,
  })
  expect(anon.status).toBe(401)
})

it('lists everything a key rotation must re-wrap', async () => {
  const mb = mailbox()
  const { owner, member, orgId } = await recoveryOrg('km-data')
  const empty = await owner.json('/api/accounts/key-management/key-rotation-data')
  expect(empty).toMatchObject({
    object: 'keyRotationData',
    organizationPasswordResetKeyData: [],
    emergencyAccessKeyData: [],
    trustedDeviceKeyData: [],
    passkeyKeyData: [],
  })

  // An emergency contact with a confirmed key.
  const grantee = await actor('km-data-grantee@example.com', mb)
  const grantor = await actor('km-data-grantor@example.com', mb)
  const before = mb.sent.length
  await grantor.call('/api/emergency-access/invite', 'POST', {
    email: grantee.email,
    type: 0,
    waitTimeDays: 1,
  })
  const p = linkParams(mb.sent[before])
  const eaId = p.get('id') as string
  await grantee.call(`/api/emergency-access/${eaId}/accept`, 'POST', { token: p.get('token') })
  await grantor.call(`/api/emergency-access/${eaId}/confirm`, 'POST', { key: '4.keyForGrantee' })
  // A trusted device of the member.
  const keys = {
    encryptedUserKey: '4.userKeyForDevice',
    encryptedPublicKey: '2.devicePublic',
    encryptedPrivateKey: '2.devicePrivate',
  }
  expect((await member.call('/api/devices/device-1/keys', 'PUT', keys)).status).toBe(200)

  const data = await member.json('/api/accounts/key-management/key-rotation-data')
  expect(data.organizationPasswordResetKeyData).toEqual([
    {
      object: 'organizationPasswordResetKeyData',
      organizationId: orgId,
      organizationName: 'Acme',
      organizationPublicKey: 'orgPublic',
    },
  ])
  expect(data.trustedDeviceKeyData).toHaveLength(1)
  expect(data.trustedDeviceKeyData[0]).toMatchObject({
    encryptedUserKey: keys.encryptedUserKey,
    encryptedPublicKey: keys.encryptedPublicKey,
  })
  const emergency = await grantor.json('/api/accounts/key-management/key-rotation-data')
  expect(emergency.emergencyAccessKeyData).toEqual([
    {
      object: 'emergencyAccessKeyData',
      id: eaId,
      granteeId: grantee.uuid,
      granteeName: 'Test User',
      granteeEmail: grantee.email,
      publicKey: 'public-key',
    },
  ])
  // Only the caller's own data.
  expect(
    (await grantee.json('/api/accounts/key-management/key-rotation-data')).emergencyAccessKeyData,
  ).toEqual([])
  const anon = await authed('/api/accounts/key-management/key-rotation-data', 'bad')
  expect(anon.status).toBe(401)
})

it('rotates the user key with rotate-user-keys and re-wraps what the client sends', async () => {
  const mb = mail
  const { member, orgId, memberId } = await recoveryOrg('km-rot')
  const grantee = await actor('km-rot-grantee@example.com')
  const before = mb.sent.length
  await member.call('/api/emergency-access/invite', 'POST', {
    email: grantee.email,
    type: 0,
    waitTimeDays: 1,
  })
  const p = linkParams(mb.sent[before])
  const eaId = p.get('id') as string
  await grantee.call(`/api/emergency-access/${eaId}/accept`, 'POST', { token: p.get('token') })
  await member.call(`/api/emergency-access/${eaId}/confirm`, 'POST', { key: '4.old' })
  expect(
    (
      await member.call('/api/devices/device-1/keys', 'PUT', {
        encryptedUserKey: '4.userKeyForDevice',
        encryptedPublicKey: '2.devicePublic',
        encryptedPrivateKey: '2.devicePrivate',
      })
    ).status,
  ).toBe(200)
  const deviceId = (await member.json('/api/accounts/key-management/key-rotation-data'))
    .trustedDeviceKeyData[0].id

  const body = rotation(member.email, {
    wrappedAccountCryptographicState: {
      publicKeyEncryptionKeyPair: {
        wrappedPrivateKey: '2.newPriv',
        publicKey: 'public-key',
        signedPublicKey: '7.signedPublic',
      },
      signatureKeyPair: {
        signatureAlgorithm: 'ed25519',
        wrappedSigningKey: '7.wrappedSigning',
        verifyingKey: 'verifying',
      },
      securityState: { securityState: 'signed-state', securityVersion: 2 },
    },
    unlockData: {
      organizationAccountRecoveryUnlockData: [
        { organizationId: orgId, resetPasswordKey: '4.rewrapped' },
      ],
      passkeyUnlockData: [],
      deviceKeyUnlockData: [
        { deviceId, encryptedPublicKey: '2.newDevPub', encryptedUserKey: '4.newDevKey' },
      ],
      emergencyAccessUnlockData: [
        { id: eaId, type: 0, waitTimeDays: 1, keyEncrypted: '4.rewrappedForGrantee' },
      ],
    },
    oldUserKeyId: null,
    newUserKeyId: 'key-id-2',
  })
  // A missing recovery enrolment is refused, like the other rotation.
  const missing = {
    ...body,
    unlockData: { ...body.unlockData, organizationAccountRecoveryUnlockData: [] },
  }
  expect((await rotate(member, missing)).status).toBe(400)
  const done = await rotate(member, body)
  expect(done.status, await done.clone().text()).toBe(200)
  expect((await memberRow(memberId))?.key).toBe('4.rewrapped')
  const ea = await env.DB.prepare('SELECT key_encrypted AS k FROM emergency_access WHERE uuid = ?1')
    .bind(eaId)
    .first<{ k: string }>()
  expect(ea?.k).toBe('4.rewrappedForGrantee')
  const dev = await env.DB.prepare('SELECT encrypted_user_key AS k FROM devices WHERE uuid = ?1')
    .bind(deviceId)
    .first<{ k: string }>()
  expect(dev?.k).toBe('4.newDevKey')

  // Every session ends; the new key, key id and V2 account keys show on the next login.
  expect((await authed('/api/accounts/profile', member.token)).status).toBe(401)
  const again = (await (await login(member.email, PASSWORD)).json()) as Record<string, any>
  expect(again.Key).toBe('2.rotatedUserKey')
  expect(again.PrivateKey).toBe('2.newPriv')
  expect(again.AccountKeys).toEqual({
    publicKeyEncryptionKeyPair: {
      wrappedPrivateKey: '2.newPriv',
      publicKey: 'public-key',
      signedPublicKey: '7.signedPublic',
    },
    signatureKeyPair: {
      signatureAlgorithm: 'ed25519',
      wrappedSigningKey: '7.wrappedSigning',
      verifyingKey: 'verifying',
    },
    securityState: { securityState: 'signed-state', securityVersion: 2 },
  })
  const sync = (await (await authed('/api/sync', again.access_token as string)).json()) as any
  expect(sync.userDecryption.userKeyId).toBe('key-id-2')
})

it('checks the unlock method and the key id against the account', async () => {
  const user = await actor('km-method@example.com')
  const base = rotation(user.email)
  const withMethod = (unlockMethodData: unknown) => ({ ...base, unlockMethodData })
  // Trusted device and key connector methods do not fit a master password account.
  expect((await rotate(user, withMethod({ unlockMethod: 0 }))).status).toBe(400)
  expect(
    (await rotate(user, withMethod({ unlockMethod: 2, keyConnectorKeyWrappedUserKey: '2.kc' })))
      .status,
  ).toBe(400)
  // The salt must be the account email and the KDF must stay.
  const mp = (m: Record<string, unknown>) =>
    withMethod({
      unlockMethod: 1,
      masterPasswordUnlockData: {
        kdf: KDF,
        masterKeyWrappedUserKey: '2.k',
        salt: user.email,
        ...m,
      },
    })
  expect((await rotate(user, mp({ salt: 'other@example.com' }))).status).toBe(400)
  expect((await rotate(user, mp({ kdf: { kdfType: 0, iterations: 700000 } }))).status).toBe(400)
  // A changed public key is refused.
  const changed = {
    ...base,
    wrappedAccountCryptographicState: {
      publicKeyEncryptionKeyPair: { wrappedPrivateKey: '2.p', publicKey: 'another-public-key' },
    },
  }
  expect((await rotate(user, changed)).status).toBe(400)
  // A stale old key id is refused once the account has a key id.
  await user.call('/api/accounts/key-management/user-key-id', 'POST', { userKeyId: 'id-1' })
  expect((await rotate(user, { ...base, oldUserKeyId: 'id-0' })).status).toBe(400)
  expect((await rotate(user, { ...base, oldUserKeyId: 'id-1', newUserKeyId: 'id-2' })).status).toBe(
    200,
  )
  // Body checks and sign-in.
  expect((await authed(ROTATE, 'bad', 'POST', base)).status).toBe(401)
})

it('leaves recovery keys for an administrator to re-wrap after a V2 upgrade', async () => {
  const { owner, member, orgId, memberId } = await recoveryOrg('km-v2')
  const base = `/api/organizations/${orgId}/users/keys`
  const plain = await actor('km-v2-plain@example.com')
  await addMember(owner, orgId, plain, { type: 2 })
  expect((await owner.json(`${base}/pending-v2-upgrades`)).data).toEqual([])
  await member.call('/api/accounts/key-management/user-key-id', 'POST', { userKeyId: 'id-1' })

  // Leaving the key out needs the token.
  const left = {
    organizationAccountRecoveryUnlockData: [{ organizationId: orgId, resetPasswordKey: null }],
    passkeyUnlockData: [],
  }
  const noToken = rotation(member.email, { unlockData: left, newUserKeyId: 'id-2' })
  expect((await rotate(member, noToken)).status).toBe(400)
  const token = { wrappedUserKey1: '2.v2ByV1', wrappedUserKey2: '2.v1ByV2' }
  const body = rotation(member.email, {
    unlockData: { ...left, v2UpgradeToken: token },
    oldUserKeyId: 'id-1',
    newUserKeyId: 'id-2',
  })
  expect((await rotate(member, body)).status).toBe(200)
  // The old recovery key stays, with the token beside it.
  expect(await memberRow(memberId)).toMatchObject({ key: RECOVERY_KEY })

  // Only an administrator who may recover the member reads the pending list.
  expect((await plain.call(`${base}/pending-v2-upgrades`)).status).toBe(403)
  const pending = await owner.json(`${base}/pending-v2-upgrades`)
  expect(pending).toMatchObject({ object: 'list', continuationToken: null })
  expect(pending.data).toEqual([
    {
      object: 'organizationUserPendingV2Upgrade',
      organizationUserId: memberId,
      userKeyId: 'id-2',
      accountRecoveryKey: RECOVERY_KEY,
      v2UpgradeToken: { wrappedUserKey1: '2.v2ByV1', wrappedUserKey2: '2.v1ByV2' },
    },
  ])

  // A stale key id is skipped and the membership stays pending.
  const upgrade = (userKeyId: string, accountRecoveryKey: string | null) =>
    owner.call(`${base}/v2-upgrades`, 'POST', {
      upgrades: [{ organizationUserId: memberId, userKeyId, accountRecoveryKey }],
    })
  expect((await upgrade('id-1', '4.stale')).status).toBe(200)
  expect(await memberRow(memberId)).toMatchObject({ key: RECOVERY_KEY })
  expect((await plain.call(`${base}/v2-upgrades`, 'POST', { upgrades: [] })).status).toBe(403)

  expect((await upgrade('id-2', '4.v2Recovery')).status).toBe(200)
  expect(await memberRow(memberId)).toEqual({ key: '4.v2Recovery', token: null })
  expect((await owner.json(`${base}/pending-v2-upgrades`)).data).toEqual([])
  const details = await owner.json(
    `/api/organizations/${orgId}/users/${memberId}/reset-password-details`,
  )
  expect(details.resetPasswordKey).toBe('4.v2Recovery')
})

it('unenrols a member whose V2 upgrade cannot be completed', async () => {
  const { owner, member, orgId, memberId } = await recoveryOrg('km-v2-null')
  await member.call('/api/accounts/key-management/user-key-id', 'POST', { userKeyId: 'id-1' })
  const body = rotation(member.email, {
    unlockData: {
      organizationAccountRecoveryUnlockData: [{ organizationId: orgId, resetPasswordKey: null }],
      passkeyUnlockData: [],
      v2UpgradeToken: { wrappedUserKey1: '2.a', wrappedUserKey2: '2.b' },
    },
    newUserKeyId: 'id-2',
  })
  expect((await rotate(member, body)).status).toBe(200)
  const res = await owner.call(`/api/organizations/${orgId}/users/keys/v2-upgrades`, 'POST', {
    upgrades: [{ organizationUserId: memberId, userKeyId: 'id-2', accountRecoveryKey: null }],
  })
  expect(res.status).toBe(200)
  expect(await memberRow(memberId)).toEqual({ key: null, token: null })
})

it('regenerates the key pair only for an account without one, or with the same public key', async () => {
  const user = await actor('km-regen@example.com')
  const path = '/api/accounts/key-management/regenerate-keys'
  // The same public key re-wraps the private key.
  const same = await user.call(path, 'POST', {
    userPublicKey: 'public-key',
    userKeyEncryptedUserPrivateKey: '2.repaired',
  })
  expect(same.status).toBe(200)
  expect((await user.json('/api/accounts/profile')).privateKey).toBe('2.repaired')
  // Another public key would strand confirmed organisation keys.
  expect(
    (
      await user.call(path, 'POST', {
        userPublicKey: 'other-key',
        userKeyEncryptedUserPrivateKey: '2.x',
      })
    ).status,
  ).toBe(400)
  expect((await user.call(path, 'POST', { userPublicKey: 'public-key' })).status).toBe(400)

  // An account without keys gets its pair.
  await env.DB.prepare('UPDATE users SET public_key = NULL, private_key = NULL WHERE uuid = ?1')
    .bind(user.uuid)
    .run()
  const fresh = await user.call(path, 'POST', {
    userPublicKey: 'brand-new-key',
    userKeyEncryptedUserPrivateKey: '2.brandNew',
  })
  expect(fresh.status).toBe(200)
  const profile = await user.json('/api/accounts/profile')
  expect(profile).toMatchObject({ privateKey: '2.brandNew' })
  expect(profile.accountKeys.publicKeyEncryptionKeyPair.publicKey).toBe('brand-new-key')
  expect((await authed(path, 'bad', 'POST', {})).status).toBe(401)
})
