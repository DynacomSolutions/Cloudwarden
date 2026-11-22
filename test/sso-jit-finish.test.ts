import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it } from 'vitest'
import { login } from './helpers'
import type { OidcIdp } from './oidc-idp'
import { actor, createOrg, enableRecoveryPolicy } from './org-helpers'
import { authedCall, configureOidc, oidcLogin, startIdp } from './sso-helpers'

let idp: OidcIdp
beforeAll(async () => {
  idp = await startIdp()
})

let n = 0
const unique = (p: string) => `${p}-${Date.now()}-${++n}`

async function ssoOrg(memberDecryptionType: number) {
  const owner = await actor(`${unique('owner')}@example.com`)
  const org = await createOrg(owner)
  const identifier = unique('jit')
  if (memberDecryptionType === 1) {
    for (const type of [3, 4]) {
      await owner.call(`/api/organizations/${org.id}/policies/${type}`, 'PUT', {
        enabled: true,
        data: null,
      })
    }
  }
  await configureOidc(owner, org.id, identifier, idp, {
    memberDecryptionType,
    keyConnectorUrl: 'https://kc.example.com',
  })
  return { owner, org, identifier }
}

async function newMember(identifier: string) {
  const email = `${unique('member')}@example.com`
  const { body } = await oidcLogin(idp, identifier, { sub: unique('sub'), email })
  return { email, token: body.access_token as string }
}

const kdf = { kdfType: 0, iterations: 600000 }
const passwordBody = (email: string, identifier: string, over: Record<string, unknown> = {}) => ({
  masterPasswordAuthentication: {
    kdf,
    masterPasswordAuthenticationHash: 'client-derived-hash',
    salt: email,
  },
  masterPasswordUnlock: {
    kdf,
    masterKeyWrappedUserKey: '2.masterKeyWrappedUserKey',
    salt: email,
    containedKeyId: 'key-id-1',
  },
  accountKeys: {
    publicKeyEncryptionKeyPair: {
      wrappedPrivateKey: '2.priv',
      publicKey: 'jit-public',
      signedPublicKey: '7.signed',
    },
    signatureKeyPair: {
      signatureAlgorithm: 'ed25519',
      wrappedSigningKey: '7.signing',
      verifyingKey: 'verifying',
    },
    securityState: { securityState: 'state', securityVersion: 2 },
  },
  masterPasswordHint: 'hint',
  orgIdentifier: identifier,
  acceptOrganizationInvite: true,
  ...over,
})

const statusOf = async (orgId: string, email: string) =>
  (
    await env.DB.prepare(
      'SELECT m.status AS s FROM users_organizations m JOIN users u ON u.uuid = m.user_uuid WHERE m.organization_uuid = ?1 AND u.email = ?2',
    )
      .bind(orgId, email)
      .first<{ s: number }>()
  )?.s

describe('SSO JIT provision finish', { timeout: 300_000 }, () => {
  const path = (p: string) => `/api/sso-jit-provision-finish/${p}`

  it('sets the master password, V2 account keys and key id in one call', async () => {
    const { org, identifier } = await ssoOrg(0)
    const { email, token } = await newMember(identifier)
    // Exactly one key pair shape.
    const both = passwordBody(email, identifier, {
      keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' },
    })
    expect((await authedCall(token, path('password'), 'POST', both)).status).toBe(400)
    // The salt must be the account email.
    const badSalt = passwordBody(email, identifier)
    badSalt.masterPasswordUnlock.salt = 'other@example.com'
    expect((await authedCall(token, path('password'), 'POST', badSalt)).status).toBe(400)
    // An organisation the account does not belong to is refused.
    const stranger = passwordBody(email, unique('nope'))
    expect((await authedCall(token, path('password'), 'POST', stranger)).status).toBe(400)

    // A pending invitation moves to accepted when the caller asks for it.
    await env.DB.prepare(
      'UPDATE users_organizations SET status = 0 WHERE organization_uuid = ?1 AND user_uuid = (SELECT uuid FROM users WHERE email = ?2)',
    )
      .bind(org.id, email)
      .run()
    expect(
      (await authedCall(token, path('password'), 'POST', passwordBody(email, identifier))).status,
    ).toBe(200)
    expect(await statusOf(org.id, email)).toBe(1)

    const again = await login(email)
    expect(again.status).toBe(200)
    const body = (await again.json()) as Record<string, any>
    expect(body.Key).toBe('2.masterKeyWrappedUserKey')
    expect(body.AccountKeys.signatureKeyPair).toMatchObject({ verifyingKey: 'verifying' })
    expect(body.AccountKeys.publicKeyEncryptionKeyPair).toMatchObject({
      publicKey: 'jit-public',
      signedPublicKey: '7.signed',
    })
    const sync = (await (await authedCall(body.access_token, '/api/sync')).json()) as any
    expect(sync.userDecryption.userKeyId).toBe('key-id-1')
    expect(sync.profile.masterPasswordHint ?? 'hint').toBe('hint')
    // A second call is refused: the account has a password now.
    expect(
      (await authedCall(token, path('password'), 'POST', passwordBody(email, identifier))).status,
    ).toBe(400)
    // Sign-in is required.
    expect(
      (await authedCall('bad', path('password'), 'POST', passwordBody(email, identifier))).status,
    ).toBe(401)
  })

  it('leaves a pending invitation pending when it is not accepted, and accepts V1 keys', async () => {
    const { org, identifier } = await ssoOrg(0)
    const { email, token } = await newMember(identifier)
    await env.DB.prepare(
      'UPDATE users_organizations SET status = 0 WHERE organization_uuid = ?1 AND user_uuid = (SELECT uuid FROM users WHERE email = ?2)',
    )
      .bind(org.id, email)
      .run()
    const v1 = passwordBody(email, identifier, {
      accountKeys: null,
      keys: { publicKey: 'v1-public', encryptedPrivateKey: '2.v1priv' },
      acceptOrganizationInvite: false,
    })
    expect((await authedCall(token, path('password'), 'POST', v1)).status).toBe(200)
    expect(await statusOf(org.id, email)).toBe(0)
    const body = (await (await login(email)).json()) as Record<string, any>
    expect(body.AccountKeys.signatureKeyPair).toBeNull()
    expect(body.PrivateKey).toBe('2.v1priv')
  })

  it('enrols the new member with a key connector wrapped user key', async () => {
    const { identifier } = await ssoOrg(1)
    const { token } = await newMember(identifier)
    const keyConnectorKeys = {
      keyConnectorKeyWrappedUserKey: '7.kcWrapped',
      accountKeys: passwordBody('x@example.com', identifier).accountKeys,
      containedKeyId: 'key-id-kc',
      orgIdentifier: identifier,
    }
    expect(
      (await authedCall(token, path('key-connector'), 'POST', { keyConnectorKeys })).status,
    ).toBe(400)
    const res = await authedCall(token, path('key-connector'), 'POST', {
      keyConnectorKeys,
      acceptOrganizationInvite: true,
    })
    expect(res.status).toBe(200)
    const profile = (await (await authedCall(token, '/api/accounts/profile')).json()) as any
    expect(profile.usesKeyConnector).toBe(true)
    expect(profile.accountKeys.signatureKeyPair).toMatchObject({ verifyingKey: 'verifying' })
    // The organisation must use the key connector, and the keys are set once.
    const other = await ssoOrg(0)
    const member = await newMember(other.identifier)
    const refused = await authedCall(member.token, path('key-connector'), 'POST', {
      keyConnectorKeys: { ...keyConnectorKeys, orgIdentifier: other.identifier },
      acceptOrganizationInvite: true,
    })
    expect(refused.status).toBe(400)
    expect(
      (
        await authedCall(token, path('key-connector'), 'POST', {
          keyConnectorKeys,
          acceptOrganizationInvite: true,
        })
      ).status,
    ).toBe(400)
  })

  it('still serves set-key-connector-key with the V1 body', async () => {
    const { identifier } = await ssoOrg(1)
    const { token } = await newMember(identifier)
    const res = await authedCall(token, '/api/accounts/set-key-connector-key', 'POST', {
      key: '2.masterKeyWrapped',
      keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' },
      kdf: 0,
      kdfIterations: 600000,
      orgIdentifier: identifier,
    })
    expect(res.status).toBe(200)
    expect(
      ((await (await authedCall(token, '/api/accounts/profile')).json()) as any).usesKeyConnector,
    ).toBe(true)
  })

  it('stores the keys, the device keys and the recovery key for a trusted device member', async () => {
    const { owner, org, identifier } = await ssoOrg(2)
    await enableRecoveryPolicy(owner, org.id, true)
    const email = `${unique('tde')}@example.com`
    const first = await oidcLogin(idp, identifier, { sub: unique('sub'), email })
    const token = first.body.access_token as string
    const body = {
      keys: { publicKey: 'tde-public', encryptedPrivateKey: '2.tdepriv', userKeyId: 'key-id-tde' },
      organizationId: org.id,
      accountRecoveryKey: '4.recoveryForOrg',
      deviceKeys: {
        encryptedUserKey: '4.userKeyForDevice',
        encryptedPublicKey: '2.devicePublic',
        encryptedPrivateKey: '2.devicePrivate',
      },
      acceptOrganizationInvite: true,
    }
    // Accepting needs the recovery key.
    expect(
      (
        await authedCall(token, path('trusted-device'), 'POST', {
          ...body,
          accountRecoveryKey: null,
        })
      ).status,
    ).toBe(400)
    // A different organisation is refused.
    expect(
      (
        await authedCall(token, path('trusted-device'), 'POST', {
          ...body,
          organizationId: crypto.randomUUID(),
        })
      ).status,
    ).toBe(400)
    const res = await authedCall(token, path('trusted-device'), 'POST', body)
    expect(res.status).toBe(200)
    const profile = (await (await authedCall(token, '/api/accounts/profile')).json()) as any
    expect(profile.privateKey).toBe('2.tdepriv')
    expect(profile.organizations.find((o: any) => o.id === org.id)).toMatchObject({
      resetPasswordEnrolled: true,
    })
    const device = await env.DB.prepare(
      'SELECT encrypted_user_key AS k FROM devices d JOIN users u ON u.uuid = d.user_uuid WHERE u.email = ?1',
    )
      .bind(email)
      .first<{ k: string }>()
    expect(device?.k).toBe('4.userKeyForDevice')
    const sync = (await (await authedCall(token, '/api/sync')).json()) as any
    expect(sync.userDecryption.userKeyId).toBe('key-id-tde')
    // An organisation that does not use trusted devices refuses.
    const plain = await ssoOrg(0)
    const member = await newMember(plain.identifier)
    expect(
      (
        await authedCall(member.token, path('trusted-device'), 'POST', {
          ...body,
          organizationId: plain.org.id,
        })
      ).status,
    ).toBe(400)
  })

  const tdeBody = (orgId: string, over: Record<string, unknown> = {}) => ({
    keys: { publicKey: 'tde-public', encryptedPrivateKey: '2.tdepriv', userKeyId: 'key-id-tde' },
    organizationId: orgId,
    accountRecoveryKey: '4.recoveryForOrg',
    acceptOrganizationInvite: true,
    ...over,
  })
  const resetKey = async (orgId: string, email: string) =>
    (
      await env.DB.prepare(
        'SELECT m.reset_password_key AS k FROM users_organizations m JOIN users u ON u.uuid = m.user_uuid WHERE m.organization_uuid = ?1 AND u.email = ?2',
      )
        .bind(orgId, email)
        .first<{ k: string | null }>()
    )?.k

  it('refuses the trusted device finish for an account that already has keys', async () => {
    const tde = await ssoOrg(2)
    const email = `${unique('tde-keys')}@example.com`
    const first = await oidcLogin(idp, tde.identifier, { sub: unique('sub'), email })
    const token = first.body.access_token as string
    await env.DB.prepare(
      "UPDATE users SET public_key = 'old-public', private_key = '2.oldpriv' WHERE email = ?1",
    )
      .bind(email)
      .run()
    const res = await authedCall(token, path('trusted-device'), 'POST', tdeBody(tde.org.id))
    expect(res.status).toBe(400)
    expect(await res.text()).toContain('already initialized')
    expect(await resetKey(tde.org.id, email)).toBeNull()
    const profile = (await (await authedCall(token, '/api/accounts/profile')).json()) as any
    expect(profile.privateKey).toBe('2.oldpriv')
  })

  it('refuses the master password finish for an account that already has keys', async () => {
    const pw = await ssoOrg(0)
    const member = await newMember(pw.identifier)
    await env.DB.prepare(
      "UPDATE users SET public_key = 'old-public', private_key = '2.oldpriv' WHERE email = ?1",
    )
      .bind(member.email)
      .run()
    expect(
      (
        await authedCall(
          member.token,
          path('password'),
          'POST',
          passwordBody(member.email, pw.identifier),
        )
      ).status,
    ).toBe(400)
  })

  it('refuses the key connector finish for an account that already has keys', async () => {
    const kc = await ssoOrg(1)
    const kcMember = await newMember(kc.identifier)
    await env.DB.prepare(
      "UPDATE users SET public_key = 'old-public', private_key = '2.oldpriv' WHERE email = ?1",
    )
      .bind(kcMember.email)
      .run()
    const keyConnectorKeys = {
      keyConnectorKeyWrappedUserKey: '7.kcWrapped',
      accountKeys: passwordBody('x@example.com', kc.identifier).accountKeys,
      orgIdentifier: kc.identifier,
    }
    expect(
      (
        await authedCall(kcMember.token, path('key-connector'), 'POST', {
          keyConnectorKeys,
          acceptOrganizationInvite: true,
        })
      ).status,
    ).toBe(400)
  })

  it('applies the recovery policy to the trusted device enrolment', async () => {
    const tde = await ssoOrg(2)
    const member = async () => {
      const email = `${unique('tde-pol')}@example.com`
      const first = await oidcLogin(idp, tde.identifier, { sub: unique('sub'), email })
      return { email, token: first.body.access_token as string }
    }
    // Sets the account recovery policy (type 8) of the organisation directly.
    const setPolicy = (enabled: boolean, autoEnroll: boolean) =>
      env.DB.prepare(
        `INSERT INTO policies (uuid, organization_uuid, atype, enabled, data, updated_at)
         VALUES (?1, ?2, 8, ?3, ?4, 0)
         ON CONFLICT (organization_uuid, atype) DO UPDATE SET enabled = ?3, data = ?4`,
      )
        .bind(
          crypto.randomUUID(),
          tde.org.id,
          enabled ? 1 : 0,
          JSON.stringify({ autoEnrollEnabled: autoEnroll }),
        )
        .run()
    // The policy is off: a recovery key is refused.
    await setPolicy(false, false)
    const a = await member()
    expect(
      (await authedCall(a.token, path('trusted-device'), 'POST', tdeBody(tde.org.id))).status,
    ).toBe(400)
    expect(await resetKey(tde.org.id, a.email)).toBeNull()
    // Without the key the call passes while the policy is off.
    expect(
      (
        await authedCall(
          a.token,
          path('trusted-device'),
          'POST',
          tdeBody(tde.org.id, { accountRecoveryKey: null }),
        )
      ).status,
    ).toBe(200)
    // Auto-enrolment makes the key required.
    await setPolicy(true, true)
    const b = await member()
    expect(
      (
        await authedCall(
          b.token,
          path('trusted-device'),
          'POST',
          tdeBody(tde.org.id, { accountRecoveryKey: null }),
        )
      ).status,
    ).toBe(400)
    expect(
      (await authedCall(b.token, path('trusted-device'), 'POST', tdeBody(tde.org.id))).status,
    ).toBe(200)
    expect(await resetKey(tde.org.id, b.email)).toBe('4.recoveryForOrg')
  })

  it('applies the two-step login policy when the finish call accepts the invitation', async () => {
    const { owner, org, identifier } = await ssoOrg(0)
    const { email, token } = await newMember(identifier)
    const set = await owner.call(`/api/organizations/${org.id}/policies/0`, 'PUT', {
      enabled: true,
      data: null,
    })
    expect(set.status, await set.clone().text()).toBe(200)
    await env.DB.prepare(
      'UPDATE users_organizations SET status = 0 WHERE organization_uuid = ?1 AND user_uuid = (SELECT uuid FROM users WHERE email = ?2)',
    )
      .bind(org.id, email)
      .run()
    const res = await authedCall(token, path('password'), 'POST', passwordBody(email, identifier))
    expect(res.status).toBe(400)
    expect(await statusOf(org.id, email)).toBe(0)
  })
})
