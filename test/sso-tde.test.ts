import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it } from 'vitest'
import { createDb, schema } from '../src/db'
import { verifyPendingDomains } from '../src/orgs/domains'
import type { OidcIdp } from './oidc-idp'
import { actor, addMember, createOrg } from './org-helpers'
import { authedCall, call, configureOidc, interceptFetch, oidcLogin, startIdp } from './sso-helpers'

let idp: OidcIdp
/** TXT records served by the DNS over HTTPS stub. */
const txt = new Map<string, string[]>()

beforeAll(async () => {
  idp = await startIdp()
  interceptFetch(async (input) => {
    const url = new URL(input instanceof Request ? input.url : String(input))
    if (url.hostname !== 'cloudflare-dns.com') return null
    const name = url.searchParams.get('name') ?? ''
    const answers = (txt.get(name) ?? []).map((t) => ({ name, type: 16, TTL: 60, data: `"${t}"` }))
    return new Response(JSON.stringify({ Status: 0, Answer: answers }), {
      headers: { 'Content-Type': 'application/dns-json' },
    })
  })
})

let n = 0
const unique = (p: string) => `${p}-${Date.now()}-${++n}`

async function org(memberDecryptionType: number, extra: Record<string, unknown> = {}) {
  const owner = await actor(`${unique('owner')}@example.com`)
  const o = await createOrg(owner)
  const identifier = unique('tde')
  if (memberDecryptionType === 1) {
    expect(
      (
        await owner.call(`/api/organizations/${o.id}/policies/3`, 'PUT', {
          enabled: true,
          data: null,
        })
      ).status,
    ).toBe(200)
    expect(
      (
        await owner.call(`/api/organizations/${o.id}/policies/4`, 'PUT', {
          enabled: true,
          data: null,
        })
      ).status,
    ).toBe(200)
  }
  await configureOidc(owner, o.id, identifier, idp, {
    memberDecryptionType,
    keyConnectorUrl: 'https://kc.example.com',
    ...extra,
  })
  return { owner, org: o, identifier }
}

describe('trusted device encryption', () => {
  it('turns on the required policies and offers trusted device decryption', async () => {
    const { owner, org: o, identifier } = await org(2)
    const policies = await owner.json(`/api/organizations/${o.id}/policies`)
    const on = new Map(policies.data.map((p: any) => [p.type, p]))
    expect((on.get(3) as any)?.enabled).toBe(true)
    expect((on.get(4) as any)?.enabled).toBe(true)
    expect((on.get(8) as any)?.data.autoEnrollEnabled).toBe(true)
    // Those policies cannot be relaxed while trusted devices are on.
    expect(
      (
        await owner.call(`/api/organizations/${o.id}/policies/3`, 'PUT', {
          enabled: false,
          data: null,
        })
      ).status,
    ).toBe(400)
    expect(
      (
        await owner.call(`/api/organizations/${o.id}/policies/8`, 'PUT', {
          enabled: true,
          data: { autoEnrollEnabled: false },
        })
      ).status,
    ).toBe(400)

    const email = `${unique('tde')}@example.com`
    const first = await oidcLogin(idp, identifier, { sub: unique('sub'), email })
    const tdo = first.body.UserDecryptionOptions.TrustedDeviceOption
    expect(tdo).toEqual({
      HasAdminApproval: false,
      HasLoginApprovingDevice: false,
      HasManageResetPasswordPermission: false,
      IsTdeOffboarding: false,
    })
    const auto = await authedCall(
      first.body.access_token,
      `/api/organizations/${identifier}/auto-enroll-status`,
    )
    expect(await auto.json()).toMatchObject({ id: o.id, resetPasswordEnabled: true })

    // The new member creates keys and trusts this device.
    const token = first.body.access_token
    expect(
      (
        await authedCall(token, '/api/accounts/keys', 'POST', {
          publicKey: 'pub',
          encryptedPrivateKey: '2.priv',
        })
      ).status,
    ).toBe(200)
    const keys = {
      encryptedUserKey: '4.userKeyForDevice',
      encryptedPublicKey: '2.devicePublic',
      encryptedPrivateKey: '2.devicePrivate',
    }
    const put = await authedCall(token, '/api/devices/sso-device-1/keys', 'PUT', keys)
    expect(put.status).toBe(200)
    expect(await put.json()).toMatchObject({
      isTrusted: true,
      encryptedUserKey: keys.encryptedUserKey,
    })

    // The next SSO login on this device returns its key set.
    const second = await oidcLogin(idp, identifier, {
      sub: (await subOf(owner, o.id, email)) ?? '',
      email,
    })
    expect(second.body.UserDecryptionOptions.TrustedDeviceOption).toMatchObject({
      EncryptedPrivateKey: '2.devicePrivate',
      EncryptedUserKey: '4.userKeyForDevice',
    })
    const retrieved = await authedCall(
      second.body.access_token,
      '/api/devices/sso-device-1/retrieve-keys',
      'POST',
    )
    expect(await retrieved.json()).toMatchObject({
      encryptedUserKey: keys.encryptedUserKey,
      encryptedPublicKey: keys.encryptedPublicKey,
    })

    // Untrusting removes the keys.
    const list = (await (await authedCall(second.body.access_token, '/api/devices')).json()) as any
    const device = list.data.find((d: any) => d.identifier === 'sso-device-1')
    expect(device.isTrusted).toBe(true)
    expect(
      (
        await authedCall(second.body.access_token, '/api/devices/untrust', 'POST', {
          devices: [device.id],
        })
      ).status,
    ).toBe(200)
    expect(
      (
        await authedCall(
          second.body.access_token,
          '/api/devices/sso-device-1/retrieve-keys',
          'POST',
        )
      ).status,
    ).toBe(400)
  })

  it('reports admin approval, approving devices and the manage permission', async () => {
    const { owner, org: o, identifier } = await org(2)
    const admin = await actor(`${unique('admin')}@example.com`)
    await addMember(owner, o.id, admin, { type: 1 })
    const db = createDb(env.DB)
    const { eq } = await import('drizzle-orm')
    await db
      .update(schema.usersOrganizations)
      .set({ resetPasswordKey: '4.recovery' })
      .where(eq(schema.usersOrganizations.userUuid, admin.uuid))
    const r = await oidcLogin(
      idp,
      identifier,
      { sub: unique('sub'), email: admin.email },
      { deviceIdentifier: 'new-device' },
    )
    expect(r.body.UserDecryptionOptions.TrustedDeviceOption).toMatchObject({
      HasAdminApproval: true,
      HasLoginApprovingDevice: true,
      HasManageResetPasswordPermission: true,
    })
    expect(r.body.UserDecryptionOptions.HasMasterPassword).toBe(true)
  })

  it('re-wraps trusted device keys after a rotation with update-trust, and lost-trust clears them', async () => {
    const { identifier } = await org(2)
    const r = await oidcLogin(idp, identifier, {
      sub: unique('sub'),
      email: `${unique('rot')}@example.com`,
    })
    const t = r.body.access_token
    await authedCall(t, '/api/devices/sso-device-1/keys', 'PUT', {
      encryptedUserKey: '4.a',
      encryptedPublicKey: '2.b',
      encryptedPrivateKey: '2.c',
    })
    const upd = await call('/api/devices/update-trust', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${t}`,
        'Content-Type': 'application/json',
        'Device-Identifier': 'sso-device-1',
      },
      body: JSON.stringify({
        currentDevice: { encryptedPublicKey: '2.b2', encryptedUserKey: '4.a2' },
        otherDevices: [],
      }),
    })
    expect(upd.status).toBe(200)
    expect(
      await (await authedCall(t, '/api/devices/sso-device-1/retrieve-keys', 'POST')).json(),
    ).toMatchObject({ encryptedUserKey: '4.a2' })
    const lost = await call('/api/devices/lost-trust', {
      method: 'POST',
      headers: { Authorization: `Bearer ${t}`, 'Device-Identifier': 'sso-device-1' },
    })
    expect(lost.status).toBe(200)
    expect((await authedCall(t, '/api/devices/sso-device-1/retrieve-keys', 'POST')).status).toBe(
      400,
    )
  })

  it('offboards members without a password when the organization leaves trusted devices', async () => {
    const { owner, org: o, identifier } = await org(2)
    const email = `${unique('off')}@example.com`
    const r = await oidcLogin(idp, identifier, { sub: unique('sub'), email })
    // The member set up trusted device decryption: account keys exist.
    await authedCall(r.body.access_token, '/api/accounts/keys', 'POST', {
      publicKey: 'pub',
      encryptedPrivateKey: '2.priv',
    })
    // Leaving trusted devices: relax the policies only after turning the option off.
    await configureOidc(owner, o.id, identifier, idp, { memberDecryptionType: 0 })
    const again = await oidcLogin(idp, identifier, {
      sub: (await subOf(owner, o.id, email)) ?? '',
      email,
    })
    expect(again.body.UserDecryptionOptions.TrustedDeviceOption.IsTdeOffboarding).toBe(true)
    const set = await authedCall(
      r.body.access_token,
      '/api/accounts/update-tde-offboarding-password',
      'PUT',
      {
        authenticationData: {
          salt: email,
          kdf: { kdfType: 0, iterations: 600000 },
          masterPasswordAuthenticationHash: 'hash',
        },
        unlockData: {
          salt: email,
          kdf: { kdfType: 0, iterations: 600000 },
          masterKeyWrappedUserKey: '2.wrapped',
        },
        masterPasswordHint: null,
      },
    )
    expect(set.status).toBe(200)
    const third = await oidcLogin(idp, identifier, {
      sub: (await subOf(owner, o.id, email)) ?? '',
      email,
    })
    expect(third.body.UserDecryptionOptions.HasMasterPassword).toBe(true)
    expect(third.body.UserDecryptionOptions.TrustedDeviceOption).toBeUndefined()
  })
})

async function subOf(owner: Awaited<ReturnType<typeof actor>>, orgId: string, email: string) {
  const members = await owner.json(`/api/organizations/${orgId}/users`)
  return members.data.find((m: any) => m.email === email)?.ssoExternalId as string | undefined
}

describe('Key Connector', () => {
  it('requires the policies, enrols new members and reports the URL', async () => {
    const owner = await actor(`${unique('kcowner')}@example.com`)
    const o = await createOrg(owner)
    const res = await owner.call(`/api/organizations/${o.id}/sso`, 'POST', {
      enabled: true,
      identifier: unique('kc'),
      data: {
        configType: 1,
        memberDecryptionType: 1,
        keyConnectorUrl: 'https://kc.example.com',
        authority: idp.issuer,
        clientId: idp.clientId,
        clientSecret: idp.clientSecret,
      },
    })
    expect(res.status).toBe(400)

    const { owner: o2, org: org2, identifier } = await org(1)
    const email = `${unique('kcuser')}@example.com`
    const r = await oidcLogin(idp, identifier, { sub: unique('sub'), email })
    expect(r.body.Key).toBeNull()
    expect(r.body.UserDecryptionOptions.KeyConnectorOption).toEqual({
      KeyConnectorUrl: 'https://kc.example.com',
    })
    const t = r.body.access_token
    const details = await authedCall(
      t,
      `/api/accounts/key-connector/confirmation-details/${identifier}`,
    )
    expect(await details.json()).toMatchObject({ organizationName: 'Acme' })
    const set = await authedCall(t, '/api/accounts/set-key-connector-key', 'POST', {
      key: '2.masterKeyWrapped',
      keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' },
      kdf: 0,
      kdfIterations: 600000,
      orgIdentifier: identifier,
    })
    expect(set.status).toBe(200)
    const profile = (await (await authedCall(t, '/api/accounts/profile')).json()) as any
    expect(profile.usesKeyConnector).toBe(true)
    expect(profile.organizations.find((x: any) => x.id === org2.id)).toMatchObject({
      keyConnectorEnabled: true,
      keyConnectorUrl: 'https://kc.example.com',
    })
    // Key Connector cannot be turned off while a member uses it.
    const off = await o2.call(`/api/organizations/${org2.id}/sso`, 'POST', {
      enabled: true,
      identifier,
      data: {
        configType: 1,
        memberDecryptionType: 0,
        authority: idp.issuer,
        clientId: idp.clientId,
        clientSecret: idp.clientSecret,
      },
    })
    expect(off.status).toBe(400)
  })

  it('converts a member with a master password, but not an owner', async () => {
    const { owner, org: o } = await org(1)
    const member = await actor(`${unique('conv')}@example.com`)
    await addMember(owner, o.id, member)
    expect((await owner.call('/api/accounts/convert-to-key-connector', 'POST')).status).toBe(400)
    expect((await member.call('/api/accounts/convert-to-key-connector', 'POST')).status).toBe(200)
    const profile = await member.json('/api/accounts/profile')
    expect(profile.usesKeyConnector).toBe(true)
  })
})

describe('claimed domains', () => {
  it('verifies a domain by DNS TXT and uses it for SSO discovery and account rules', async () => {
    const { owner, org: o, identifier } = await org(0)
    const domain = `${unique('corp')}.example.com`
    const added = await owner.json(`/api/organizations/${o.id}/domain`, 'POST', {
      domainName: `https://${domain.toUpperCase()}/`,
    })
    expect(added).toMatchObject({ domainName: domain, verifiedDate: null })
    expect(added.txt).toMatch(/^bw=/)
    expect(
      (await owner.call(`/api/organizations/${o.id}/domain`, 'POST', { domainName: domain }))
        .status,
    ).toBe(409)

    const notYet = await owner.json(`/api/organizations/${o.id}/domain/${added.id}/verify`, 'POST')
    expect(notYet.verifiedDate).toBeNull()
    txt.set(domain, ['v=spf1 -all', added.txt])
    const ok = await owner.json(`/api/organizations/${o.id}/domain/${added.id}/verify`, 'POST')
    expect(ok.verifiedDate).not.toBeNull()

    // Another organization cannot claim it.
    const other = await org(0)
    expect(
      (
        await other.owner.call(`/api/organizations/${other.org.id}/domain`, 'POST', {
          domainName: domain,
        })
      ).status,
    ).toBe(409)

    const discovered = await call('/api/organizations/domain/sso/verified', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: `someone@${domain}` }),
    })
    expect(((await discovered.json()) as any).data).toEqual([
      expect.objectContaining({ organizationIdentifier: identifier, domainName: domain }),
    ])

    // An existing account on the claimed domain may sign in with SSO without an invitation.
    const claimed = await actor(`person@${domain}`)
    const r = await oidcLogin(idp, identifier, { sub: unique('sub'), email: claimed.email })
    expect(r.token?.status).toBe(200)
    const profile = await claimed.json('/api/accounts/profile')
    expect(profile.organizations.find((x: any) => x.id === o.id).userIsClaimedByOrganization).toBe(
      true,
    )
    expect(
      (await claimed.call('/api/accounts', 'DELETE', { masterPasswordHash: 'client-derived-hash' }))
        .status,
    ).toBe(400)
    const members = await owner.json(`/api/organizations/${o.id}/users`)
    const m = members.data.find((x: any) => x.email === claimed.email)
    expect(
      (await owner.call(`/api/organizations/${o.id}/users/${m.id}/confirm`, 'POST', { key: '4.k' }))
        .status,
    ).toBe(200)
    expect((await claimed.call(`/api/organizations/${o.id}/leave`, 'POST')).status).toBe(400)

    expect(m.claimedByOrganization).toBe(true)
    expect(
      (await owner.call(`/api/organizations/${o.id}/users/${m.id}/delete-account`, 'DELETE'))
        .status,
    ).toBe(200)
    expect((await claimed.call('/api/accounts/profile')).status).toBe(401)
  })

  it('verifies pending domains from the cron job', async () => {
    const { owner, org: o } = await org(0)
    const domain = `${unique('cron')}.example.com`
    const added = await owner.json(`/api/organizations/${o.id}/domain`, 'POST', {
      domainName: domain,
    })
    txt.set(domain, [added.txt])
    await verifyPendingDomains(env)
    const got = await owner.json(`/api/organizations/${o.id}/domain/${added.id}`)
    expect(got.verifiedDate).not.toBeNull()
  })
})
