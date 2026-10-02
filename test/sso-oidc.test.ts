import { env } from 'cloudflare:workers'
import { eq } from 'drizzle-orm'
import { beforeAll, describe, expect, it } from 'vitest'
import { generateTotpKey, totpAt } from '../src/auth/totp'
import { clock } from '../src/auth/twofactor'
import { createDb, schema } from '../src/db'
import { BASE, login } from './helpers'
import type { OidcIdp } from './oidc-idp'
import { actor, addMember, createOrg, linkParams, mail } from './org-helpers'
import {
  authedCall,
  call,
  callback,
  codeFrom,
  configureOidc,
  oidcLogin,
  redeem,
  startIdp,
  startSso,
} from './sso-helpers'

let idp: OidcIdp
beforeAll(async () => {
  idp = await startIdp()
})

let n = 0
const unique = (p: string) => `${p}-${Date.now()}-${++n}`

async function ssoOrg(data: Record<string, unknown> = {}) {
  const owner = await actor(`${unique('owner')}@example.com`)
  const org = await createOrg(owner)
  const identifier = unique('acme')
  await configureOidc(owner, org.id, identifier, idp, data)
  return { owner, org, identifier }
}

describe('SSO with OpenID Connect', () => {
  it('provisions a new member just in time without a master password', async () => {
    const { owner, org, identifier } = await ssoOrg()
    const email = `${unique('jit')}@example.com`
    const { body, token } = await oidcLogin(idp, identifier, {
      sub: unique('sub'),
      email,
      name: 'Jit User',
    })
    expect(token?.status).toBe(200)
    expect(body.access_token).toBeTruthy()
    expect(body.refresh_token).toBeTruthy()
    expect(body.Key).toBeNull()
    expect(body.UserDecryptionOptions.HasMasterPassword).toBe(false)
    expect(body.UserDecryptionOptions.MasterPasswordUnlock).toBeUndefined()
    expect(body.UserDecryptionOptions.TrustedDeviceOption).toBeUndefined()

    const profile = (await (
      await authedCall(body.access_token, '/api/accounts/profile')
    ).json()) as any
    expect(profile.email).toBe(email)
    expect(profile.name).toBe('Jit User')
    const membership = profile.organizations.find((o: any) => o.id === org.id)
    expect(membership).toMatchObject({
      status: 1,
      type: 2,
      ssoBound: true,
      ssoEnabled: true,
      identifier,
      useSso: true,
    })

    // The administrator sees an accepted member waiting for confirmation, with the SSO link.
    const members = await owner.json(`/api/organizations/${org.id}/users`)
    const m = members.data.find((x: any) => x.email === email)
    expect(m).toMatchObject({ status: 1, hasMasterPassword: false })
    expect(m.ssoExternalId).toBeTruthy()
  })

  it('lets the new member set a master password, then enforces Require SSO for password logins', async () => {
    const { owner, org, identifier } = await ssoOrg()
    const email = `${unique('setpw')}@example.com`
    const { body } = await oidcLogin(idp, identifier, { sub: unique('sub'), email })
    const set = await authedCall(body.access_token, '/api/accounts/set-password', 'POST', {
      masterPasswordHash: 'client-derived-hash',
      key: '2.masterKeyWrappedUserKey',
      masterPasswordHint: null,
      orgIdentifier: identifier,
      keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' },
      kdf: 0,
      kdfIterations: 600000,
    })
    expect(set.status).toBe(200)
    // A second set-password is refused.
    const again = await authedCall(body.access_token, '/api/accounts/set-password', 'POST', {
      masterPasswordHash: 'other',
      key: '2.k',
      orgIdentifier: identifier,
      kdf: 0,
      kdfIterations: 600000,
    })
    expect(again.status).toBe(400)
    expect((await login(email)).status).toBe(200)

    // Require SSO needs Single organization first.
    const premature = await owner.call(`/api/organizations/${org.id}/policies/4`, 'PUT', {
      enabled: true,
      data: null,
    })
    expect(premature.status).toBe(400)
    expect(
      (
        await owner.call(`/api/organizations/${org.id}/policies/3`, 'PUT', {
          enabled: true,
          data: null,
        })
      ).status,
    ).toBe(200)
    expect(
      (
        await owner.call(`/api/organizations/${org.id}/policies/4`, 'PUT', {
          enabled: true,
          data: null,
        })
      ).status,
    ).toBe(200)

    const blocked = await login(email)
    expect(blocked.status).toBe(400)
    const err = (await blocked.json()) as any
    expect(err.SsoOrganizationIdentifier).toBe(identifier)
    expect(err.ErrorModel.Message).toMatch(/SSO/)
    // Owners are exempt.
    expect((await login(owner.email)).status).toBe(200)
    // Personal API keys are covered as well.
    const memberToken = (
      await oidcLogin(idp, identifier, {
        sub: (await profileSub(owner, org.id, email)) ?? '',
        email,
      })
    ).body.access_token
    const key = (await (
      await authedCall(memberToken, '/api/accounts/api-key', 'POST', {
        masterPasswordHash: 'client-derived-hash',
      })
    ).json()) as any
    const apiLogin = await call('/identity/connect/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: `user.${((await (await authedCall(memberToken, '/api/accounts/profile')).json()) as any).id}`,
        client_secret: key.apiKey,
        scope: 'api',
        deviceType: '8',
        deviceName: 'cli',
        deviceIdentifier: 'cli-1',
      }).toString(),
    })
    expect(apiLogin.status).toBe(400)
    expect(((await apiLogin.json()) as any).SsoOrganizationIdentifier).toBe(identifier)
    // SSO itself still works, now with the master password option.
    const again2 = await oidcLogin(idp, identifier, {
      sub: (await profileSub(owner, org.id, email)) ?? '',
      email,
    })
    expect(again2.body.UserDecryptionOptions.HasMasterPassword).toBe(true)
    expect(again2.body.UserDecryptionOptions.MasterPasswordUnlock.masterKeyEncryptedUserKey).toBe(
      '2.masterKeyWrappedUserKey',
    )
  })

  it('refuses to take over an existing account that is not in the organization', async () => {
    const { identifier } = await ssoOrg()
    const victim = await actor(`${unique('victim')}@example.com`)
    const r = await oidcLogin(idp, identifier, { sub: unique('sub'), email: victim.email })
    expect(r.back.status).toBe(400)
    expect(await r.back.text()).toMatch(/already exists/)
  })

  it('does not link an existing account by a pending invitation; it must accept first', async () => {
    const { owner, org, identifier } = await ssoOrg()
    const member = await actor(`${unique('invited')}@example.com`)
    const before = mail.sent.length
    const inv = await owner.call(`/api/organizations/${org.id}/users/invite`, 'POST', {
      emails: [member.email],
      type: 2,
      accessAll: false,
      collections: [],
      groups: [],
    })
    expect(inv.status).toBe(200)
    const sub = unique('sub')
    const refused = await oidcLogin(idp, identifier, { sub, email: member.email })
    expect(refused.back.status).toBe(400)
    expect(await refused.back.text()).toMatch(/already exists/)

    // After accepting with the master password, SSO links the account.
    const params = linkParams(mail.sent[before])
    const accepted = await member.call(
      `/api/organizations/${org.id}/users/${params.get('organizationUserId')}/accept`,
      'POST',
      { token: params.get('token') },
    )
    expect(accepted.status).toBe(200)
    const r = await oidcLogin(idp, identifier, { sub, email: member.email })
    expect(r.token?.status).toBe(200)
    expect(r.body.UserDecryptionOptions.HasMasterPassword).toBe(true)
    const profile = await member.json('/api/accounts/profile')
    expect(profile.organizations.find((o: any) => o.id === org.id)).toMatchObject({
      status: 1,
      ssoBound: true,
    })
  })

  it('provisions new accounts only for claimed domains or invited addresses', async () => {
    const owner = await actor(`${unique('owner')}@example.com`)
    const org = await createOrg(owner)
    const identifier = unique('noclaim')
    await configureOidc(owner, org.id, identifier, idp, {}, false)
    const stranger = await oidcLogin(idp, identifier, {
      sub: unique('sub'),
      email: `${unique('stranger')}@unclaimed.example.org`,
    })
    expect(stranger.back.status).toBe(400)
    expect(await stranger.back.text()).toMatch(/invitation/)

    const invitedEmail = `${unique('newbie')}@unclaimed.example.org`
    await owner.call(`/api/organizations/${org.id}/users/invite`, 'POST', {
      emails: [invitedEmail],
      type: 2,
      accessAll: false,
      collections: [],
      groups: [],
    })
    const ok = await oidcLogin(idp, identifier, { sub: unique('sub'), email: invitedEmail })
    expect(ok.token?.status).toBe(200)
    const profile = (await (
      await authedCall(ok.body.access_token, '/api/accounts/profile')
    ).json()) as any
    // An invited (not claimed) address is not marked verified by SSO.
    expect(profile.emailVerified).toBe(false)
    expect(profile.organizations.find((o: any) => o.id === org.id)).toMatchObject({ status: 1 })
  })

  it('requires email_verified for new accounts unless the organization opts out', async () => {
    const { owner, org, identifier } = await ssoOrg()
    // A provider that does not say the address is verified.
    const missing = await oidcLogin(idp, identifier, {
      sub: unique('sub'),
      email: `${unique('noflag')}@example.com`,
      email_verified: undefined as unknown as boolean,
    })
    expect(missing.back.status).toBe(400)
    expect(await missing.back.text()).toMatch(/not verified/)
    const cfg = await owner.json(`/api/organizations/${org.id}/sso`)
    const saved = await owner.call(`/api/organizations/${org.id}/sso`, 'POST', {
      enabled: true,
      identifier,
      data: { ...cfg.data, allowUnverifiedEmail: true },
    })
    expect(saved.status).toBe(200)
    const optedOut = await oidcLogin(idp, identifier, {
      sub: unique('sub'),
      email: `${unique('optout')}@example.com`,
      email_verified: false,
    })
    expect(optedOut.token?.status).toBe(200)
  })

  it('uses only verified email claims, never usernames', async () => {
    const { identifier } = await ssoOrg()
    const unverified = await oidcLogin(idp, identifier, {
      sub: unique('sub'),
      email: `${unique('unv')}@example.com`,
      email_verified: false,
    })
    expect(unverified.back.status).toBe(400)
    expect(await unverified.back.text()).toMatch(/not verified/)
    const username = await oidcLogin(idp, identifier, {
      sub: unique('sub'),
      preferred_username: `${unique('pu')}@example.com`,
      upn: `${unique('upn')}@example.com`,
    })
    expect(username.back.status).toBe(400)
    expect(await username.back.text()).toMatch(/did not return an email/)
  })

  it('links a signed-in account through the user identifier, only for the same email', async () => {
    const { owner, org, identifier } = await ssoOrg()
    const member = await actor(`${unique('linker')}@example.com`)
    await addMember(owner, org.id, member)
    const userIdentifier = await (await member.call('/api/accounts/sso/user-identifier')).text()
    const mismatch = await startSso({ identifier, userIdentifier })
    const bad = await callback(
      idp.authorize(mismatch.location, { sub: unique('sub'), email: 'other@example.com' }),
      mismatch.cookie,
    )
    expect(bad.status).toBe(400)
    expect(await bad.text()).toMatch(/different email/)

    // The link token is single use.
    const reused = await startSso({ identifier, userIdentifier })
    expect(reused.res.status).toBe(400)
    const fresh = await (await member.call('/api/accounts/sso/user-identifier')).text()
    const s = await startSso({ identifier, userIdentifier: fresh })
    const ok = await callback(
      idp.authorize(s.location, { sub: unique('sub'), email: member.email }),
      s.cookie,
    )
    expect(ok.status).toBe(302)
    // Unlinking needs a master password (this member has one).
    expect((await member.call(`/api/accounts/sso/${org.id}`, 'DELETE')).status).toBe(200)
    expect((await member.call(`/api/accounts/sso/${org.id}`, 'DELETE')).status).toBe(404)
  })

  it('returns the client state unchanged and supports the CLI loopback redirect', async () => {
    const { identifier } = await ssoOrg()
    const state = `Zy9_returnUri='/settings'_identifier=${identifier}`
    const s = await startSso({
      identifier,
      clientId: 'cli',
      redirectUri: 'http://localhost:8065',
      state,
    })
    expect(s.res.status).toBe(302)
    const back = await callback(
      idp.authorize(s.location, { sub: unique('sub'), email: `${unique('cli')}@example.com` }),
      s.cookie,
    )
    const loc = new URL(back.headers.get('Location') ?? '')
    expect(`${loc.origin}`).toBe('http://localhost:8065')
    expect(loc.searchParams.get('state')).toBe(state)
    const token = await redeem(
      codeFrom(loc.toString()),
      s.verifier,
      { client_id: 'cli' },
      'http://localhost:8065',
    )
    expect(token.status).toBe(200)
  })
})

/** The SSO external ID of a member, from the admin member list. */
async function profileSub(owner: Awaited<ReturnType<typeof actor>>, orgId: string, email: string) {
  const members = await owner.json(`/api/organizations/${orgId}/users`)
  return members.data.find((m: any) => m.email === email)?.ssoExternalId as string | undefined
}

describe('SSO security', () => {
  it('never redirects to a redirect URI outside the allow list', async () => {
    const { identifier } = await ssoOrg()
    for (const [clientId, redirectUri] of [
      ['web', 'https://evil.example.com/sso-connector.html'],
      ['web', `${BASE}/sso-connector.html.evil.example.com`],
      ['web', `${BASE}/other.html`],
      ['mobile', 'https://evil.example.com'],
      ['cli', 'https://localhost:8065'],
      ['unknown', `${BASE}/sso-connector.html`],
    ] as const) {
      const s = await startSso({ identifier, clientId, redirectUri })
      expect(s.res.status, `${clientId} ${redirectUri}`).toBe(400)
      expect(s.res.headers.get('Location')).toBeNull()
    }
  })

  it('requires PKCE S256 and a valid prevalidation token for the organization', async () => {
    const { identifier } = await ssoOrg()
    const other = await ssoOrg()
    const pre = (await (
      await call(`/identity/sso/prevalidate?domainHint=${other.identifier}`)
    ).json()) as any
    const base = {
      client_id: 'web',
      redirect_uri: `${BASE}/sso-connector.html`,
      response_type: 'code',
      scope: 'api offline_access',
      state: 's',
      code_challenge: 'x'.repeat(43),
      code_challenge_method: 'S256',
      domain_hint: identifier,
    }
    const wrongOrg = await call(
      `/identity/connect/authorize?${new URLSearchParams({ ...base, ssoToken: pre.token })}`,
    )
    expect(wrongOrg.status).toBe(400)
    const plain = await call(
      `/identity/connect/authorize?${new URLSearchParams({ ...base, code_challenge_method: 'plain', ssoToken: pre.token })}`,
    )
    expect(plain.status).toBe(400)
    expect((await call('/identity/sso/prevalidate?domainHint=does-not-exist')).status).toBe(400)
  })

  it('binds the callback to the browser that started it and to the state, once', async () => {
    const { identifier } = await ssoOrg()
    const user = { sub: unique('sub'), email: `${unique('bind')}@example.com` }
    const s = await startSso({ identifier })
    const back = idp.authorize(s.location, user)
    expect((await callback(back, '')).status).toBe(400)
    expect((await callback(back, '__Host-cw-sso=forged.cookie')).status).toBe(400)
    const tampered = new URL(back)
    tampered.searchParams.set('state', 'not-our-state')
    expect((await callback(tampered.toString(), s.cookie)).status).toBe(400)
    expect((await callback(back, s.cookie)).status).toBe(302)
    // Replaying the same callback fails: the flow is single use.
    expect((await callback(back, s.cookie)).status).toBe(400)
  })

  it('rejects ID tokens with a wrong audience, issuer, nonce, signature or algorithm', async () => {
    const { identifier } = await ssoOrg()
    const attempt = async () => {
      const s = await startSso({ identifier })
      return callback(
        idp.authorize(s.location, { sub: unique('sub'), email: `${unique('t')}@example.com` }),
        s.cookie,
      )
    }
    const other = (await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair
    const cases: (typeof idp.tamper)[] = [
      { idToken: (c) => ({ ...c, aud: 'someone-else' }) },
      { idToken: (c) => ({ ...c, iss: 'https://evil.example.com' }) },
      { idToken: (c) => ({ ...c, nonce: 'replayed-nonce' }) },
      { idToken: (c) => ({ ...c, exp: Math.floor(Date.now() / 1000) - 600 }) },
      { otherKey: other },
      { alg: 'none' },
    ]
    try {
      for (const t of cases) {
        idp.tamper = t
        const res = await attempt()
        expect(res.status, JSON.stringify(Object.keys(t))).toBe(400)
      }
    } finally {
      idp.tamper = {}
    }
    expect((await attempt()).status).toBe(302)
  })

  it('binds the code to the client, redirect URI and PKCE verifier, and spends it once', async () => {
    const { identifier } = await ssoOrg()
    const s = await startSso({ identifier })
    const back = await callback(
      idp.authorize(s.location, { sub: unique('sub'), email: `${unique('code')}@example.com` }),
      s.cookie,
    )
    const code = codeFrom(back.headers.get('Location') ?? '')
    expect((await redeem(code, 'a'.repeat(64))).status).toBe(400)
    expect((await redeem(code, s.verifier, { client_id: 'browser' })).status).toBe(400)
    expect((await redeem(code, s.verifier, {}, `${BASE}/other`)).status).toBe(400)
    expect((await redeem(code, s.verifier)).status).toBe(200)
    expect((await redeem(code, s.verifier)).status).toBe(400)
  })

  it('asks for two-step login and keeps the code valid until it is passed', async () => {
    const { owner, org, identifier } = await ssoOrg()
    const member = await actor(`${unique('tf')}@example.com`)
    await addMember(owner, org.id, member)
    const key = generateTotpKey()
    const got = (await member.json('/api/two-factor/get-authenticator', 'POST', {
      masterPasswordHash: 'client-derived-hash',
    })) as any
    const put = await member.call('/api/two-factor/authenticator', 'PUT', {
      key,
      token: await totpAt(key, clock.now()),
      userVerificationToken: got.userVerificationToken,
    })
    expect(put.status).toBe(200)
    const s = await startSso({ identifier })
    const back = await callback(
      idp.authorize(s.location, { sub: unique('sub'), email: member.email }),
      s.cookie,
    )
    const code = codeFrom(back.headers.get('Location') ?? '')
    const first = await redeem(code, s.verifier)
    expect(first.status).toBe(400)
    expect(((await first.json()) as any).TwoFactorProviders2).toBeTruthy()
    // A fresh time step: the enrolment code cannot be used twice.
    const real = clock.now
    clock.now = () => real() + 60_000
    try {
      const second = await redeem(code, s.verifier, {
        twoFactorProvider: '0',
        twoFactorToken: (await totpAt(key, clock.now())) as string,
      })
      expect(second.status).toBe(200)
    } finally {
      clock.now = real
    }
  })

  it('uses the UserInfo endpoint and additional claim types when configured', async () => {
    const { identifier } = await ssoOrg({
      getClaimsFromUserInfoEndpoint: true,
      additionalEmailClaimTypes: 'mail_custom',
    })
    const email = `${unique('claims')}@example.com`
    const r = await oidcLogin(idp, identifier, {
      sub: unique('sub'),
      mail_custom: email,
      email_verified: true,
    })
    expect(r.token?.status).toBe(200)
    const profile = (await (
      await authedCall(r.body.access_token, '/api/accounts/profile')
    ).json()) as any
    expect(profile.email).toBe(email)
  })
})

describe('SSO configuration', () => {
  it('returns the service provider URLs and validates the settings', async () => {
    const { owner, org, identifier } = await ssoOrg()
    const cfg = await owner.json(`/api/organizations/${org.id}/sso`)
    expect(cfg).toMatchObject({ enabled: true, identifier })
    expect(cfg.urls.callbackPath).toBe(`${BASE}/sso/oidc-signin`)
    expect(cfg.urls.spAcsUrl).toBe(`${BASE}/sso/saml2/${org.id}/Acs`)
    expect(cfg.data.clientId).toBe(idp.clientId)
    // The client secret is never returned and is encrypted at rest.
    expect(cfg.data.clientSecret).toBe('********')
    const [stored] = await createDb(env.DB)
      .select()
      .from(schema.ssoConfigs)
      .where(eq(schema.ssoConfigs.organizationUuid, org.id))
    expect(stored?.data).not.toContain(idp.clientSecret)
    // Saving the placeholder keeps the stored secret: logins still authenticate to the provider.
    const resave = await owner.call(`/api/organizations/${org.id}/sso`, 'POST', {
      enabled: true,
      identifier,
      data: cfg.data,
    })
    expect(resave.status).toBe(200)
    const after = await oidcLogin(idp, identifier, {
      sub: unique('sub'),
      email: `${unique('resave')}@example.com`,
    })
    expect(after.token?.status).toBe(200)

    const bad = await owner.call(`/api/organizations/${org.id}/sso`, 'POST', {
      enabled: true,
      identifier,
      data: { configType: 1, authority: 'http://insecure.example.com', clientId: '' },
    })
    expect(bad.status).toBe(400)
    const taken = await ssoOrg()
    const dup = await owner.call(`/api/organizations/${org.id}/sso`, 'POST', {
      enabled: false,
      identifier: taken.identifier.toUpperCase(),
      data: null,
    })
    expect(dup.status).toBe(400)

    const test = await owner.json(`/api/organizations/${org.id}/sso/test`, 'POST', {
      data: cfg.data,
    })
    expect(test).toMatchObject({ success: true, issuer: idp.issuer })
    const broken = await owner.json(`/api/organizations/${org.id}/sso/test`, 'POST', {
      data: { ...cfg.data, authority: `${idp.issuer}/missing-tenant` },
    })
    expect(broken.success).toBe(false)
  })

  it('requires the client secret again when the provider settings change', async () => {
    const { owner, org, identifier } = await ssoOrg()
    const cfg = await owner.json(`/api/organizations/${org.id}/sso`)
    for (const change of [
      { authority: 'https://other-idp.example.com' },
      { metadataAddress: `${idp.issuer}/.well-known/openid-configuration` },
      { clientId: 'another-client' },
    ]) {
      const data = { ...cfg.data, ...change }
      const save = await owner.call(`/api/organizations/${org.id}/sso`, 'POST', {
        enabled: true,
        identifier,
        data,
      })
      expect(save.status, JSON.stringify(change)).toBe(400)
      const test = await owner.json(`/api/organizations/${org.id}/sso/test`, 'POST', { data })
      expect(test.success).toBe(false)
      expect(test.problems.join(' ')).toMatch(/client secret again/)
    }
    // With the secret entered again the change is accepted.
    const ok = await owner.call(`/api/organizations/${org.id}/sso`, 'POST', {
      enabled: true,
      identifier,
      data: { ...cfg.data, clientId: 'another-client', clientSecret: 'new-secret' },
    })
    expect(ok.status).toBe(200)
  })

  it('refuses a link token to a session without a master password', async () => {
    const { identifier } = await ssoOrg()
    const r = await oidcLogin(idp, identifier, {
      sub: unique('sub'),
      email: `${unique('nomp')}@example.com`,
    })
    const res = await authedCall(r.body.access_token, '/api/accounts/sso/user-identifier')
    expect(res.status).toBe(400)
  })

  it('only lets members with the manage SSO permission read or change it', async () => {
    const { owner, org } = await ssoOrg()
    const user = await actor(`${unique('plain')}@example.com`)
    await addMember(owner, org.id, user)
    expect((await user.call(`/api/organizations/${org.id}/sso`)).status).toBe(403)
    expect(
      (await user.call(`/api/organizations/${org.id}/sso`, 'POST', { enabled: false })).status,
    ).toBe(403)
  })

  it('reports the SSO URL in the server configuration', async () => {
    const res = await call('/api/config')
    expect(((await res.json()) as any).environment.sso).toBe(`${env.DOMAIN}/sso`)
  })
})
