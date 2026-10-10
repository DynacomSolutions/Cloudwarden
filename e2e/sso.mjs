// End-to-end SSO (TASKS #288): an organisation configured for OpenID Connect against the mock
// provider in `oidc-idp.mjs`; the script plays the web client (prevalidate, authorize with PKCE,
// follow the redirects with the flow cookie, redeem the code) and checks the new member's session.
// The dev server must run with SSO_ALLOW_INSECURE_LOOPBACK=true (http provider on 127.0.0.1).
import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { buildAccount } from './crypto.mjs'
import { startOidcIdp } from './oidc-idp.mjs'

const b64u = (buf) => Buffer.from(buf).toString('base64url')

/**
 * `direct` is the plain http address of the dev server; `base` is its public (TLS proxy) origin,
 * which appears in redirects and is rewritten to `direct` here.
 */
export async function runSso({ direct, base, pass, ownerEmail, registrationToken }) {
  const local = (url) => url.replace(base, direct)
  const api = (path, token, body, method = 'POST') =>
    fetch(`${direct}${path}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    })

  // Owner account and organisation.
  const stamp = Date.now()
  const owner = await buildAccount(ownerEmail, 'owner password 1 for sso')
  const reg = await fetch(`${direct}/identity/accounts/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...owner.body, emailVerificationToken: registrationToken }),
  })
  assert.equal(reg.status, 200, await reg.text())
  const login = await fetch(`${direct}/identity/connect/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      username: ownerEmail,
      password: owner.masterPasswordHash,
      scope: 'api offline_access',
      client_id: 'web',
      deviceType: '9',
      deviceName: 'e2e',
      deviceIdentifier: crypto.randomUUID(),
    }),
  })
  assert.equal(login.status, 200, await login.clone().text())
  const ownerToken = (await login.json()).access_token
  const org = await api('/api/organizations', ownerToken, {
    name: 'SSO e2e',
    billingEmail: ownerEmail,
    key: '4.orgKeyForOwner',
    keys: { publicKey: 'orgPublic', encryptedPrivateKey: '2.orgPrivate' },
    planType: 0,
  })
  assert.equal(org.status, 200, await org.clone().text())
  const orgId = (await org.json()).id

  const memberEmail = `sso-member-${stamp}@example.com`
  const clientId = 'cloudwarden-e2e'
  const clientSecret = b64u(randomBytes(18))
  const idp = await startOidcIdp({
    clientId,
    clientSecret,
    user: { sub: `e2e-${stamp}`, email: memberEmail, email_verified: true, name: 'SSO Member' },
  })
  try {
    const identifier = `e2e-${stamp}`
    const cfg = await api(`/api/organizations/${orgId}/sso`, ownerToken, {
      enabled: true,
      identifier,
      data: {
        configType: 1,
        memberDecryptionType: 0,
        authority: idp.issuer,
        clientId,
        clientSecret,
      },
    })
    assert.equal(cfg.status, 200, await cfg.clone().text())
    const invite = await api(`/api/organizations/${orgId}/users/invite`, ownerToken, {
      emails: [memberEmail],
      type: 2,
      accessAll: false,
      collections: [],
      groups: [],
    })
    assert.equal(invite.status, 200, await invite.clone().text())
    pass('SSO: organisation configured for the mock OIDC provider, member invited')

    // The web client's side of the login.
    const pre = await fetch(`${direct}/identity/sso/prevalidate?domainHint=${identifier}`)
    assert.equal(pre.status, 200, await pre.clone().text())
    const { token: ssoToken } = await pre.json()
    const verifier = b64u(randomBytes(48))
    const challenge = b64u(createHash('sha256').update(verifier).digest())
    const redirectUri = `${base}/sso-connector.html`
    const state = `e2estate_identifier=${identifier}`
    const authorize = await fetch(
      `${direct}/identity/connect/authorize?${new URLSearchParams({
        client_id: 'web',
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'api offline_access',
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        response_mode: 'query',
        domain_hint: identifier,
        ssoToken,
      })}`,
      { redirect: 'manual' },
    )
    assert.equal(authorize.status, 302, await authorize.clone().text())
    const cookie = (authorize.headers.get('set-cookie') ?? '').split(';')[0]
    const atIdp = await fetch(authorize.headers.get('location'), { redirect: 'manual' })
    assert.equal(atIdp.status, 302)
    const callback = await fetch(local(atIdp.headers.get('location')), {
      headers: { Cookie: cookie },
      redirect: 'manual',
    })
    assert.equal(callback.status, 302, await callback.clone().text())
    const done = new URL(callback.headers.get('location'))
    assert.equal(`${done.origin}${done.pathname}`, redirectUri)
    assert.equal(done.searchParams.get('state'), state)
    pass('SSO: authorize, provider sign-in and callback return a code with the client state')

    const tokenRes = await fetch(`${direct}/identity/connect/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: done.searchParams.get('code'),
        code_verifier: verifier,
        redirect_uri: redirectUri,
        client_id: 'web',
        scope: 'api offline_access',
        deviceType: '9',
        deviceName: 'e2e',
        deviceIdentifier: crypto.randomUUID(),
      }),
    })
    assert.equal(tokenRes.status, 200, await tokenRes.clone().text())
    const session = await tokenRes.json()
    assert.equal(session.UserDecryptionOptions.HasMasterPassword, false)
    const profile = await (
      await api('/api/accounts/profile', session.access_token, undefined, 'GET')
    ).json()
    assert.equal(profile.email, memberEmail)
    const membership = profile.organizations.find((o) => o.id === orgId)
    assert.equal(membership?.ssoBound, true)
    pass('SSO: code redeemed with PKCE; just-in-time member without a master password')

    const discovery = await (
      await fetch(`${direct}/identity/.well-known/openid-configuration`)
    ).json()
    assert.ok(discovery.jwks_uri?.endsWith('/identity/.well-known/openid-configuration/jwks'))
    pass('identity discovery document served')
  } finally {
    await idp.close()
  }
}
