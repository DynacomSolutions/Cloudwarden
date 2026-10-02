import { beforeAll, describe, expect, it } from 'vitest'
import { BASE } from './helpers'
import { actor, createOrg } from './org-helpers'
import { buildResponse, type SamlIdp, samlIdp } from './saml-idp'
import { call, claimDomain, codeFrom, redeem, startSso } from './sso-helpers'

let idp: SamlIdp
beforeAll(async () => {
  idp = await samlIdp()
})

let n = 0
const unique = (p: string) => `${p}-${Date.now()}-${++n}`

async function samlOrg(extra: Record<string, unknown> = {}) {
  const owner = await actor(`${unique('owner')}@example.com`)
  const org = await createOrg(owner)
  const identifier = unique('saml')
  await claimDomain(org.id)
  const res = await owner.call(`/api/organizations/${org.id}/sso`, 'POST', {
    enabled: true,
    identifier,
    data: {
      configType: 2,
      memberDecryptionType: 0,
      spUniqueEntityId: true,
      spWantAssertionsSigned: true,
      idpEntityId: idp.entityId,
      idpBindingType: 1,
      idpSingleSignOnServiceUrl: 'https://idp.example.com/sso',
      idpX509PublicCert: idp.pem,
      ...extra,
    },
  })
  expect(res.status).toBe(200)
  return { owner, org, identifier }
}

async function requestId(location: string) {
  const u = new URL(location)
  const bytes = Uint8Array.from(atob(u.searchParams.get('SAMLRequest') ?? ''), (c) =>
    c.charCodeAt(0),
  )
  const xml = await new Response(
    new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw')),
  ).text()
  return { id: /ID="([^"]+)"/.exec(xml)?.[1] ?? '', relay: u.searchParams.get('RelayState') ?? '' }
}

const acs = (orgId: string, body: Record<string, string>, cookie: string) =>
  call(`/sso/saml2/${orgId}/Acs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookie },
    body: new URLSearchParams(body).toString(),
  })

describe('SSO with SAML 2.0', () => {
  it('signs in through the ACS and serves metadata', async () => {
    const { org, identifier } = await samlOrg()
    const meta = await call(`/sso/saml2/${org.id}`)
    expect(meta.status).toBe(200)
    expect(await meta.text()).toContain(`${BASE}/sso/saml2/${org.id}/Acs`)

    const s = await startSso({ identifier })
    expect(s.res.status).toBe(302)
    expect(s.location.startsWith('https://idp.example.com/sso?SAMLRequest=')).toBe(true)
    const { id, relay } = await requestId(s.location)
    const email = `${unique('saml')}@example.com`
    const response = await buildResponse(idp, {
      acs: `${BASE}/sso/saml2/${org.id}/Acs`,
      audience: `${BASE}/sso/saml2/${org.id}`,
      inResponseTo: id,
      nameId: unique('nameid'),
      email,
    })
    const back = await acs(org.id, { SAMLResponse: response, RelayState: relay }, s.cookie)
    expect(back.status).toBe(302)
    const token = await redeem(codeFrom(back.headers.get('Location') ?? ''), s.verifier)
    expect(token.status).toBe(200)
    // Posting the same response again (same flow) is refused.
    expect(
      (await acs(org.id, { SAMLResponse: response, RelayState: relay }, s.cookie)).status,
    ).toBe(400)
  })

  it('refuses a replayed unsolicited assertion in a new flow', async () => {
    const { org, identifier } = await samlOrg({ idpAllowUnsolicitedAuthnResponse: true })
    const response = await buildResponse(idp, {
      acs: `${BASE}/sso/saml2/${org.id}/Acs`,
      audience: `${BASE}/sso/saml2/${org.id}`,
      inResponseTo: null,
      nameId: unique('nameid'),
      email: `${unique('replay')}@example.com`,
    })
    const a = await startSso({ identifier })
    const first = await acs(
      org.id,
      { SAMLResponse: response, RelayState: (await requestId(a.location)).relay },
      a.cookie,
    )
    expect(first.status).toBe(302)
    const b = await startSso({ identifier })
    const second = await acs(
      org.id,
      { SAMLResponse: response, RelayState: (await requestId(b.location)).relay },
      b.cookie,
    )
    expect(second.status).toBe(400)
    expect(await second.text()).toMatch(/already used/)
  })

  it('refuses a response sent to another organization ACS', async () => {
    const one = await samlOrg()
    const two = await samlOrg()
    const s = await startSso({ identifier: one.identifier })
    const { id, relay } = await requestId(s.location)
    const response = await buildResponse(idp, {
      acs: `${BASE}/sso/saml2/${two.org.id}/Acs`,
      audience: `${BASE}/sso/saml2/${two.org.id}`,
      inResponseTo: id,
      nameId: 'x',
      email: `${unique('cross')}@example.com`,
    })
    expect(
      (await acs(two.org.id, { SAMLResponse: response, RelayState: relay }, s.cookie)).status,
    ).toBe(400)
  })
})
