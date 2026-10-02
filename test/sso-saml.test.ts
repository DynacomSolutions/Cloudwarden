import { env } from 'cloudflare:workers'
import { beforeAll, describe, expect, it } from 'vitest'
import { type SsoConfigData, ssoUrls } from '../src/sso/config'
import { SsoError } from '../src/sso/errors'
import { generateSpKeys, type SpKeys } from '../src/sso/pki'
import { buildAuthnRequest, spMetadata, validateSamlResponse } from '../src/sso/saml'
import { parseXml } from '../src/sso/xml'
import {
  type BuildOptions,
  buildResponse,
  encryptAssertion,
  responseXml,
  type SamlIdp,
  samlIdp,
  signElement,
} from './saml-idp'

const ORG = '00000000-0000-4000-8000-0000000000a1'
const urls = ssoUrls(env, ORG)
const REQ = '_req0001'

let idp: SamlIdp
let other: SamlIdp
let sp: SpKeys
let data: SsoConfigData

beforeAll(async () => {
  idp = await samlIdp()
  other = await samlIdp()
  sp = await generateSpKeys('Test SP')
  data = {
    configType: 2,
    idpEntityId: idp.entityId,
    idpSingleSignOnServiceUrl: 'https://idp.example.com/sso',
    idpX509PublicCert: idp.pem,
    spWantAssertionsSigned: true,
  }
})

const base = (o: Partial<BuildOptions> = {}): BuildOptions => ({
  acs: urls.spAcsUrl,
  audience: urls.spEntityId,
  inResponseTo: REQ,
  nameId: 'user-123',
  email: 'saml@example.com',
  name: 'Saml User',
  ...o,
})

const validate = (resp: string, d: SsoConfigData = data, now = Date.now()) =>
  validateSamlResponse(env, ORG, d, sp, resp, { requestId: REQ, now })

const rejects = async (p: Promise<unknown>, msg: RegExp) => {
  const err = await p.then(
    () => null,
    (e: unknown) => e,
  )
  expect(err).toBeInstanceOf(SsoError)
  expect((err as Error).message).toMatch(msg)
}

describe('SAML response validation', () => {
  it('accepts a signed assertion and maps the attributes', async () => {
    const r = await validate(await buildResponse(idp, base()))
    expect(r.identity).toEqual({
      externalId: 'user-123',
      email: 'saml@example.com',
      name: 'Saml User',
    })
    expect(r.assertionKey.startsWith(`${idp.entityId}|_a`)).toBe(true)
  })

  it('accepts a signed response with a signed assertion', async () => {
    const r = await validate(await buildResponse(idp, base({ signResponse: true })))
    expect(r.identity.externalId).toBe('user-123')
  })

  it('rejects an unsigned assertion', async () => {
    await rejects(validate(await buildResponse(idp, base({ signAssertion: false }))), /not signed/)
    // A signed response alone is not enough when assertions must be signed.
    await rejects(
      validate(await buildResponse(idp, base({ signAssertion: false, signResponse: true }))),
      /not signed/,
    )
  })

  it('accepts a signed response without assertion signature when allowed', async () => {
    const r = await validate(
      await buildResponse(idp, base({ signAssertion: false, signResponse: true })),
      { ...data, spWantAssertionsSigned: false },
    )
    expect(r.identity.email).toBe('saml@example.com')
  })

  it('rejects a signature from another key', async () => {
    await rejects(
      validate(await buildResponse(idp, base({ signer: other }))),
      /signature is invalid/,
    )
  })

  it('rejects a tampered assertion', async () => {
    const xml = new TextDecoder().decode(
      Uint8Array.from(atob(await buildResponse(idp, base())), (c) => c.charCodeAt(0)),
    )
    const tampered = xml.replace('user-123', 'admin-1')
    await rejects(validate(btoa(tampered)), /signature is invalid/)
  })

  it('rejects signature wrapping (a second, unsigned assertion)', async () => {
    const parts = responseXml(idp, base())
    const signed = (await signElement(parts.assertion, parts.aid, idp)).replace(
      /^<\?xml[^>]*\?>/,
      '',
    )
    const evil = parts.assertion.replace('user-123', 'evil').replace(parts.aid, '_evil')
    const xml = parts.response.replace('__ASSERTION__', evil + signed)
    await rejects(validate(btoa(xml)), /exactly one assertion/)
    // The signed assertion hidden inside an extension, with an unsigned copy carrying its ID.
    const copy = parts.assertion.replace('user-123', 'evil')
    const wrapped = parts.response.replace(
      '__ASSERTION__',
      `<samlp:Extensions>${signed}</samlp:Extensions>${copy}`,
    )
    await rejects(validate(btoa(wrapped)), /exactly one assertion|misplaced|unique ID/)
  })

  it('rejects the wrong audience, recipient, issuer and destination', async () => {
    await rejects(
      validate(await buildResponse(idp, base({ audience: 'https://other.example.com' }))),
      /audience/,
    )
    await rejects(
      validate(
        await buildResponse(idp, base({ acs: 'https://other.example.com/acs', destination: null })),
      ),
      /subject confirmation/,
    )
    await rejects(
      validate(await buildResponse(idp, base({ issuer: 'https://evil.example.com' }))),
      /issuer/,
    )
    await rejects(
      validate(await buildResponse(idp, base({ destination: 'https://other.example.com/acs' }))),
      /destination/,
    )
  })

  it('rejects expired and not yet valid assertions, allowing two minutes of skew', async () => {
    const now = Date.now()
    await rejects(
      validate(
        await buildResponse(
          idp,
          base({ notBefore: new Date(now - 3_600_000), notOnOrAfter: new Date(now - 180_000) }),
        ),
      ),
      /expired/,
    )
    await rejects(
      validate(await buildResponse(idp, base({ notBefore: new Date(now + 600_000) }))),
      /not yet valid/,
    )
    const skewed = await validate(
      await buildResponse(idp, base({ notBefore: new Date(now + 60_000) })),
    )
    expect(skewed.identity.externalId).toBe('user-123')
  })

  it('rejects a response to another request and unsolicited responses', async () => {
    await rejects(
      validate(await buildResponse(idp, base({ inResponseTo: '_other' }))),
      /different request/,
    )
    await rejects(validate(await buildResponse(idp, base({ inResponseTo: null }))), /Unsolicited/)
  })

  it('rejects a failed status', async () => {
    await rejects(
      validate(
        await buildResponse(idp, base({ status: 'urn:oasis:names:tc:SAML:2.0:status:Responder' })),
      ),
      /did not authenticate/,
    )
  })

  it('rejects SHA-1 unless the minimum allows it', async () => {
    const sha1 = await buildResponse(idp, base({ hash: 'SHA-1' }))
    await rejects(validate(sha1), /weaker/)
    const ok = await validate(sha1, {
      ...data,
      spMinIncomingSigningAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    })
    expect(ok.identity.externalId).toBe('user-123')
  })

  it('rejects DTDs and malformed XML', async () => {
    const dtd = `<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "x">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`
    await rejects(validate(btoa(dtd)), /DTD/)
    await rejects(validate(btoa('<samlp:Response')), /well-formed/)
  })

  it('uses the email as the identifier for transient name IDs', async () => {
    const r = await validate(
      await buildResponse(
        idp,
        base({
          nameId: 'random-1',
          nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
        }),
      ),
    )
    expect(r.identity.externalId).toBe('saml@example.com')
  })
})

describe('SAML encrypted assertions', () => {
  for (const mode of ['gcm', 'cbc'] as const) {
    it(`decrypts an AES-${mode.toUpperCase()} assertion and checks its signature`, async () => {
      const parts = responseXml(idp, base())
      const signed = (await signElement(parts.assertion, parts.aid, idp)).replace(
        /^<\?xml[^>]*\?>/,
        '',
      )
      const enc = await encryptAssertion(signed, sp.certificateDer, mode)
      const xml = parts.response.replace('__ASSERTION__', enc)
      const r = await validate(btoa(xml))
      expect(r.identity.externalId).toBe('user-123')
    })
  }

  it('rejects an encrypted assertion signed by another key', async () => {
    const parts = responseXml(idp, base())
    const signed = (await signElement(parts.assertion, parts.aid, other)).replace(
      /^<\?xml[^>]*\?>/,
      '',
    )
    const enc = await encryptAssertion(signed, sp.certificateDer, 'gcm')
    await rejects(
      validate(btoa(parts.response.replace('__ASSERTION__', enc))),
      /signature is invalid/,
    )
  })

  it('rejects an assertion encrypted to another service provider', async () => {
    const otherSp = await generateSpKeys('Other SP')
    const parts = responseXml(idp, base())
    const signed = (await signElement(parts.assertion, parts.aid, idp)).replace(
      /^<\?xml[^>]*\?>/,
      '',
    )
    const enc = await encryptAssertion(signed, otherSp.certificateDer, 'gcm')
    await rejects(
      validate(btoa(parts.response.replace('__ASSERTION__', enc))),
      /could not be decrypted/,
    )
  })
})

describe('SAML outbound messages', () => {
  it('publishes metadata with the SP certificate and ACS', () => {
    const xml = spMetadata(env, ORG, data, sp.certificateDer)
    const doc = parseXml(xml)
    expect(doc.documentElement?.getAttribute('entityID')).toBe(urls.spEntityId)
    expect(xml).toContain(urls.spAcsUrl)
    expect(xml).toContain('<ds:X509Certificate>')
  })

  it('builds a signed redirect AuthnRequest whose signature verifies', async () => {
    const out = await buildAuthnRequest(
      env,
      ORG,
      { ...data, spSigningBehavior: 1 },
      sp,
      REQ,
      'relay',
    )
    expect(out.binding).toBe('redirect')
    if (out.binding !== 'redirect') return
    const url = new URL(out.url)
    const raw = out.url.slice(out.url.indexOf('?') + 1)
    const signedPart = raw.slice(0, raw.indexOf('&Signature='))
    const sig = Uint8Array.from(atob(url.searchParams.get('Signature') ?? ''), (c) =>
      c.charCodeAt(0),
    )
    const { parseCertificate } = await import('../src/sso/pki')
    const spki = parseCertificate(sp.certificateDer).spki
    const key = await crypto.subtle.importKey(
      'spki',
      spki,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    )
    expect(
      await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        key,
        sig,
        new TextEncoder().encode(signedPart),
      ),
    ).toBe(true)
    // The request inflates to an AuthnRequest with our ID and ACS.
    const deflated = Uint8Array.from(atob(url.searchParams.get('SAMLRequest') ?? ''), (c) =>
      c.charCodeAt(0),
    )
    const xml = await new Response(
      new Blob([deflated]).stream().pipeThrough(new DecompressionStream('deflate-raw')),
    ).text()
    expect(xml).toContain(`ID="${REQ}"`)
    expect(xml).toContain(urls.spAcsUrl)
    expect(url.searchParams.get('RelayState')).toBe('relay')
  })

  it('builds a POST AuthnRequest', async () => {
    const out = await buildAuthnRequest(
      env,
      ORG,
      { ...data, idpBindingType: 2, spSigningBehavior: 1 },
      sp,
      REQ,
      'relay',
    )
    expect(out.binding).toBe('post')
    if (out.binding !== 'post') return
    const xml = atob(out.fields.SAMLRequest ?? '')
    expect(xml).toContain('<ds:Signature')
    expect(out.fields.RelayState).toBe('relay')
  })
})
