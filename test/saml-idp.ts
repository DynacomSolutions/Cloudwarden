import * as xmldsig from 'xmldsigjs'
import { b64, generateSpKeys, type SpKeys } from '../src/sso/pki'
import { NS, parseXml, serialize } from '../src/sso/xml'

/**
 * A test SAML identity provider: a generated RSA key and self-signed certificate, and builders for
 * signed (or deliberately broken) Responses. Nothing leaves the test process.
 */
export interface SamlIdp {
  keys: SpKeys
  pem: string
  entityId: string
}

export async function samlIdp(entityId = 'https://idp.example.com/saml'): Promise<SamlIdp> {
  const keys = await generateSpKeys('Test IdP')
  const body = b64(keys.certificateDer).replace(/(.{64})/g, '$1\n')
  return {
    keys,
    entityId,
    pem: `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----\n`,
  }
}

export interface AssertionOptions {
  acs: string
  audience: string
  inResponseTo: string | null
  nameId: string
  email?: string
  name?: string
  issuer?: string
  assertionId?: string
  responseId?: string
  notBefore?: Date
  notOnOrAfter?: Date
  subjectNotOnOrAfter?: Date
  destination?: string | null
  status?: string
  nameIdFormat?: string
}

const iso = (d: Date) => d.toISOString()

export function responseXml(idp: SamlIdp, o: AssertionOptions) {
  const now = new Date()
  const issuer = o.issuer ?? idp.entityId
  const aid = o.assertionId ?? `_a${crypto.randomUUID().replace(/-/g, '')}`
  const rid = o.responseId ?? `_r${crypto.randomUUID().replace(/-/g, '')}`
  const irt = o.inResponseTo ? ` InResponseTo="${o.inResponseTo}"` : ''
  const nb = o.notBefore ?? new Date(now.getTime() - 60_000)
  const na = o.notOnOrAfter ?? new Date(now.getTime() + 5 * 60_000)
  const sna = o.subjectNotOnOrAfter ?? na
  const attrs = [
    o.email
      ? `<saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"><saml:AttributeValue>${o.email}</saml:AttributeValue></saml:Attribute>`
      : '',
    o.name
      ? `<saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"><saml:AttributeValue>${o.name}</saml:AttributeValue></saml:Attribute>`
      : '',
  ].join('')
  const destination = o.destination === null ? '' : ` Destination="${o.destination ?? o.acs}"`
  const assertion =
    `<saml:Assertion xmlns:saml="${NS.saml}" ID="${aid}" Version="2.0" IssueInstant="${iso(now)}">` +
    `<saml:Issuer>${issuer}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="${o.nameIdFormat ?? 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'}">${o.nameId}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData${irt} NotOnOrAfter="${iso(sna)}" Recipient="${o.acs}"/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${iso(nb)}" NotOnOrAfter="${iso(na)}"><saml:AudienceRestriction><saml:Audience>${o.audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${iso(now)}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    (attrs ? `<saml:AttributeStatement>${attrs}</saml:AttributeStatement>` : '') +
    '</saml:Assertion>'
  return {
    aid,
    rid,
    assertion,
    response:
      `<samlp:Response xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${rid}" Version="2.0" IssueInstant="${iso(now)}"${destination}${irt}>` +
      `<saml:Issuer>${issuer}</saml:Issuer>` +
      `<samlp:Status><samlp:StatusCode Value="${o.status ?? 'urn:oasis:names:tc:SAML:2.0:status:Success'}"/></samlp:Status>` +
      '__ASSERTION__' +
      '</samlp:Response>',
  }
}

/** Signs the element with `id` inside `xml` (enveloped, exc-c14n), placing the signature after its Issuer. */
export async function signElement(
  xml: string,
  id: string,
  idp: SamlIdp,
  hash: 'SHA-1' | 'SHA-256' = 'SHA-256',
): Promise<string> {
  const doc = parseXml(xml)
  const key = await crypto.subtle.importKey(
    'pkcs8',
    idp.keys.privateKeyPkcs8,
    { name: 'RSASSA-PKCS1-v1_5', hash },
    false,
    ['sign'],
  )
  const all = doc.getElementsByTagName('*')
  let target: ReturnType<typeof doc.getElementsByTagName>[number] | null = null
  for (let i = 0; i < all.length; i++)
    if (all.item(i)?.getAttribute('ID') === id) target = all.item(i)
  if (!target) throw new Error(`no element ${id}`)
  const signed = new xmldsig.SignedXml(doc as never)
  signed.XmlSignature.SignedInfo.CanonicalizationMethod.Algorithm =
    'http://www.w3.org/2001/10/xml-exc-c14n#'
  const sig = await signed.Sign({ name: 'RSASSA-PKCS1-v1_5', hash } as never, key, doc as never, {
    x509: [b64(idp.keys.certificateDer)],
    references: [{ uri: `#${id}`, hash, transforms: ['enveloped', 'exc-c14n'] }],
  })
  const sigEl = sig.GetXml() as never
  const issuer = target.getElementsByTagNameNS(NS.saml, 'Issuer').item(0)
  target.insertBefore(sigEl, (issuer?.nextSibling ?? target.firstChild) as never)
  return serialize(doc)
}

export interface BuildOptions extends AssertionOptions {
  signAssertion?: boolean
  signResponse?: boolean
  hash?: 'SHA-1' | 'SHA-256'
  /** Signs with this other identity provider's key instead. */
  signer?: SamlIdp
}

/** A complete Response, signed as requested, base64 encoded for the POST binding. */
export async function buildResponse(idp: SamlIdp, o: BuildOptions): Promise<string> {
  const parts = responseXml(idp, o)
  const signer = o.signer ?? idp
  let assertion = parts.assertion
  if (o.signAssertion !== false) assertion = await signElement(assertion, parts.aid, signer, o.hash)
  let xml = parts.response.replace('__ASSERTION__', assertion.replace(/^<\?xml[^>]*\?>/, ''))
  if (o.signResponse) xml = await signElement(xml, parts.rid, signer, o.hash)
  return b64(new TextEncoder().encode(xml))
}

/** Encrypts an assertion to the SP certificate (xmlenc: RSA-OAEP key transport, AES content). */
export async function encryptAssertion(
  assertionXml: string,
  spCertDer: Uint8Array,
  mode: 'gcm' | 'cbc',
): Promise<string> {
  const { parseCertificate } = await import('../src/sso/pki')
  const spki = parseCertificate(spCertDer).spki
  const rsa = await crypto.subtle.importKey(
    'spki',
    spki,
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt'],
  )
  const raw = crypto.getRandomValues(new Uint8Array(mode === 'gcm' ? 32 : 16))
  const plain = new TextEncoder().encode(assertionXml)
  let cipher: Uint8Array
  let alg: string
  if (mode === 'gcm') {
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain))
    cipher = new Uint8Array([...iv, ...ct])
    alg = 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
  } else {
    // XML Encryption padding: random bytes, last byte holds the pad length.
    const pad = 16 - (plain.length % 16)
    const padded = new Uint8Array(plain.length + pad)
    padded.set(plain)
    padded.set(crypto.getRandomValues(new Uint8Array(pad - 1)), plain.length)
    padded[padded.length - 1] = pad
    const key = await crypto.subtle.importKey('raw', raw, 'AES-CBC', false, ['encrypt'])
    const iv = crypto.getRandomValues(new Uint8Array(16))
    // WebCrypto adds a PKCS#7 block; drop it to keep only our own padding.
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, padded))
    cipher = new Uint8Array([...iv, ...ct.slice(0, padded.length)])
    alg = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc'
  }
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsa, raw))
  return (
    `<saml:EncryptedAssertion xmlns:saml="${NS.saml}"><xenc:EncryptedData xmlns:xenc="${NS.xenc}" Type="http://www.w3.org/2001/04/xmlenc#Element">` +
    `<xenc:EncryptionMethod Algorithm="${alg}"/>` +
    `<ds:KeyInfo xmlns:ds="${NS.ds}"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>` +
    `<xenc:CipherData><xenc:CipherValue>${b64(wrapped)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
    `<xenc:CipherData><xenc:CipherValue>${b64(cipher)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>`
  )
}
