import * as xmldsig from 'xmldsigjs'
import { fromB64u, safeEqualStrings, utf8 } from '../auth/crypto'
import type { Bindings } from '../env'
import {
  NAMEID_FORMATS,
  Saml2BindingType,
  SIG_RSA_SHA256,
  SIGNING_ALGORITHMS,
  SpSigningBehavior,
  type SsoConfigData,
  spEntityId,
  ssoUrls,
} from './config'
import { SsoError } from './errors'
import {
  b64,
  certificatesFrom,
  type ParsedCertificate,
  parseCertificate,
  rsaVerifyKey,
  type SpKeys,
  spDecryptionKey,
  spSigningKey,
} from './pki'
import {
  child,
  children,
  countIds,
  type Document,
  descendants,
  type Element,
  esc,
  NS,
  parseXml,
  serialize,
  text,
} from './xml'

/**
 * SAML 2.0 service provider (TASKS #282): SP metadata, AuthnRequest (HTTP-Redirect or HTTP-POST,
 * optionally signed), and validation of the identity provider's Response: XML signature with the
 * configured certificate (`xmldsigjs`), signature wrapping defences, issuer, destination,
 * audience, time conditions, InResponseTo, replay, and encrypted assertions (RSA-OAEP with
 * AES-CBC or AES-GCM).
 */

/** Allowed clock difference with the identity provider. */
export const CLOCK_SKEW_MS = 2 * 60 * 1000
/** Upper bound for remembering an assertion ID when the assertion carries no expiry. */
const MAX_REPLAY_WINDOW_MS = 24 * 3600 * 1000

const STATUS_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
const TRANSIENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'
const BINDING_POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
const BINDING_REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'

const HASH_OF_SIG: Record<string, string> = {
  'http://www.w3.org/2000/09/xmldsig#rsa-sha1': 'SHA-1',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256': 'SHA-256',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384': 'SHA-384',
  'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512': 'SHA-512',
}
const DIGESTS: Record<string, number> = {
  'http://www.w3.org/2000/09/xmldsig#sha1': 0,
  'http://www.w3.org/2001/04/xmlenc#sha256': 1,
  'http://www.w3.org/2001/04/xmldsig-more#sha384': 2,
  'http://www.w3.org/2001/04/xmlenc#sha512': 3,
}
const TRANSFORMS = new Set([
  'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
  'http://www.w3.org/2001/10/xml-exc-c14n#',
  'http://www.w3.org/2001/10/xml-exc-c14n#WithComments',
  'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
  'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments',
])

export interface SamlIdentity {
  externalId: string
  email: string | null
  name: string | null
}

// ----- Outbound: metadata and AuthnRequest -----

const signingBehaviourSigns = (data: SsoConfigData) => {
  const behaviour = data.spSigningBehavior ?? SpSigningBehavior.IfIdpWantAuthnRequestsSigned
  if (behaviour === SpSigningBehavior.Never) return false
  if (behaviour === SpSigningBehavior.Always) return true
  return data.idpWantAuthnRequestsSigned === true
}

const outboundAlgorithm = (data: SsoConfigData) => {
  const alg = data.spOutboundSigningAlgorithm?.trim() || SIG_RSA_SHA256
  if (!HASH_OF_SIG[alg]) throw new SsoError('The outbound signing algorithm is not supported.')
  return alg
}

/** The SP metadata document for an organisation. */
export function spMetadata(
  env: Bindings,
  orgUuid: string,
  data: SsoConfigData,
  certificateDer: Uint8Array,
): string {
  const urls = ssoUrls(env, orgUuid)
  const format = NAMEID_FORMATS[data.spNameIdFormat ?? 0]
  const cert = b64(certificateDer)
  const keyDescriptor = (use: string) =>
    `<md:KeyDescriptor use="${use}"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<md:EntityDescriptor xmlns:md="${NS.md}" xmlns:ds="${NS.ds}" entityID="${esc(spEntityId(env, orgUuid, data))}">`,
    `<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="${signingBehaviourSigns(data)}" WantAssertionsSigned="${data.spWantAssertionsSigned === true}">`,
    keyDescriptor('signing'),
    keyDescriptor('encryption'),
    format ? `<md:NameIDFormat>${esc(format)}</md:NameIDFormat>` : '',
    `<md:AssertionConsumerService Binding="${BINDING_POST}" Location="${esc(urls.spAcsUrl)}" index="0" isDefault="true"/>`,
    '</md:SPSSODescriptor>',
    '</md:EntityDescriptor>',
  ].join('')
}

export const newRequestId = () => `_${crypto.randomUUID().replace(/-/g, '')}`

function authnRequestXml(env: Bindings, orgUuid: string, data: SsoConfigData, id: string) {
  const urls = ssoUrls(env, orgUuid)
  const format = NAMEID_FORMATS[data.spNameIdFormat ?? 0]
  return [
    `<samlp:AuthnRequest xmlns:samlp="${NS.samlp}" xmlns:saml="${NS.saml}" ID="${id}" Version="2.0"`,
    ` IssueInstant="${new Date().toISOString()}" Destination="${esc(data.idpSingleSignOnServiceUrl ?? '')}"`,
    ` AssertionConsumerServiceURL="${esc(urls.spAcsUrl)}" ProtocolBinding="${BINDING_POST}">`,
    `<saml:Issuer>${esc(spEntityId(env, orgUuid, data))}</saml:Issuer>`,
    format ? `<samlp:NameIDPolicy Format="${esc(format)}" AllowCreate="true"/>` : '',
    '</samlp:AuthnRequest>',
  ].join('')
}

async function deflateRaw(s: string): Promise<Uint8Array> {
  const stream = new Blob([utf8(s)]).stream().pipeThrough(new CompressionStream('deflate-raw'))
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

export type AuthnRequestDispatch =
  | { binding: 'redirect'; url: string }
  | { binding: 'post'; url: string; fields: Record<string, string> }

/** Builds the AuthnRequest in the binding the identity provider expects. */
export async function buildAuthnRequest(
  env: Bindings,
  orgUuid: string,
  data: SsoConfigData,
  sp: SpKeys,
  requestId: string,
  relayState: string,
): Promise<AuthnRequestDispatch> {
  const destination = (data.idpSingleSignOnServiceUrl ?? '').trim()
  let target: URL
  try {
    target = new URL(destination)
  } catch {
    throw new SsoError('The identity provider single sign-on URL is not set or invalid.')
  }
  if (target.protocol !== 'https:') throw new SsoError('The single sign-on URL must use https.')
  const xml = authnRequestXml(env, orgUuid, data, requestId)
  const sign = signingBehaviourSigns(data)

  if ((data.idpBindingType ?? Saml2BindingType.HttpRedirect) === Saml2BindingType.HttpPost) {
    const body = sign ? await signEnveloped(xml, requestId, sp, outboundAlgorithm(data)) : xml
    return {
      binding: 'post',
      url: target.toString(),
      fields: { SAMLRequest: b64(utf8(body)), RelayState: relayState },
    }
  }

  // HTTP-Redirect: deflate, base64, and sign the query string itself (SAML bindings 3.4.4.1).
  let query = `SAMLRequest=${encodeURIComponent(b64(await deflateRaw(xml)))}&RelayState=${encodeURIComponent(relayState)}`
  if (sign) {
    const alg = outboundAlgorithm(data)
    query += `&SigAlg=${encodeURIComponent(alg)}`
    const key = await spSigningKey(sp.privateKeyPkcs8, HASH_OF_SIG[alg] as string)
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, utf8(query))
    query += `&Signature=${encodeURIComponent(b64(new Uint8Array(sig)))}`
  }
  const sep = target.search ? '&' : '?'
  return { binding: 'redirect', url: `${target.toString()}${sep}${query}` }
}

/** Signs a document with an enveloped signature placed after its Issuer element. */
async function signEnveloped(xml: string, id: string, sp: SpKeys, alg: string): Promise<string> {
  const doc = parseXml(xml)
  const hash = HASH_OF_SIG[alg] as string
  const key = await spSigningKey(sp.privateKeyPkcs8, hash)
  const signed = new xmldsig.SignedXml(doc as never)
  signed.XmlSignature.SignedInfo.CanonicalizationMethod.Algorithm =
    'http://www.w3.org/2001/10/xml-exc-c14n#'
  const signature = await signed.Sign(
    { name: 'RSASSA-PKCS1-v1_5', hash } as never,
    key,
    doc as never,
    {
      x509: [b64(sp.certificateDer)],
      references: [{ uri: `#${id}`, hash, transforms: ['enveloped', 'exc-c14n'] }],
    },
  )
  const sigEl = signature.GetXml() as unknown as Element
  const root = doc.documentElement as Element
  const issuer = child(root, NS.saml, 'Issuer')
  root.insertBefore(sigEl as never, (issuer?.nextSibling ?? root.firstChild) as never)
  return serialize(doc)
}

// ----- Inbound: Response validation -----

export interface ExpectedResponse {
  /** ID of the AuthnRequest this flow sent. */
  requestId: string
  now: number
}

const parseTime = (v: string | null, what: string): number | null => {
  if (v === null || v === '') return null
  const t = Date.parse(v)
  if (Number.isNaN(t)) throw new SsoError(`The SAML ${what} time is invalid.`)
  return t
}

/** Identity provider certificates, parsed once per validation. */
function idpCertificates(data: SsoConfigData, now: number): ParsedCertificate[] {
  const certs = certificatesFrom(data.idpX509PublicCert).map(parseCertificate)
  if (certs.length === 0) throw new SsoError('No identity provider certificate is configured.')
  if (data.spValidateCertificates) {
    const valid = certs.filter((c) => c.notBefore.getTime() <= now && now < c.notAfter.getTime())
    if (valid.length === 0) throw new SsoError('The identity provider certificate has expired.')
    return valid
  }
  return certs
}

/**
 * Verifies the enveloped signature `sigEl` over `target` (its parent). Guards against signature
 * wrapping: one reference, pointing at `target` by its unique ID, with only canonicalisation and
 * enveloped transforms, and an algorithm at or above the configured minimum.
 */
async function verifySignature(
  doc: Document,
  target: Element,
  sigEl: Element,
  certs: ParsedCertificate[],
  data: SsoConfigData,
): Promise<void> {
  if (sigEl.parentNode !== target) throw new SsoError('The SAML signature is misplaced.')
  const id = target.getAttribute('ID') ?? ''
  if (!id || countIds(doc, id) !== 1)
    throw new SsoError('The signed SAML element has no unique ID.')

  const signedInfo = child(sigEl, NS.ds, 'SignedInfo')
  if (!signedInfo) throw new SsoError('The SAML signature has no SignedInfo.')
  const method = child(signedInfo, NS.ds, 'SignatureMethod')?.getAttribute('Algorithm') ?? ''
  const hash = HASH_OF_SIG[method]
  if (!hash) throw new SsoError('The SAML signature algorithm is not supported.')
  const minimum = SIGNING_ALGORITHMS.indexOf(
    data.spMinIncomingSigningAlgorithm?.trim() || SIG_RSA_SHA256,
  )
  const floor = minimum < 0 ? 1 : minimum
  if (SIGNING_ALGORITHMS.indexOf(method) < floor) {
    throw new SsoError('The SAML signature algorithm is weaker than the configured minimum.')
  }
  const refs = children(signedInfo, NS.ds, 'Reference')
  if (refs.length !== 1) throw new SsoError('The SAML signature must have exactly one reference.')
  const ref = refs[0] as Element
  if (ref.getAttribute('URI') !== `#${id}`) {
    throw new SsoError('The SAML signature does not cover the expected element.')
  }
  const digest = child(ref, NS.ds, 'DigestMethod')?.getAttribute('Algorithm') ?? ''
  if (DIGESTS[digest] === undefined || (DIGESTS[digest] as number) < floor) {
    throw new SsoError('The SAML digest algorithm is not accepted.')
  }
  const transforms = child(ref, NS.ds, 'Transforms')
  for (const t of transforms ? children(transforms, NS.ds, 'Transform') : []) {
    if (!TRANSFORMS.has(t.getAttribute('Algorithm') ?? '')) {
      throw new SsoError('The SAML signature uses a transform that is not accepted.')
    }
  }

  for (const cert of certs) {
    const key = await rsaVerifyKey(cert, hash)
    const signed = new xmldsig.SignedXml(doc as never)
    signed.LoadXml(sigEl as never)
    try {
      if (await signed.Verify({ key, content: doc.documentElement as never })) return
    } catch {
      // A digest mismatch throws; try the next certificate, then fail below.
    }
  }
  throw new SsoError('The SAML signature is invalid.')
}

/** Decrypts an EncryptedAssertion into its own document (xmlenc, RSA-OAEP key transport). */
/**
 * Decrypts an EncryptedAssertion. Every failure (key transport, cipher, padding, XML) surfaces as
 * the same error, so the response gives no decryption or padding oracle.
 */
async function decryptAssertion(encrypted: Element, sp: SpKeys): Promise<Document> {
  try {
    return await decryptAssertionInner(encrypted, sp)
  } catch (err) {
    throw new SsoError('The encrypted assertion could not be decrypted.', err)
  }
}

/** The data encryption algorithm of an EncryptedAssertion, read before any decryption. */
function encryptionMethod(encrypted: Element): string {
  const data = descendants(encrypted, NS.xenc, 'EncryptedData')[0]
  return (data ? child(data, NS.xenc, 'EncryptionMethod')?.getAttribute('Algorithm') : '') ?? ''
}

async function decryptAssertionInner(encrypted: Element, sp: SpKeys): Promise<Document> {
  const data = descendants(encrypted, NS.xenc, 'EncryptedData')
  if (data.length !== 1) throw new SsoError('The encrypted assertion is malformed.')
  const encData = data[0] as Element
  const keys = descendants(encrypted, NS.xenc, 'EncryptedKey')
  if (keys.length !== 1) throw new SsoError('The encrypted assertion must carry one key.')
  const encKey = keys[0] as Element

  const keyMethodEl = child(encKey, NS.xenc, 'EncryptionMethod')
  const keyMethod = keyMethodEl?.getAttribute('Algorithm') ?? ''
  let oaepHash = 'SHA-1'
  if (keyMethod === 'http://www.w3.org/2009/xmlenc11#rsa-oaep') {
    const digestAlg =
      (keyMethodEl ? child(keyMethodEl, NS.ds, 'DigestMethod')?.getAttribute('Algorithm') : '') ??
      ''
    const mgf =
      (keyMethodEl ? child(keyMethodEl, NS.xenc11, 'MGF')?.getAttribute('Algorithm') : '') ?? ''
    oaepHash =
      {
        'http://www.w3.org/2001/04/xmlenc#sha256': 'SHA-256',
        'http://www.w3.org/2000/09/xmldsig#sha1': 'SHA-1',
        '': 'SHA-1',
      }[digestAlg] ?? ''
    const mgfHash =
      {
        'http://www.w3.org/2009/xmlenc11#mgf1sha256': 'SHA-256',
        'http://www.w3.org/2009/xmlenc11#mgf1sha1': 'SHA-1',
        '': 'SHA-1',
      }[mgf] ?? ''
    // WebCrypto ties the MGF1 hash to the OAEP digest.
    if (!oaepHash || oaepHash !== mgfHash)
      throw new SsoError('The key transport parameters are not supported.')
  } else if (keyMethod !== 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p') {
    throw new SsoError('The key transport algorithm is not supported (RSA-OAEP is required).')
  }
  const cipherKey = fromB64u(
    text(descendants(encKey, NS.xenc, 'CipherValue')[0]).replace(/\s+/g, ''),
  )
  if (!cipherKey) throw new SsoError('The encrypted key is malformed.')
  let rawKey: ArrayBuffer
  try {
    rawKey = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      await spDecryptionKey(sp.privateKeyPkcs8, oaepHash),
      cipherKey,
    )
  } catch (err) {
    throw new SsoError('The encrypted assertion key could not be decrypted.', err)
  }

  const dataMethod = child(encData, NS.xenc, 'EncryptionMethod')?.getAttribute('Algorithm') ?? ''
  const cipher = fromB64u(
    text(child(child(encData, NS.xenc, 'CipherData') as Element, NS.xenc, 'CipherValue')).replace(
      /\s+/g,
      '',
    ),
  )
  if (!cipher) throw new SsoError('The encrypted assertion is malformed.')
  let plain: Uint8Array
  try {
    if (dataMethod.endsWith('#aes128-gcm') || dataMethod.endsWith('#aes256-gcm')) {
      const key = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt'])
      plain = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: cipher.slice(0, 12), tagLength: 128 },
          key,
          cipher.slice(12),
        ),
      )
    } else if (dataMethod.endsWith('#aes128-cbc') || dataMethod.endsWith('#aes256-cbc')) {
      plain = await aesCbcDecryptXmlEnc(rawKey, cipher)
    } else {
      throw new SsoError('The assertion encryption algorithm is not supported.')
    }
  } catch (err) {
    if (err instanceof SsoError) throw err
    throw new SsoError('The encrypted assertion could not be decrypted.', err)
  }
  return parseXml(new TextDecoder().decode(plain))
}

/**
 * AES-CBC with XML Encryption padding (only the last byte, the pad length, is defined), which
 * WebCrypto's PKCS#7 check would reject. One extra block that decrypts to a full PKCS#7 pad is
 * appended, so WebCrypto strips that and returns the original padded plaintext.
 */
async function aesCbcDecryptXmlEnc(rawKey: ArrayBuffer, data: Uint8Array): Promise<Uint8Array> {
  if (data.length < 32 || data.length % 16 !== 0)
    throw new SsoError('The encrypted assertion is malformed.')
  const key = await crypto.subtle.importKey('raw', rawKey, 'AES-CBC', false, ['encrypt', 'decrypt'])
  const iv = data.slice(0, 16)
  const body = data.slice(16)
  const last = body.slice(body.length - 16)
  const extra = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv: last }, key, new Uint8Array(16).fill(16)),
  ).slice(0, 16)
  const joined = new Uint8Array(body.length + 16)
  joined.set(body)
  joined.set(extra, body.length)
  const padded = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, key, joined))
  const pad = padded[padded.length - 1] ?? 0
  if (pad < 1 || pad > 16) throw new SsoError('The encrypted assertion padding is invalid.')
  return padded.slice(0, padded.length - pad)
}

const ATTR_EMAIL = [
  'email',
  'mail',
  'emailaddress',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
  'urn:oid:0.9.2342.19200300.100.1.3',
]
const ATTR_NAME = [
  'name',
  'displayname',
  'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
  'http://schemas.microsoft.com/identity/claims/displayname',
  'urn:oid:2.16.840.1.113730.3.1.241',
  'urn:oid:2.5.4.3',
]

const listSetting = (s: string | null | undefined) =>
  (s ?? '')
    .split(/[,\s]+/)
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean)

function attributes(assertion: Element): Map<string, string> {
  const out = new Map<string, string>()
  for (const statement of children(assertion, NS.saml, 'AttributeStatement')) {
    for (const attr of children(statement, NS.saml, 'Attribute')) {
      const value = text(children(attr, NS.saml, 'AttributeValue')[0])
      if (!value) continue
      for (const key of [attr.getAttribute('Name'), attr.getAttribute('FriendlyName')]) {
        if (key && !out.has(key.toLowerCase())) out.set(key.toLowerCase(), value)
      }
    }
  }
  return out
}

/** Checks the assertion's conditions and subject; returns the identity and replay expiry. */
function checkAssertion(
  env: Bindings,
  orgUuid: string,
  data: SsoConfigData,
  assertion: Element,
  expected: ExpectedResponse,
): { identity: SamlIdentity; id: string; expiresAt: number } {
  const now = expected.now
  if (assertion.getAttribute('Version') !== '2.0')
    throw new SsoError('The SAML assertion version is not 2.0.')
  const id = assertion.getAttribute('ID') ?? ''
  if (!id) throw new SsoError('The SAML assertion has no ID.')
  const issuer = text(child(assertion, NS.saml, 'Issuer'))
  if (!safeEqualStrings(issuer, (data.idpEntityId ?? '').trim())) {
    throw new SsoError('The SAML assertion issuer does not match the identity provider.')
  }

  const conditions = child(assertion, NS.saml, 'Conditions')
  if (!conditions) throw new SsoError('The SAML assertion has no conditions.')
  const notBefore = parseTime(conditions.getAttribute('NotBefore'), 'NotBefore')
  const notOnOrAfter = parseTime(conditions.getAttribute('NotOnOrAfter'), 'NotOnOrAfter')
  if (notBefore !== null && now + CLOCK_SKEW_MS < notBefore)
    throw new SsoError('The SAML assertion is not yet valid.')
  if (notOnOrAfter !== null && now - CLOCK_SKEW_MS >= notOnOrAfter)
    throw new SsoError('The SAML assertion has expired.')
  const audienceRestrictions = children(conditions, NS.saml, 'AudienceRestriction')
  if (audienceRestrictions.length === 0)
    throw new SsoError('The SAML assertion has no audience restriction.')
  const entity = spEntityId(env, orgUuid, data)
  for (const restriction of audienceRestrictions) {
    const audiences = children(restriction, NS.saml, 'Audience').map((a) => text(a))
    if (!audiences.includes(entity))
      throw new SsoError('The SAML assertion is meant for a different audience.')
  }

  const subject = child(assertion, NS.saml, 'Subject')
  if (!subject) throw new SsoError('The SAML assertion has no subject.')
  const acs = ssoUrls(env, orgUuid).spAcsUrl
  let subjectExpiry: number | null = null
  const bearer = children(subject, NS.saml, 'SubjectConfirmation').filter(
    (sc) => sc.getAttribute('Method') === BEARER,
  )
  const confirmed = bearer.some((sc) => {
    const scd = child(sc, NS.saml, 'SubjectConfirmationData')
    if (!scd) return false
    const recipient = scd.getAttribute('Recipient')
    const until = parseTime(scd.getAttribute('NotOnOrAfter'), 'NotOnOrAfter')
    const from = parseTime(scd.getAttribute('NotBefore'), 'NotBefore')
    const inResponseTo = scd.getAttribute('InResponseTo')
    if (recipient !== acs) return false
    if (until === null || now - CLOCK_SKEW_MS >= until) return false
    if (from !== null && now + CLOCK_SKEW_MS < from) return false
    if (inResponseTo) {
      if (inResponseTo !== expected.requestId) return false
    } else if (!data.idpAllowUnsolicitedAuthnResponse) {
      return false
    }
    subjectExpiry = until
    return true
  })
  if (!confirmed) throw new SsoError('The SAML subject confirmation is missing or invalid.')

  const nameIdEl = child(subject, NS.saml, 'NameID')
  if (child(subject, NS.saml, 'EncryptedID'))
    throw new SsoError('Encrypted name identifiers are not supported.')
  const nameId = text(nameIdEl)
  const format = nameIdEl?.getAttribute('Format') ?? ''
  const attrs = attributes(assertion)
  const pick = (names: string[]) => {
    for (const n of names) {
      const v = attrs.get(n.toLowerCase())
      if (v) return v
    }
    return null
  }
  let email = pick([...listSetting(data.additionalEmailClaimTypes), ...ATTR_EMAIL])
  if (!email && nameId.includes('@')) email = nameId
  const givenSurname = [
    pick([
      'givenname',
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
      'urn:oid:2.5.4.42',
    ]),
    pick([
      'surname',
      'sn',
      'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
      'urn:oid:2.5.4.4',
    ]),
  ]
    .filter(Boolean)
    .join(' ')
  const name =
    pick([...listSetting(data.additionalNameClaimTypes), ...ATTR_NAME]) ?? (givenSurname || null)
  let externalId = pick(listSetting(data.additionalUserIdClaimTypes))
  if (!externalId) externalId = format === TRANSIENT ? email : nameId || null
  if (!externalId) throw new SsoError('The SAML assertion does not identify the user.')

  const expiries = [notOnOrAfter, subjectExpiry].filter((v): v is number => v !== null)
  const expiresAt = Math.min(now + MAX_REPLAY_WINDOW_MS, ...expiries) + CLOCK_SKEW_MS
  return {
    identity: { externalId, email: email?.includes('@') ? email : null, name },
    id,
    expiresAt,
  }
}

export interface ValidatedResponse {
  identity: SamlIdentity
  /** Replay key: issuer and assertion ID. */
  assertionKey: string
  expiresAt: number
}

/**
 * Validates a base64 `SAMLResponse` from the HTTP-POST binding. Throws `SsoError` on any failure.
 * The caller must record `assertionKey` until `expiresAt` and refuse a repeat.
 */
export async function validateSamlResponse(
  env: Bindings,
  orgUuid: string,
  data: SsoConfigData,
  sp: SpKeys,
  samlResponse: string,
  expected: ExpectedResponse,
): Promise<ValidatedResponse> {
  const bytes = fromB64u(samlResponse.replace(/\s+/g, ''))
  if (!bytes) throw new SsoError('The SAML response is not valid base64.')
  const doc = parseXml(new TextDecoder().decode(bytes))
  const response = doc.documentElement as Element
  if (response.namespaceURI !== NS.samlp || response.localName !== 'Response') {
    throw new SsoError('The SAML message is not a Response.')
  }
  if (response.getAttribute('Version') !== '2.0')
    throw new SsoError('The SAML response version is not 2.0.')
  const acs = ssoUrls(env, orgUuid).spAcsUrl
  const destination = response.getAttribute('Destination')
  if (destination !== null && destination !== acs)
    throw new SsoError('The SAML response destination is wrong.')
  // A signed response must name its destination, so it cannot be replayed to another endpoint.
  if (destination === null && child(response, NS.ds, 'Signature')) {
    throw new SsoError('The signed SAML response has no destination.')
  }
  const inResponseTo = response.getAttribute('InResponseTo')
  if (inResponseTo) {
    if (inResponseTo !== expected.requestId)
      throw new SsoError('The SAML response answers a different request.')
  } else if (!data.idpAllowUnsolicitedAuthnResponse) {
    throw new SsoError('Unsolicited SAML responses are not allowed.')
  }
  const responseIssuer = child(response, NS.saml, 'Issuer')
  if (responseIssuer && !safeEqualStrings(text(responseIssuer), (data.idpEntityId ?? '').trim())) {
    throw new SsoError('The SAML response issuer does not match the identity provider.')
  }
  const status = child(response, NS.samlp, 'Status')
  const code = status ? child(status, NS.samlp, 'StatusCode')?.getAttribute('Value') : null
  if (code !== STATUS_SUCCESS)
    throw new SsoError('The identity provider did not authenticate the user.')

  const certs = idpCertificates(data, expected.now)
  // Exactly one assertion in the whole message, plain or encrypted, as a direct child.
  const plain = descendants(doc, NS.saml, 'Assertion')
  const encrypted = descendants(doc, NS.saml, 'EncryptedAssertion')
  if (plain.length + encrypted.length !== 1)
    throw new SsoError('The SAML response must contain exactly one assertion.')
  const responseSig = child(response, NS.ds, 'Signature')
  if (responseSig) await verifySignature(doc, response, responseSig, certs, data)

  let assertionDoc = doc
  let assertion: Element
  if (encrypted.length === 1) {
    if ((encrypted[0] as Element).parentNode !== response)
      throw new SsoError('The encrypted assertion is misplaced.')
    // AES-CBC is malleable: only decrypt it when the response signature, which covers the
    // ciphertext, has already been verified.
    const method = encryptionMethod(encrypted[0] as Element)
    if (/#aes(128|192|256)-cbc$/.test(method) && !responseSig) {
      throw new SsoError('AES-CBC encrypted assertions are accepted only in a signed response.')
    }
    assertionDoc = await decryptAssertion(encrypted[0] as Element, sp)
    assertion = assertionDoc.documentElement as Element
    if (assertion.namespaceURI !== NS.saml || assertion.localName !== 'Assertion') {
      throw new SsoError('The encrypted assertion does not hold an assertion.')
    }
    if (descendants(assertionDoc, NS.saml, 'Assertion').length !== 1) {
      throw new SsoError('The encrypted assertion must contain exactly one assertion.')
    }
  } else {
    assertion = plain[0] as Element
    if (assertion.parentNode !== response) throw new SsoError('The SAML assertion is misplaced.')
  }
  const assertionSig = child(assertion, NS.ds, 'Signature')
  if (assertionSig) await verifySignature(assertionDoc, assertion, assertionSig, certs, data)
  if (!assertionSig && (data.spWantAssertionsSigned || !responseSig)) {
    throw new SsoError('The SAML assertion is not signed.')
  }

  const checked = checkAssertion(env, orgUuid, data, assertion, expected)
  return {
    identity: checked.identity,
    assertionKey: `${(data.idpEntityId ?? '').trim()}|${checked.id}`,
    expiresAt: checked.expiresAt,
  }
}

/** Checks the identity provider settings parse. Used by the admin test button. */
export function testSaml(data: SsoConfigData, now = Date.now()) {
  const problems: string[] = []
  if (!data.idpEntityId?.trim()) problems.push('Identity provider entity ID is not set.')
  try {
    const url = new URL(data.idpSingleSignOnServiceUrl ?? '')
    if (url.protocol !== 'https:') problems.push('Single sign-on URL must use https.')
  } catch {
    problems.push('Single sign-on URL is not set or invalid.')
  }
  try {
    const certs = certificatesFrom(data.idpX509PublicCert).map(parseCertificate)
    if (certs.length === 0) problems.push('No identity provider certificate is configured.')
    for (const c of certs) {
      if (c.notAfter.getTime() <= now)
        problems.push(`A certificate expired on ${c.notAfter.toISOString()}.`)
    }
  } catch (err) {
    problems.push(err instanceof SsoError ? err.message : 'The certificate could not be read.')
  }
  if (data.spOutboundSigningAlgorithm && !HASH_OF_SIG[data.spOutboundSigningAlgorithm]) {
    problems.push('Outbound signing algorithm is not supported.')
  }
  return {
    problems,
    redirectBinding: (data.idpBindingType ?? 1) === 1 ? BINDING_REDIRECT : BINDING_POST,
  }
}
