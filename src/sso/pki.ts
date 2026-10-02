import * as asn1js from 'asn1js'
import * as pkijs from 'pkijs'
import { fromB64u } from '../auth/crypto'
import { SsoError } from './errors'

/** X.509 handling for SAML: identity provider certificates and the service provider key pair. */

const engine = () => {
  pkijs.setEngine('workers', new pkijs.CryptoEngine({ name: 'workers', crypto }) as never)
  return pkijs.getCrypto(true)
}

export interface ParsedCertificate {
  der: Uint8Array
  spki: Uint8Array
  notBefore: Date
  notAfter: Date
}

const toB64 = (bytes: Uint8Array) => {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}
export const b64 = toB64

/** Splits a setting holding one or more PEM blocks (or bare base64 DER) into DER certificates. */
export function certificatesFrom(setting: string | null | undefined): Uint8Array[] {
  const raw = (setting ?? '').trim()
  if (!raw) return []
  const blocks = raw.includes('-----BEGIN')
    ? [...raw.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)].map(
        (m) => m[1] ?? '',
      )
    : [raw]
  return blocks.map((b) => {
    const der = fromB64u(b.replace(/\s+/g, ''))
    if (!der || der.length < 64) throw new SsoError('The identity provider certificate is invalid.')
    return der
  })
}

export function parseCertificate(der: Uint8Array): ParsedCertificate {
  try {
    const cert = pkijs.Certificate.fromBER(der)
    return {
      der,
      spki: new Uint8Array(cert.subjectPublicKeyInfo.toSchema().toBER(false)),
      notBefore: cert.notBefore.value,
      notAfter: cert.notAfter.value,
    }
  } catch (err) {
    throw new SsoError('The identity provider certificate could not be read.', err)
  }
}

/** Imports the certificate's RSA public key for RSASSA-PKCS1-v1_5 with `hash`. */
export const rsaVerifyKey = (cert: ParsedCertificate, hash: string) =>
  crypto.subtle.importKey('spki', cert.spki, { name: 'RSASSA-PKCS1-v1_5', hash }, true, ['verify'])

export interface SpKeys {
  privateKeyPkcs8: Uint8Array
  certificateDer: Uint8Array
}

/** Creates the service provider's RSA 2048 key and a self-signed certificate valid ten years. */
export async function generateSpKeys(commonName: string): Promise<SpKeys> {
  const keys = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair
  const cert = new pkijs.Certificate()
  cert.version = 2
  const serial = crypto.getRandomValues(new Uint8Array(16))
  serial[0] = (serial[0] ?? 0) & 0x7f
  cert.serialNumber = new asn1js.Integer({ valueHex: serial })
  const name = () =>
    new pkijs.AttributeTypeAndValue({
      type: '2.5.4.3',
      value: new asn1js.Utf8String({ value: commonName.slice(0, 64) }),
    })
  cert.issuer.typesAndValues.push(name())
  cert.subject.typesAndValues.push(name())
  const now = new Date()
  cert.notBefore.value = new Date(now.getTime() - 60_000)
  cert.notAfter.value = new Date(now.getTime() + 10 * 365 * 24 * 3600 * 1000)
  const e = engine()
  await cert.subjectPublicKeyInfo.importKey(keys.publicKey, e)
  await cert.sign(keys.privateKey, 'SHA-256', e)
  return {
    privateKeyPkcs8: new Uint8Array(
      (await crypto.subtle.exportKey('pkcs8', keys.privateKey)) as ArrayBuffer,
    ),
    certificateDer: new Uint8Array(cert.toSchema(true).toBER(false)),
  }
}

export const spSigningKey = (pkcs8: Uint8Array, hash: string) =>
  crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSASSA-PKCS1-v1_5', hash }, false, ['sign'])

/** The same RSA key, imported for RSA-OAEP key transport (encrypted assertions). */
export const spDecryptionKey = (pkcs8: Uint8Array, hash: string) =>
  crypto.subtle.importKey('pkcs8', pkcs8, { name: 'RSA-OAEP', hash }, false, ['decrypt'])
