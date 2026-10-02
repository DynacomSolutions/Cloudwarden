import { eq, sql } from 'drizzle-orm'
import { z } from 'zod'
import type { Db } from '../db'
import { schema } from '../db'
import type { Bindings } from '../env'

/** `SsoType` on the wire. */
export const SsoType = { None: 0, OpenIdConnect: 1, Saml2: 2 } as const

/** `MemberDecryptionType` on the wire. */
export const MemberDecryptionType = {
  MasterPassword: 0,
  KeyConnector: 1,
  TrustedDeviceEncryption: 2,
} as const

/** `OpenIdConnectRedirectBehavior`: 0 redirect (GET), 1 form post. */
export const OidcRedirectBehavior = { RedirectGet: 0, FormPost: 1 } as const

/** `Saml2BindingType`: 1 HTTP-Redirect, 2 HTTP-POST. */
export const Saml2BindingType = { HttpRedirect: 1, HttpPost: 2 } as const

/** `Saml2SigningBehavior`: 0 if the IdP wants signed requests, 1 always, 3 never. */
export const SpSigningBehavior = { IfIdpWantAuthnRequestsSigned: 0, Always: 1, Never: 3 } as const

export const SIG_RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
export const SIG_RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
export const SIG_RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
export const SIG_RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
/** Ordered weakest first; `spMinIncomingSigningAlgorithm` is a floor in this order. */
export const SIGNING_ALGORITHMS = [SIG_RSA_SHA1, SIG_RSA_SHA256, SIG_RSA_SHA384, SIG_RSA_SHA512]

export const NAMEID_UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
/** `Saml2NameIdFormat` values (0 not configured, then the standard formats). */
export const NAMEID_FORMATS: Record<number, string | null> = {
  0: null,
  1: NAMEID_UNSPECIFIED,
  2: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  3: 'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
  4: 'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
  5: 'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
  6: 'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
  7: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  8: 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
}

const optText = z.string().max(4000).nullish()
const optBool = z.boolean().nullish()
const optInt = z.number().int().nullish()

/** `SsoConfigApi`, as the client sends it (camelCase). Unknown keys are dropped. */
export const ssoConfigSchema = z.object({
  configType: z.number().int().min(0).max(2).nullish(),
  memberDecryptionType: z.number().int().min(0).max(2).nullish(),
  keyConnectorUrl: optText,
  // OpenID Connect
  authority: optText,
  clientId: optText,
  clientSecret: optText,
  metadataAddress: optText,
  redirectBehavior: optInt,
  getClaimsFromUserInfoEndpoint: optBool,
  additionalScopes: optText,
  additionalUserIdClaimTypes: optText,
  additionalEmailClaimTypes: optText,
  additionalNameClaimTypes: optText,
  acrValues: optText,
  expectedReturnAcrValue: optText,
  // SAML 2.0 service provider
  spUniqueEntityId: optBool,
  spNameIdFormat: optInt,
  spOutboundSigningAlgorithm: optText,
  spSigningBehavior: optInt,
  spMinIncomingSigningAlgorithm: optText,
  spWantAssertionsSigned: optBool,
  spValidateCertificates: optBool,
  // SAML 2.0 identity provider
  idpEntityId: optText,
  idpBindingType: optInt,
  idpSingleSignOnServiceUrl: optText,
  idpSingleLogoutServiceUrl: optText,
  idpX509PublicCert: z.string().max(20000).nullish(),
  idpOutboundSigningAlgorithm: optText,
  idpAllowUnsolicitedAuthnResponse: optBool,
  idpDisableOutboundLogoutRequests: optBool,
  idpWantAuthnRequestsSigned: optBool,
})
export type SsoConfigData = z.infer<typeof ssoConfigSchema>

export type SsoConfigRow = typeof schema.ssoConfigs.$inferSelect

export const parseConfigData = (row: SsoConfigRow): SsoConfigData => {
  try {
    const parsed = ssoConfigSchema.safeParse(JSON.parse(row.data))
    return parsed.success ? parsed.data : {}
  } catch {
    return {}
  }
}

export const baseUrl = (env: Bindings) => env.DOMAIN.replace(/\/+$/, '')

/** The service provider URLs shown to administrators and used in the protocol. */
export function ssoUrls(env: Bindings, orgUuid: string) {
  const base = `${baseUrl(env)}/sso`
  return {
    callbackPath: `${base}/oidc-signin`,
    signedOutCallbackPath: `${base}/oidc-signedout`,
    spEntityId: `${base}/saml2/${orgUuid}`,
    spEntityIdStatic: `${base}/saml2`,
    spMetadataUrl: `${base}/saml2/${orgUuid}`,
    spAcsUrl: `${base}/saml2/${orgUuid}/Acs`,
  }
}

/** The SP entity ID this organisation's configuration uses. */
export const spEntityId = (env: Bindings, orgUuid: string, data: SsoConfigData) => {
  const urls = ssoUrls(env, orgUuid)
  return data.spUniqueEntityId === false ? urls.spEntityIdStatic : urls.spEntityId
}

export async function loadSsoConfig(db: Db, orgUuid: string): Promise<SsoConfigRow | undefined> {
  const [row] = await db
    .select()
    .from(schema.ssoConfigs)
    .where(eq(schema.ssoConfigs.organizationUuid, orgUuid))
    .limit(1)
  return row
}

/** The organisation whose SSO identifier matches, ignoring case. */
export async function orgByIdentifier(db: Db, identifier: string) {
  const trimmed = identifier.trim()
  if (!trimmed) return undefined
  const [org] = await db
    .select()
    .from(schema.organizations)
    .where(sql`lower(${schema.organizations.identifier}) = ${trimmed.toLowerCase()}`)
    .limit(1)
  return org
}

/** Enabled SSO configuration of an organisation, with parsed data, or null. */
export async function activeSso(db: Db, orgUuid: string) {
  const row = await loadSsoConfig(db, orgUuid)
  if (!row?.enabled) return null
  return { row, data: parseConfigData(row) }
}

/** Splits a comma or space separated list setting into its non-empty entries. */
export const listSetting = (s: string | null | undefined): string[] =>
  (s ?? '')
    .split(/[,\s]+/)
    .map((v) => v.trim())
    .filter(Boolean)
