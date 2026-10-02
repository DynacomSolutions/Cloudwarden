import { and, eq, isNull } from 'drizzle-orm'
import { fromB64u } from '../auth/crypto'
import type { Db } from '../db'
import { schema } from '../db'
import type { Bindings } from '../env'
import { seal, unseal } from '../orgs/sealed'
import { loadSsoConfig, type SsoConfigRow } from './config'
import { SsoError } from './errors'
import { b64, generateSpKeys, type SpKeys } from './pki'

/** Event codes for SSO and claimed domains, as the official clients name them. */
export const SsoEventType = {
  UserMigratedKeyToKeyConnector: 1009,
  OrganizationUserUnlinkedSso: 1505,
  OrganizationUserFirstSsoLogin: 1510,
  OrganizationEnabledSso: 1604,
  OrganizationDisabledSso: 1605,
  OrganizationEnabledKeyConnector: 1606,
  OrganizationDisabledKeyConnector: 1607,
  OrganizationDomainAdded: 2000,
  OrganizationDomainRemoved: 2001,
  OrganizationDomainVerified: 2002,
  OrganizationDomainNotVerified: 2003,
} as const

/**
 * The organisation's SAML service provider key and certificate, created on first use. A
 * concurrent creation loses the conditional update and reads the winner's key.
 */
export async function ensureSpKeys(env: Bindings, db: Db, row: SsoConfigRow): Promise<SpKeys> {
  if (row.spPrivateKey && row.spCertificate) return decode(env, row)
  const created = await generateSpKeys(`Cloudwarden SSO ${row.organizationUuid}`)
  await db
    .update(schema.ssoConfigs)
    .set({
      // The private key is encrypted at rest.
      spPrivateKey: await seal(env, keyPurpose(row.organizationUuid), b64(created.privateKeyPkcs8)),
      spCertificate: b64(created.certificateDer),
    })
    .where(
      and(
        eq(schema.ssoConfigs.organizationUuid, row.organizationUuid),
        isNull(schema.ssoConfigs.spPrivateKey),
      ),
    )
  const fresh = await loadSsoConfig(db, row.organizationUuid)
  if (!fresh) throw new SsoError('SSO is not configured.')
  return decode(env, fresh)
}

const keyPurpose = (orgUuid: string) => `sso-sp-key:${orgUuid}`

async function decode(env: Bindings, row: SsoConfigRow): Promise<SpKeys> {
  const stored = row.spPrivateKey ?? ''
  const plain = stored.startsWith('v1.')
    ? await unseal(env, keyPurpose(row.organizationUuid), stored).catch(() => '')
    : stored
  const privateKeyPkcs8 = fromB64u(plain)
  const certificateDer = fromB64u(row.spCertificate ?? '')
  if (!privateKeyPkcs8 || !certificateDer) throw new SsoError('The SAML signing key is damaged.')
  return { privateKeyPkcs8, certificateDer }
}
