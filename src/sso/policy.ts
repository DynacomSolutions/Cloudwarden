import { and, eq } from 'drizzle-orm'
import { type Db, schema } from '../db'
import { ApiError } from '../errors'
import { requireOrg } from '../orgs/access'
import { PolicyType } from '../orgs/constants'
import { enforcedPolicies } from '../orgs/policies'
import { activeSso } from './config'

/**
 * "Require single sign-on" (policy type 4, TASKS #283). Owners and admins are exempt, as for the
 * other restrictive policies. Returns the SSO identifier of the first organisation that requires
 * SSO of this user and has it configured, or null. A policy without a working SSO configuration
 * does not lock members out.
 */
export async function requiredSsoIdentifier(db: Db, userUuid: string): Promise<string | null> {
  for (const p of await enforcedPolicies(db, userUuid, PolicyType.RequireSso)) {
    const org = await requireOrg(db, p.organizationUuid).catch(() => null)
    if (org?.identifier && (await activeSso(db, org.uuid))) return org.identifier
  }
  return null
}

/**
 * Policies the SSO decryption options depend on cannot be relaxed while those options are on:
 * key connector and trusted devices need single organisation and require SSO; trusted devices
 * also need account recovery with automatic enrolment. Require SSO needs single organisation.
 */
export async function assertSsoPolicyDependencies(
  db: Db,
  orgUuid: string,
  type: number,
  enabled: boolean,
  data: Record<string, unknown> | null,
) {
  const sso = await activeSso(db, orgUuid)
  const decryption = sso?.data.memberDecryptionType ?? 0
  const kcOrTde = decryption === 1 || decryption === 2
  if (!enabled && kcOrTde && (type === PolicyType.SingleOrg || type === PolicyType.RequireSso)) {
    throw new ApiError(
      400,
      'This policy is required while Key Connector or trusted devices are turned on.',
    )
  }
  if (
    decryption === 2 &&
    type === PolicyType.ResetPassword &&
    (!enabled || data?.autoEnrollEnabled !== true)
  ) {
    throw new ApiError(
      400,
      'Account recovery with automatic enrollment is required while trusted devices are turned on.',
    )
  }
  if (enabled && type === PolicyType.RequireSso) {
    const [single] = await db
      .select({ enabled: schema.policies.enabled })
      .from(schema.policies)
      .where(
        and(
          eq(schema.policies.organizationUuid, orgUuid),
          eq(schema.policies.atype, PolicyType.SingleOrg),
        ),
      )
      .limit(1)
    if (!single?.enabled) throw new ApiError(400, 'Turn on the single organization policy first.')
  }
  if (!enabled && type === PolicyType.SingleOrg) {
    const [requireSso] = await db
      .select({ enabled: schema.policies.enabled })
      .from(schema.policies)
      .where(
        and(
          eq(schema.policies.organizationUuid, orgUuid),
          eq(schema.policies.atype, PolicyType.RequireSso),
        ),
      )
      .limit(1)
    if (requireSso?.enabled)
      throw new ApiError(400, 'Turn off the require single sign-on policy first.')
  }
}
