// One policy write path for the Admin Console and the Public API (TASKS #271), so both validate
// and enforce a policy the same way.
import { and, eq } from 'drizzle-orm'
import type { Context } from 'hono'
import { z } from 'zod'
import { type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { bumpOrgRevision } from './access'
import { EventType, PolicyType } from './constants'
import { eventStatement } from './events'
import { type PolicyRow, revokeNonCompliantMembers } from './policies'
import { batch } from './util'

export async function findPolicy(db: Db, orgUuid: string, type: number) {
  const [row] = await db
    .select()
    .from(schema.policies)
    .where(and(eq(schema.policies.organizationUuid, orgUuid), eq(schema.policies.atype, type)))
    .limit(1)
  return row
}

/**
 * Upstream rules between the account recovery and single organisation policies: recovery needs
 * single organisation (otherwise an administrator could take over an account that also holds
 * data in other organisations), and single organisation stays on while recovery is.
 */
async function assertRecoveryDependencies(db: Db, orgUuid: string, type: number, enabled: boolean) {
  if (type === PolicyType.ResetPassword && enabled) {
    if (!(await findPolicy(db, orgUuid, PolicyType.SingleOrg))?.enabled) {
      throw new ApiError(
        400,
        'Turn on the single organization policy before turning on account recovery.',
      )
    }
  }
  if (type === PolicyType.SingleOrg && !enabled) {
    if ((await findPolicy(db, orgUuid, PolicyType.ResetPassword))?.enabled) {
      throw new ApiError(400, 'Turn off the account recovery policy first.')
    }
  }
}

/** Stores a policy, applies its side effects and records the event. Returns the saved row. */
export async function savePolicy(
  c: Context<Env>,
  db: Db,
  orgUuid: string,
  type: number,
  body: { enabled: boolean; data?: Record<string, unknown> | null },
  systemUser: number | null = null,
): Promise<PolicyRow> {
  await assertRecoveryDependencies(db, orgUuid, type, body.enabled)
  const existing = await findPolicy(db, orgUuid, type)
  const uuid = existing?.uuid ?? crypto.randomUUID()
  const now = Date.now()
  const data = body.data ? JSON.stringify(body.data) : null
  await batch(db, [
    db
      .insert(schema.policies)
      .values({
        uuid,
        organizationUuid: orgUuid,
        atype: type,
        enabled: body.enabled,
        data,
        updatedAt: now,
      })
      .onConflictDoUpdate({
        target: [schema.policies.organizationUuid, schema.policies.atype],
        set: { enabled: body.enabled, data, updatedAt: now },
      }),
    // Members who cannot meet a newly required two-step login are revoked, owners excepted.
    ...(type === PolicyType.TwoFactorAuthentication && body.enabled
      ? [revokeNonCompliantMembers(db, orgUuid, now)]
      : []),
    eventStatement(db, c, {
      type: EventType.PolicyUpdated,
      organizationUuid: orgUuid,
      policyUuid: uuid,
      systemUser,
    }),
    bumpOrgRevision(db, orgUuid, now),
  ])
  const row = await findPolicy(db, orgUuid, type)
  if (!row) throw new ApiError(500, 'Policy was not saved.')
  return row
}

const optionalBool = z.boolean().nullish()
const optionalInt = z.number().int().min(0).nullish()

/** Shape of the `data` of the policy types that Cloudwarden reads. Other keys pass through. */
const DATA_SHAPES: Record<number, z.ZodType> = {
  [PolicyType.MasterPassword]: z.looseObject({
    minComplexity: z.number().int().min(0).max(4).nullish(),
    minLength: z.number().int().min(0).max(128).nullish(),
    requireUpper: optionalBool,
    requireLower: optionalBool,
    requireNumbers: optionalBool,
    requireSpecial: optionalBool,
    enforceOnLogin: optionalBool,
  }),
  [PolicyType.PasswordGenerator]: z.looseObject({
    minLength: optionalInt,
    minNumbers: optionalInt,
    minSpecial: optionalInt,
    useUpper: optionalBool,
    useLower: optionalBool,
    useNumbers: optionalBool,
    useSpecial: optionalBool,
  }),
  [PolicyType.SendOptions]: z.looseObject({ disableHideEmail: optionalBool }),
  [PolicyType.ResetPassword]: z.looseObject({ autoEnrollEnabled: optionalBool }),
  [PolicyType.MaximumVaultTimeout]: z.looseObject({
    minutes: optionalInt,
    action: z.string().nullish(),
  }),
}

/** Throws 400 when `data` has the wrong shape for the policy type (Public API). */
export function assertPolicyData(type: number, data: Record<string, unknown> | null | undefined) {
  const shape = DATA_SHAPES[type]
  if (!shape || !data) return
  const parsed = shape.safeParse(data)
  if (parsed.success) return
  const errors: Record<string, string[]> = {}
  for (const issue of parsed.error.issues) {
    const key = `data.${issue.path.join('.') || 'data'}`
    errors[key] = [...(errors[key] ?? []), issue.message]
  }
  throw new ApiError(400, 'The request is invalid.', errors)
}
