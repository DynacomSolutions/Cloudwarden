import type { Bindings } from '../env'
import { ApiError } from '../errors'
import { log } from '../log'
import { seal, unsealWithInfo } from '../orgs/sealed'

/** Per-user secrets kept encrypted in D1 (TASKS #405): the personal API key and the recovery code. */
export type UserSecretKind = 'api-key' | 'recovery-code'

const COLUMN: Record<UserSecretKind, string> = {
  'api-key': 'api_key',
  'recovery-code': 'totp_recover',
}
const purpose = (uuid: string, kind: UserSecretKind) => `user-secret:${kind}:${uuid}`
/** Sealed values start with `v1.`; the plain values they replaced never contain a dot. */
const isSealed = (stored: string) => stored.startsWith('v1.')

export const sealUserSecret = (env: Bindings, uuid: string, kind: UserSecretKind, plain: string) =>
  seal(env, purpose(uuid, kind), plain)

/**
 * Plain value of a stored secret. `legacy` marks a row not yet encrypted and `stale` one sealed under
 * a previous `JWT_SECRET`; both should be sealed again. Never returns null: a value that cannot be
 * opened (key rotated or misconfigured) is logged without any value and fails with 500, so a stored
 * secret is never replaced just because it could not be read.
 */
export async function openUserSecret(
  env: Bindings,
  uuid: string,
  kind: UserSecretKind,
  stored: string,
): Promise<{ value: string; legacy: boolean; stale: boolean }> {
  if (!isSealed(stored)) return { value: stored, legacy: true, stale: false }
  try {
    const opened = await unsealWithInfo(env, purpose(uuid, kind), stored)
    return { ...opened, legacy: false }
  } catch {
    log('error', 'user_secret.unseal_failed', { kind })
    throw new ApiError(500, 'Stored secret cannot be read; check the encryption key configuration.')
  }
}

/** Seals again under the current key; guarded on the stored value so a concurrent write wins. */
export async function resealIfNeeded(
  env: Bindings,
  uuid: string,
  kind: UserSecretKind,
  stored: string,
  opened: { value: string; legacy: boolean; stale: boolean },
) {
  if (!opened.legacy && !opened.stale) return
  const col = COLUMN[kind]
  await env.DB.prepare(`UPDATE users SET ${col} = ?1 WHERE uuid = ?2 AND ${col} = ?3`)
    .bind(await sealUserSecret(env, uuid, kind, opened.value), uuid, stored)
    .run()
}

/**
 * Value to show for a secret. An existing one is returned unchanged (and sealed again if needed).
 * Only a NULL column gets a generated value, written with `IS NULL` so concurrent first views agree
 * on the stored one, which is read back.
 */
export async function viewUserSecret(
  env: Bindings,
  uuid: string,
  kind: UserSecretKind,
  stored: string | null,
  generate: () => string,
): Promise<string> {
  let current = stored
  if (!current) {
    const col = COLUMN[kind]
    await env.DB.prepare(
      `UPDATE users SET ${col} = ?1, updated_at = ?2 WHERE uuid = ?3 AND ${col} IS NULL`,
    )
      .bind(await sealUserSecret(env, uuid, kind, generate()), Date.now(), uuid)
      .run()
    current = (
      await env.DB.prepare(`SELECT ${col} AS v FROM users WHERE uuid = ?1`)
        .bind(uuid)
        .first<{ v: string | null }>()
    )?.v as string | null
    if (!current) throw new ApiError(500, 'Stored secret is missing.')
  }
  const opened = await openUserSecret(env, uuid, kind, current)
  await resealIfNeeded(env, uuid, kind, current, opened)
  return opened.value
}

/** Encrypts every remaining plain value. D1 cannot do this in SQL, so reads and the backup export do. */
export async function sealLegacyUserSecrets(env: Bindings): Promise<void> {
  const { results } = await env.DB.prepare(
    "SELECT uuid, api_key, totp_recover FROM users WHERE (api_key IS NOT NULL AND api_key NOT LIKE 'v1.%') OR (totp_recover IS NOT NULL AND totp_recover NOT LIKE 'v1.%')",
  ).all<{ uuid: string; api_key: string | null; totp_recover: string | null }>()
  for (const r of results) {
    for (const [kind, stored] of [
      ['api-key', r.api_key],
      ['recovery-code', r.totp_recover],
    ] as const) {
      if (stored && !isSealed(stored))
        await resealIfNeeded(env, r.uuid, kind, stored, {
          value: stored,
          legacy: true,
          stale: false,
        })
    }
  }
}
