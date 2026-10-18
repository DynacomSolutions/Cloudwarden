import type { Bindings } from '../env'
import { seal, unseal } from '../orgs/sealed'

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

/** Plain value of a stored secret. `legacy` marks a row not yet encrypted. Null if it cannot be opened. */
export async function openUserSecret(
  env: Bindings,
  uuid: string,
  kind: UserSecretKind,
  stored: string,
): Promise<{ value: string; legacy: boolean } | null> {
  if (!isSealed(stored)) return { value: stored, legacy: true }
  try {
    return { value: await unseal(env, purpose(uuid, kind), stored), legacy: false }
  } catch {
    return null
  }
}

/** Encrypts one legacy plain value in place; guarded on the old value so a concurrent write wins. */
export async function sealInPlace(
  env: Bindings,
  uuid: string,
  kind: UserSecretKind,
  plain: string,
) {
  const col = COLUMN[kind]
  await env.DB.prepare(`UPDATE users SET ${col} = ?1 WHERE uuid = ?2 AND ${col} = ?3`)
    .bind(await sealUserSecret(env, uuid, kind, plain), uuid, plain)
    .run()
}

/** Encrypts every remaining plain value. D1 cannot do this in SQL, so reads and the backup export do. */
export async function sealLegacyUserSecrets(env: Bindings): Promise<void> {
  const { results } = await env.DB.prepare(
    "SELECT uuid, api_key, totp_recover FROM users WHERE (api_key IS NOT NULL AND api_key NOT LIKE 'v1.%') OR (totp_recover IS NOT NULL AND totp_recover NOT LIKE 'v1.%')",
  ).all<{ uuid: string; api_key: string | null; totp_recover: string | null }>()
  for (const r of results) {
    if (r.api_key && !isSealed(r.api_key)) await sealInPlace(env, r.uuid, 'api-key', r.api_key)
    if (r.totp_recover && !isSealed(r.totp_recover))
      await sealInPlace(env, r.uuid, 'recovery-code', r.totp_recover)
  }
}
