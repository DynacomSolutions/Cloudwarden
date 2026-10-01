import { eq } from 'drizzle-orm'
import { safeEqualStrings, sha256B64u } from '../auth/crypto'
import { signJwt, verifyJwt } from '../auth/jwt'
import { type StoredPassword, verifyMasterPassword } from '../auth/passwords'
import type { Db } from '../db'
import { schema } from '../db'
import type { Bindings } from '../env'
import { ApiError } from '../errors'
import { baseUrl, signBlobToken, signingKeyFor, verificationKeysFor } from './blobs'
import {
  claimAccess,
  SEND_FILE,
  SEND_FILE_AUD,
  type SendRow,
  sendUuidFrom,
  unavailable,
} from './sends'

export const SEND_ACCESS_AUD = 'send_access'
export const SEND_TOKEN_TTL_SECONDS = 1800

export const notAvailable = () => new ApiError(404, 'Send not found.')

/** The Send a recipient asks for, or a 404 when it is missing or unusable (never says which). */
export async function loadForAccess(
  db: Db,
  idOrAccess: string,
  now = Date.now(),
): Promise<SendRow> {
  const uuid = sendUuidFrom(idOrAccess)
  const [row] = uuid
    ? await db.select().from(schema.sends).where(eq(schema.sends.uuid, uuid)).limit(1)
    : []
  if (!row || unavailable(row, now)) throw notAvailable()
  return row
}

export type PasswordCheck = 'ok' | 'required' | 'invalid'

export async function checkSendPassword(
  send: SendRow,
  password: string | null | undefined,
): Promise<PasswordCheck> {
  if (!send.passwordHash || !send.passwordSalt) return 'ok'
  if (!password) return 'required'
  const stored: StoredPassword = {
    passwordHash: send.passwordHash,
    salt: send.passwordSalt,
    passwordIterations: send.passwordIter ?? 100_000,
  }
  return (await verifyMasterPassword(stored, password)) ? 'ok' : 'invalid'
}

/** Legacy flows: translate a failed password check into the status the clients expect. */
export function passwordError(check: PasswordCheck): ApiError | null {
  if (check === 'required') return new ApiError(401, 'Password not provided.')
  if (check === 'invalid') {
    return new ApiError(400, 'The request is invalid.', { password: ['Invalid password.'] })
  }
  return null
}

const sendTokenLabel = 'send-access'

/** Binds a token to the Send's current password and revision, so edits revoke old tokens. */
const sendVersion = (send: SendRow) => sha256B64u(`${send.passwordHash ?? ''}:${send.updatedAt}`)

export async function signSendAccessToken(env: Bindings, send: SendRow): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  return signJwt(
    {
      aud: SEND_ACCESS_AUD,
      sub: send.uuid,
      v: await sendVersion(send),
      nbf: now - 5,
      exp: now + SEND_TOKEN_TTL_SECONDS,
    },
    await signingKeyFor(env, sendTokenLabel),
  )
}

/** The Send named by a valid `send_access` bearer token that still matches it, or null. */
export async function sendFromBearer(
  env: Bindings,
  db: Db,
  header: string | undefined,
): Promise<SendRow | null> {
  const match = /^Bearer\s+(\S+)$/i.exec(header ?? '')
  if (!match?.[1]) return null
  const claims = await verifyJwt<{ aud?: string; sub?: string; v?: string; exp: number }>(
    match[1],
    await verificationKeysFor(env, sendTokenLabel),
  )
  if (claims?.aud !== SEND_ACCESS_AUD || !claims.sub || !claims.v) return null
  const [send] = await db
    .select()
    .from(schema.sends)
    .where(eq(schema.sends.uuid, claims.sub))
    .limit(1)
  if (!send || !safeEqualStrings(claims.v, await sendVersion(send))) return null
  return send
}

/** Counts the access and returns the signed URL for a File Send's blob. */
export async function fileDownloadUrl(db: Db, env: Bindings, send: SendRow, fileId: string) {
  if (send.atype !== SEND_FILE || !send.r2Key) throw notAvailable()
  const data = JSON.parse(send.data) as { id?: string }
  if (!data.id || !safeEqualStrings(data.id, fileId)) throw notAvailable()
  if (!(await claimAccess(db, send.uuid, Date.now()))) throw notAvailable()
  const token = await signBlobToken(env, SEND_FILE_AUD, `${send.uuid}/${fileId}`)
  return {
    object: 'send-fileDownload',
    id: fileId,
    url: `${baseUrl(env)}/send-files/${send.uuid}/${fileId}?token=${token}`,
  }
}
