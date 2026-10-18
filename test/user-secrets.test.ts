import { env } from 'cloudflare:workers'
import { eq } from 'drizzle-orm'
import { describe, expect, it } from 'vitest'
import { useRecoveryCode } from '../src/auth/twofactor'
import { openUserSecret, sealUserSecret } from '../src/auth/user-secrets'
import { createDb, schema } from '../src/db'
import type { User } from '../src/env'
import { createSession, dbWithRace, withEnv } from './helpers'

const PW = 'client-derived-hash'
const NEW_JWT = 'n'.repeat(48)
const KEY_A = 'a'.repeat(40)
const KEY_B = 'b'.repeat(40)

const post = (e: Record<string, unknown>, token: string, path: string, body: unknown) =>
  withEnv(e, path, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

const column = async (email: string, col: 'totp_recover' | 'api_key') =>
  (await env.DB.prepare(`select uuid, ${col} v from users where email = ?`)
    .bind(email)
    .first<{ uuid: string; v: string | null }>()) as { uuid: string; v: string | null }

const credentials = (e: Record<string, unknown>, uuid: string, secret: string) =>
  withEnv(e, '/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: `user.${uuid}`,
      client_secret: secret,
      scope: 'api',
      deviceIdentifier: 'cli-x',
      deviceType: '25',
      deviceName: 'cli',
    }).toString(),
  })

describe('stored secrets survive key problems', () => {
  it('does not open a value sealed under another JWT_SECRET, unless it is the previous one', async () => {
    const sealed = await sealUserSecret(env, 'u1', 'api-key', 'value')
    const rotated = { ...env, JWT_SECRET: NEW_JWT, DATA_ENCRYPTION_KEY: undefined }
    await expect(openUserSecret(rotated, 'u1', 'api-key', sealed)).rejects.toThrow()
    const opened = await openUserSecret(
      { ...rotated, JWT_SECRET_PREVIOUS: env.JWT_SECRET },
      'u1',
      'api-key',
      sealed,
    )
    expect(opened).toMatchObject({ value: 'value', stale: true })
  })

  it('a wrong DATA_ENCRYPTION_KEY gives 500 on views, a plain login failure at the token endpoint, and leaves the recovery code and API key untouched', async () => {
    const email = 'us-wrong-key@example.com'
    const s = await createSession(email)
    const e1 = { DATA_ENCRYPTION_KEY: KEY_A }
    const rec = await post(e1, s.access_token, '/api/two-factor/get-recover', {
      masterPasswordHash: PW,
    })
    const code = ((await rec.json()) as any).code
    const key = await post(e1, s.access_token, '/api/accounts/api-key', { masterPasswordHash: PW })
    const apiKey = ((await key.json()) as any).apiKey
    const before = {
      r: (await column(email, 'totp_recover')).v,
      k: (await column(email, 'api_key')).v,
    }

    const e2 = { DATA_ENCRYPTION_KEY: KEY_B }
    for (const [path] of [['/api/two-factor/get-recover'], ['/api/accounts/api-key']] as const) {
      const res = await post(e2, s.access_token, path, { masterPasswordHash: PW })
      expect(res.status).toBe(500)
      expect(await res.text()).not.toContain(code)
    }
    // The token endpoint treats an unreadable key like a wrong secret (TASKS #415).
    const uuid = (await column(email, 'api_key')).uuid
    const wrong = await credentials(e1, uuid, 'not-the-key')
    const login = await credentials(e2, uuid, apiKey)
    expect(login.status).toBe(wrong.status)
    expect(login.status).toBe(400)
    expect(await login.text()).toBe(await wrong.text())
    expect({
      r: (await column(email, 'totp_recover')).v,
      k: (await column(email, 'api_key')).v,
    }).toEqual(before)

    // The right key still returns the same values.
    const again = await post(e1, s.access_token, '/api/two-factor/get-recover', {
      masterPasswordHash: PW,
    })
    expect(((await again.json()) as any).code).toBe(code)
  })

  it('JWT_SECRET_PREVIOUS opens old values and re-seals them under the new secret', async () => {
    const email = 'us-rotate@example.com'
    const s = await createSession(email)
    const rec = await post({}, s.access_token, '/api/two-factor/get-recover', {
      masterPasswordHash: PW,
    })
    const code = ((await rec.json()) as any).code
    const key = await post({}, s.access_token, '/api/accounts/api-key', { masterPasswordHash: PW })
    const apiKey = ((await key.json()) as any).apiKey
    const before = {
      r: (await column(email, 'totp_recover')).v,
      k: (await column(email, 'api_key')).v,
    }

    const rotated = { JWT_SECRET: NEW_JWT, JWT_SECRET_PREVIOUS: env.JWT_SECRET }
    const rec2 = await post(rotated, s.access_token, '/api/two-factor/get-recover', {
      masterPasswordHash: PW,
    })
    expect(rec2.status).toBe(200)
    expect(((await rec2.json()) as any).code).toBe(code)
    const login = await credentials(rotated, (await column(email, 'api_key')).uuid, apiKey)
    expect(login.status).toBe(200)
    const key2 = await post(rotated, s.access_token, '/api/accounts/api-key', {
      masterPasswordHash: PW,
    })
    expect(((await key2.json()) as any).apiKey).toBe(apiKey)

    const r = await column(email, 'totp_recover')
    const k = await column(email, 'api_key')
    expect(r.v).not.toBe(before.r)
    expect(k.v).not.toBe(before.k)
    const onlyNew = { ...env, JWT_SECRET: NEW_JWT, DATA_ENCRYPTION_KEY: undefined }
    expect((await openUserSecret(onlyNew, r.uuid, 'recovery-code', r.v as string))?.value).toBe(
      code,
    )
    expect((await openUserSecret(onlyNew, k.uuid, 'api-key', k.v as string))?.value).toBe(apiKey)
  })

  it('concurrent first views of the recovery code agree', async () => {
    const email = 'us-race@example.com'
    const s = await createSession(email)
    const view = async () =>
      (
        (await (
          await post({}, s.access_token, '/api/two-factor/get-recover', { masterPasswordHash: PW })
        ).json()) as any
      ).code as string
    const [a, b, c] = await Promise.all([view(), view(), view()])
    expect(b).toBe(a)
    expect(c).toBe(a)
    expect(await view()).toBe(a)
  })
})

describe('recovery code use races a re-seal', () => {
  it('a valid code still works once when a view re-seals it between read and write', async () => {
    const email = 'us-recover-race@example.com'
    const s = await createSession(email)
    const rec = await post({}, s.access_token, '/api/two-factor/get-recover', {
      masterPasswordHash: PW,
    })
    const code = ((await rec.json()) as any).code as string
    const { uuid } = await column(email, 'totp_recover')
    const load = async () =>
      (
        await createDb(env.DB).select().from(schema.users).where(eq(schema.users.uuid, uuid))
      )[0] as User
    const user = await load()

    const DB = dbWithRace(env.DB, /^update "users"/i, async () => {
      await env.DB.prepare('update users set totp_recover = ? where uuid = ?')
        .bind(await sealUserSecret(env, uuid, 'recovery-code', code), uuid)
        .run()
    })
    const raced = { ...env, DB }
    expect(await useRecoveryCode(raced, createDb(DB), user, code)).toBe(true)
    // Single use: the same code fails now.
    expect(await useRecoveryCode(env, createDb(env.DB), await load(), code)).toBe(false)
  })
})
