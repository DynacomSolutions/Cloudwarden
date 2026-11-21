// User event types 1000 to 1007 and 1011: sign-in, password, two-step login and client export.
import { env } from 'cloudflare:workers'
import { afterEach, describe, expect, it } from 'vitest'
import { generateTotpKey, totpAt } from '../src/auth/totp'
import { clock } from '../src/auth/twofactor'
import { authed, createSession, json, login } from './helpers'
import { actor, addMember, createOrg } from './org-helpers'

const PW = 'client-derived-hash'

afterEach(() => {
  clock.now = () => Date.now()
})

interface Row {
  event_type: number
  user_uuid: string | null
  organization_uuid: string | null
  organization_user_uuid: string | null
  acting_user_uuid: string | null
  device_type: number | null
}

/** Event rows of one account, oldest first. */
async function rowsOf(userUuid: string, type?: number) {
  const res = await env.DB.prepare(
    `select event_type, user_uuid, organization_uuid, organization_user_uuid, acting_user_uuid, device_type
       from events where user_uuid = ? ${type === undefined ? '' : 'and event_type = ?'}
       order by event_date, rowid`,
  )
    .bind(...(type === undefined ? [userUuid] : [userUuid, type]))
    .all<Row>()
  return res.results
}

const uuidOf = async (token: string) =>
  ((await (await authed('/api/accounts/profile', token)).json()) as { id: string }).id

const call = async (token: string, path: string, method: string, body?: unknown) => {
  const res = await authed(path, token, method, body)
  const text = await res.text()
  return { status: res.status, body: text ? JSON.parse(text) : null }
}

describe('sign-in events', () => {
  it('records a successful login (1000) with the device type', async () => {
    const s = await createSession('et-login@example.com')
    const id = await uuidOf(s.access_token)
    const rows = await rowsOf(id, 1000)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      user_uuid: id,
      acting_user_uuid: id,
      organization_uuid: null,
      device_type: 9,
    })
  })

  it('records a failed login (1005) only for a known account', async () => {
    const s = await createSession('et-fail@example.com')
    const id = await uuidOf(s.access_token)
    expect((await login('et-fail@example.com', 'wrong')).status).toBe(400)
    expect((await login('et-nobody@example.com', 'wrong')).status).toBe(400)
    const rows = await rowsOf(id, 1005)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ acting_user_uuid: id, device_type: 9 })
    const stray = await env.DB.prepare(
      'select count(*) n from events where event_type = 1005',
    ).first<{
      n: number
    }>()
    expect(stray?.n).toBeGreaterThanOrEqual(1)
    const unknown = await env.DB.prepare(
      'select count(*) n from events where event_type = 1005 and user_uuid is null',
    ).first<{ n: number }>()
    expect(unknown?.n).toBe(0)
  })

  it('copies user events to the log of every organisation the member belongs to', async () => {
    const owner = await actor('et-org-owner@example.com')
    const member = await actor('et-org-member@example.com')
    const { id: orgId } = await createOrg(owner)
    const ouId = await addMember(owner, orgId, member)
    expect((await login(member.email, 'wrong')).status).toBe(400)

    const log = await owner.json(`/api/organizations/${orgId}/events`)
    const failed = log.data.find((e: any) => e.type === 1005)
    expect(failed).toMatchObject({
      userId: member.uuid,
      actingUserId: member.uuid,
      organizationId: orgId,
      organizationUserId: ouId,
      deviceType: 9,
    })
    // The account's own feed lists the event once, not once per organisation.
    const own = await member.json('/api/events')
    expect(own.data.filter((e: any) => e.type === 1005)).toHaveLength(1)
  })
})

describe('two-step login events', () => {
  async function enableTotp(token: string, key: string) {
    const got = await call(token, '/api/two-factor/get-authenticator', 'POST', {
      masterPasswordHash: PW,
    })
    const code = (await totpAt(key, clock.now())) as string
    return call(token, '/api/two-factor/authenticator', 'PUT', {
      key,
      token: code,
      userVerificationToken: got.body.userVerificationToken,
    })
  }

  it('records enabling (1002), a wrong code (1006) and disabling (1003)', async () => {
    clock.now = () => 1_800_000_000_000
    const email = 'et-2fa@example.com'
    const s = await createSession(email)
    const id = await uuidOf(s.access_token)
    expect((await enableTotp(s.access_token, generateTotpKey())).status).toBe(200)
    expect(await rowsOf(id, 1002)).toHaveLength(1)

    const bad = await login(email, PW, { twoFactorProvider: '0', twoFactorToken: '000000' })
    expect(bad.status).toBe(400)
    expect(await rowsOf(id, 1006)).toHaveLength(1)
    // The failed attempt is not a completed sign-in.
    expect(await rowsOf(id, 1000)).toHaveLength(1)

    const off = await call(s.access_token, '/api/two-factor/disable', 'POST', {
      masterPasswordHash: PW,
      type: 0,
    })
    expect(off.status).toBe(200)
    expect(await rowsOf(id, 1003)).toHaveLength(1)
  })

  it('records recovery with the recovery code (1004)', async () => {
    const email = 'et-recover@example.com'
    const s = await createSession(email)
    const id = await uuidOf(s.access_token)
    await enableTotp(s.access_token, generateTotpKey())
    const code = (
      await call(s.access_token, '/api/two-factor/get-recover', 'POST', { masterPasswordHash: PW })
    ).body.code
    const res = await json('/api/two-factor/recover', {
      email,
      masterPasswordHash: PW,
      recoveryCode: code,
    })
    expect(res.status).toBe(200)
    expect(await rowsOf(id, 1004)).toHaveLength(1)
  })

  it('records a recovery code used at login (1004) and a wrong one (1006)', async () => {
    const email = 'et-recover-login@example.com'
    const s = await createSession(email)
    const id = await uuidOf(s.access_token)
    await enableTotp(s.access_token, generateTotpKey())
    const code = (
      await call(s.access_token, '/api/two-factor/get-recover', 'POST', { masterPasswordHash: PW })
    ).body.code
    const wrong = await login(email, PW, { twoFactorProvider: '8', twoFactorToken: 'NOTACODE' })
    expect(wrong.status).toBe(400)
    expect(await rowsOf(id, 1006)).toHaveLength(1)
    const ok = await login(email, PW, { twoFactorProvider: '8', twoFactorToken: code })
    expect(ok.status).toBe(200)
    expect(await rowsOf(id, 1004)).toHaveLength(1)
  })
})

describe('account events', () => {
  it('records a password change (1001)', async () => {
    const s = await createSession('et-pw@example.com')
    const id = await uuidOf(s.access_token)
    const res = await call(s.access_token, '/api/accounts/password', 'POST', {
      masterPasswordHash: PW,
      newMasterPasswordHash: 'another-derived-hash',
      key: '2.newKey',
    })
    expect(res.status).toBe(200)
    const rows = await rowsOf(id, 1001)
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ acting_user_uuid: id })
  })

  it('accepts the vault export event (1007) without an item or an organisation', async () => {
    const s = await createSession('et-export@example.com')
    const id = await uuidOf(s.access_token)
    const now = new Date().toISOString()
    const res = await call(s.access_token, '/events/collect', 'POST', [
      { type: 1007, date: now },
      { type: 2400, date: now },
      // Not a client event: dropped.
      { type: 1001, date: now },
    ])
    expect(res.status).toBe(200)
    expect(await rowsOf(id, 1007)).toHaveLength(1)
    expect(await rowsOf(id, 2400)).toHaveLength(1)
    expect(await rowsOf(id, 1001)).toHaveLength(0)
  })
})
