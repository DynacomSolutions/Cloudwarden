import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { login } from './helpers'
import { actor, linkParams, loginCipher, mailbox } from './org-helpers'

async function trust(
  grantor: Awaited<ReturnType<typeof actor>>,
  grantee: Awaited<ReturnType<typeof actor>>,
  mb: ReturnType<typeof mailbox>,
  type: number,
  waitTimeDays = 1,
) {
  const before = mb.sent.length
  const inv = await grantor.call('/api/emergency-access/invite', 'POST', {
    email: grantee.email,
    type,
    waitTimeDays,
  })
  expect(inv.status).toBe(200)
  expect(mb.sent[before]?.to).toBe(grantee.email)
  expect(mb.sent[before]?.text).toContain('#/accept-emergency?')
  const p = linkParams(mb.sent[before])
  const id = p.get('id') as string
  const acc = await grantee.call(`/api/emergency-access/${id}/accept`, 'POST', {
    token: p.get('token'),
  })
  expect(acc.status).toBe(200)
  const conf = await grantor.call(`/api/emergency-access/${id}/confirm`, 'POST', {
    key: '4.keyForGrantee',
  })
  expect(conf.status).toBe(200)
  return id
}

it('runs the view flow: invite, accept, confirm, initiate, approve, view', async () => {
  const mb = mailbox()
  const grantor = await actor('ea-grantor@example.com', mb)
  const grantee = await actor('ea-grantee@example.com', mb)
  await grantor.call('/api/ciphers', 'POST', loginCipher('2.secret'))
  const id = await trust(grantor, grantee, mb, 0, 7)

  const trusted = await grantor.json('/api/emergency-access/trusted')
  expect(trusted.data[0]).toMatchObject({
    id,
    email: grantee.email,
    status: 2,
    type: 0,
    waitTimeDays: 7,
    granteeId: grantee.uuid,
  })
  const granted = await grantee.json('/api/emergency-access/granted')
  expect(granted.data[0]).toMatchObject({
    id,
    grantorId: grantor.uuid,
    email: grantor.email,
    status: 2,
  })
  expect(await grantee.json(`/api/emergency-access/${id}`)).toMatchObject({
    id,
    status: 2,
    type: 0,
    waitTimeDays: 7,
  })

  // Nothing is readable before recovery is approved, and only the grantee may initiate.
  expect((await grantee.call(`/api/emergency-access/${id}/view`, 'POST')).status).toBe(400)
  expect((await grantor.call(`/api/emergency-access/${id}/initiate`, 'POST')).status).toBe(404)
  expect((await grantee.call(`/api/emergency-access/${id}/initiate`, 'POST')).status).toBe(200)
  expect((await grantee.call(`/api/emergency-access/${id}/view`, 'POST')).status).toBe(400)
  expect(mb.sent.at(-1)?.to).toBe(grantor.email)
  expect((await grantee.call(`/api/emergency-access/${id}/approve`, 'POST')).status).toBe(404)

  expect((await grantor.call(`/api/emergency-access/${id}/approve`, 'POST')).status).toBe(200)
  const view = await grantee.json(`/api/emergency-access/${id}/view`, 'POST')
  expect(view).toMatchObject({ keyEncrypted: '4.keyForGrantee', object: 'emergencyAccessView' })
  expect(view.ciphers).toHaveLength(1)
  expect(view.ciphers[0].name).toBe('2.secret')
  // A view grant cannot take over the account.
  expect((await grantee.call(`/api/emergency-access/${id}/takeover`, 'POST')).status).toBe(400)

  // Rejecting returns to confirmed and closes access again.
  expect((await grantor.call(`/api/emergency-access/${id}/reject`, 'POST')).status).toBe(200)
  expect((await grantee.call(`/api/emergency-access/${id}/view`, 'POST')).status).toBe(400)
  expect((await grantee.json(`/api/emergency-access/${id}`)).status).toBe(2)
})

it('approves automatically once the wait time has passed', async () => {
  const mb = mailbox()
  const grantor = await actor('ea-wait-grantor@example.com', mb)
  const grantee = await actor('ea-wait-grantee@example.com', mb)
  const id = await trust(grantor, grantee, mb, 0, 3)
  await grantee.call(`/api/emergency-access/${id}/initiate`, 'POST')
  expect((await grantee.json(`/api/emergency-access/${id}`)).status).toBe(3)

  // Two days in: still waiting.
  const day = 24 * 3600 * 1000
  await env.DB.prepare('update emergency_access set recovery_initiated_at = ? where uuid = ?')
    .bind(Date.now() - 2 * day, id)
    .run()
  expect((await grantee.call(`/api/emergency-access/${id}/view`, 'POST')).status).toBe(400)
  // Three days in: approved without the grantor doing anything.
  await env.DB.prepare('update emergency_access set recovery_initiated_at = ? where uuid = ?')
    .bind(Date.now() - 3 * day - 1000, id)
    .run()
  expect((await grantee.json(`/api/emergency-access/${id}`)).status).toBe(4)
  expect((await grantee.call(`/api/emergency-access/${id}/view`, 'POST')).status).toBe(200)
  expect((await grantor.json('/api/emergency-access/trusted')).data[0].status).toBe(4)
})

it('runs takeover and lets the grantor sign in with the new password only', async () => {
  const mb = mailbox()
  const grantor = await actor('ea-take-grantor@example.com', mb)
  const grantee = await actor('ea-take-grantee@example.com', mb)
  const id = await trust(grantor, grantee, mb, 1, 1)
  await grantee.call(`/api/emergency-access/${id}/initiate`, 'POST')
  await grantor.call(`/api/emergency-access/${id}/approve`, 'POST')

  const takeover = await grantee.json(`/api/emergency-access/${id}/takeover`, 'POST')
  expect(takeover).toMatchObject({
    keyEncrypted: '4.keyForGrantee',
    kdf: 0,
    kdfIterations: 600000,
    object: 'emergencyAccessTakeover',
  })
  expect((await grantee.json(`/api/emergency-access/${id}/policies`)).data).toEqual([])

  const set = await grantee.call(`/api/emergency-access/${id}/password`, 'POST', {
    newMasterPasswordHash: 'recovered-hash',
    key: '2.newUserKey',
  })
  expect(set.status).toBe(200)
  expect((await login(grantor.email, 'client-derived-hash')).status).toBe(400)
  const ok = await login(grantor.email, 'recovered-hash')
  expect(ok.status).toBe(200)
  expect(((await ok.json()) as any).Key).toBe('2.newUserKey')
  // The grantor's old token no longer works.
  expect((await grantor.call('/api/accounts/profile')).status).toBe(401)
})

it('guards invitations: self, duplicates, wrong token, and either side can delete', async () => {
  const mb = mailbox()
  const grantor = await actor('ea-g-grantor@example.com', mb)
  const grantee = await actor('ea-g-grantee@example.com', mb)
  const stranger = await actor('ea-g-stranger@example.com', mb)
  const body = { email: grantee.email, type: 0, waitTimeDays: 5 }
  expect(
    (await grantor.call('/api/emergency-access/invite', 'POST', { ...body, email: grantor.email }))
      .status,
  ).toBe(400)
  expect(
    (await grantor.call('/api/emergency-access/invite', 'POST', { ...body, waitTimeDays: 0 }))
      .status,
  ).toBe(400)
  expect((await grantor.call('/api/emergency-access/invite', 'POST', body)).status).toBe(200)
  expect((await grantor.call('/api/emergency-access/invite', 'POST', body)).status).toBe(400)
  const p = linkParams(mb.sent[0])
  const id = p.get('id')
  expect(
    (await stranger.call(`/api/emergency-access/${id}/accept`, 'POST', { token: p.get('token') }))
      .status,
  ).toBe(400)
  expect(
    (await grantee.call(`/api/emergency-access/${id}/accept`, 'POST', { token: 'a.b.c' })).status,
  ).toBe(400)
  // Confirming before acceptance is refused; reinvite resends mail.
  expect(
    (await grantor.call(`/api/emergency-access/${id}/confirm`, 'POST', { key: '4.k' })).status,
  ).toBe(400)
  expect((await grantor.call(`/api/emergency-access/${id}/reinvite`, 'POST')).status).toBe(200)
  expect(mb.sent).toHaveLength(2)
  expect(
    (await grantee.call(`/api/emergency-access/${id}/accept`, 'POST', { token: p.get('token') }))
      .status,
  ).toBe(200)

  // Update the wait time, then the grantee removes themselves.
  expect(
    (await grantor.call(`/api/emergency-access/${id}`, 'PUT', { type: 1, waitTimeDays: 10 }))
      .status,
  ).toBe(200)
  expect(await grantor.json(`/api/emergency-access/${id}`)).toMatchObject({
    type: 1,
    waitTimeDays: 10,
  })
  expect((await stranger.call(`/api/emergency-access/${id}`, 'DELETE')).status).toBe(404)
  expect((await grantee.call(`/api/emergency-access/${id}`, 'DELETE')).status).toBe(200)
  expect((await grantor.call(`/api/emergency-access/${id}`)).status).toBe(404)

  // Public keys of other users are readable, private keys only for oneself.
  const pub = await grantor.json(`/api/users/${grantee.uuid}/public-key`)
  expect(pub).toMatchObject({ userId: grantee.uuid, publicKey: 'public-key' })
  expect((await grantor.json(`/api/users/${grantee.uuid}/keys`)).privateKey).toBeNull()
  expect((await grantor.json(`/api/users/${grantor.uuid}/keys`)).privateKey).toBe('2.pk')
})
