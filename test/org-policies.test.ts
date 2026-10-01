import { env } from 'cloudflare:workers'
import { expect, it } from 'vitest'
import { form, login } from './helpers'
import { actor, addMember, createOrg, loginCipher } from './org-helpers'

it('stores policies, returns them in sync and reports them for members', async () => {
  const owner = await actor('pol-owner@example.com')
  const member = await actor('pol-member@example.com')
  const { id } = await createOrg(owner)
  await addMember(owner, id, member, { type: 2 })

  const empty = await owner.json(`/api/organizations/${id}/policies/7`)
  expect(empty).toMatchObject({ organizationId: id, type: 7, enabled: false })

  const saved = await owner.json(`/api/organizations/${id}/policies/7`, 'PUT', {
    policy: { enabled: true, data: { disableHideEmail: true } },
    metadata: {},
  })
  expect(saved).toMatchObject({
    type: 7,
    enabled: true,
    data: { disableHideEmail: true },
    object: 'policy',
  })
  // The older bare body is accepted too, and a second save updates the same row.
  const again = await owner.json(`/api/organizations/${id}/policies/7`, 'PUT', {
    enabled: false,
    data: null,
  })
  expect(again.id).toBe(saved.id)
  expect(again.enabled).toBe(false)
  await owner.json(`/api/organizations/${id}/policies/7`, 'PUT', { enabled: true, data: { a: 1 } })

  const list = await owner.json(`/api/organizations/${id}/policies`)
  expect(list.data).toHaveLength(1)

  const synced = await member.json('/api/sync')
  expect(synced.policies).toHaveLength(1)
  expect(synced.policies[0]).toMatchObject({ organizationId: id, type: 7, enabled: true })
  // Disabled policies are not synced.
  await owner.json(`/api/organizations/${id}/policies/7`, 'PUT', { enabled: false })
  expect((await member.json('/api/sync')).policies).toHaveLength(0)
})

it('returns the master password policy in the token response and enforces it as data', async () => {
  const owner = await actor('mp-owner@example.com')
  const member = await actor('mp-member@example.com')
  const { id } = await createOrg(owner)
  await addMember(owner, id, member, { type: 2 })

  const before = (await (await login('mp-member@example.com')).json()) as any
  expect(before.MasterPasswordPolicy).toEqual({ Object: 'masterPasswordPolicy' })

  await owner.json(`/api/organizations/${id}/policies/1`, 'PUT', {
    enabled: true,
    data: { minLength: 14, minComplexity: 3, requireUpper: true, enforceOnLogin: true },
  })
  const after = (await (await login('mp-member@example.com')).json()) as any
  expect(after.MasterPasswordPolicy).toMatchObject({
    MinLength: 14,
    MinComplexity: 3,
    RequireUpper: true,
    RequireNumbers: false,
    EnforceOnLogin: true,
    Object: 'masterPasswordPolicy',
  })
  const direct = await member.json(`/api/organizations/${id}/policies/master-password`)
  expect(direct).toMatchObject({ type: 1, enabled: true, data: { minLength: 14 } })

  // Owners are exempt from the requirement.
  const ownerLogin = (await (
    await form('/identity/connect/token', {
      grant_type: 'password',
      username: 'mp-owner@example.com',
      password: 'client-derived-hash',
      scope: 'api offline_access',
      client_id: 'web',
      deviceType: '9',
      deviceName: 'chrome',
      deviceIdentifier: 'device-2',
    })
  ).json()) as any
  expect(ownerLogin.MasterPasswordPolicy).toEqual({ Object: 'masterPasswordPolicy' })
})

it('rejects personal items for members under the personal ownership policy', async () => {
  const owner = await actor('po-owner@example.com')
  const member = await actor('po-member@example.com')
  const { id, defaultCollectionId } = await createOrg(owner)
  await addMember(owner, id, member, { type: 2, collections: [{ id: defaultCollectionId }] })
  expect((await member.call('/api/ciphers', 'POST', loginCipher('2.before'))).status).toBe(200)

  await owner.json(`/api/organizations/${id}/policies/5`, 'PUT', { enabled: true })
  const blocked = await member.call('/api/ciphers', 'POST', loginCipher('2.blocked'))
  expect(blocked.status).toBe(400)
  expect(((await blocked.json()) as any).message).toContain('policy')
  expect(
    (
      await member.call('/api/ciphers/create', 'POST', {
        cipher: loginCipher('2.b2'),
        collectionIds: [],
      })
    ).status,
  ).toBe(400)
  expect(
    (
      await member.call('/api/ciphers/import', 'POST', {
        ciphers: [loginCipher('2.b3')],
        folders: [],
        folderRelationships: [],
      })
    ).status,
  ).toBe(400)
  // Organisation items are still allowed, and owners are exempt.
  const orgItem = await member.call('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.fine', { organizationId: id }),
    collectionIds: [defaultCollectionId],
  })
  expect(orgItem.status).toBe(200)
  expect((await owner.call('/api/ciphers', 'POST', loginCipher('2.owner'))).status).toBe(200)

  await owner.json(`/api/organizations/${id}/policies/5`, 'PUT', { enabled: false })
  expect((await member.call('/api/ciphers', 'POST', loginCipher('2.after'))).status).toBe(200)
})

it('requires two-step login when the policy is on: revokes members and blocks accept and restore', async () => {
  const owner = await actor('tf-owner@example.com')
  const plain = await actor('tf-plain@example.com')
  const secure = await actor('tf-secure@example.com')
  const { id } = await createOrg(owner)
  const plainId = await addMember(owner, id, plain, { type: 2 })
  const secureId = await addMember(owner, id, secure, { type: 2 })
  await env.DB.prepare(
    'insert into twofactor (uuid, user_uuid, atype, enabled, data, last_used) values (?, ?, 0, 1, ?, 0)',
  )
    .bind(crypto.randomUUID(), secure.uuid, 'secret')
    .run()

  await owner.json(`/api/organizations/${id}/policies/0`, 'PUT', { enabled: true })
  const users = (await owner.json(`/api/organizations/${id}/users`)).data
  expect(users.find((u: any) => u.id === plainId).status).toBe(-1)
  expect(users.find((u: any) => u.id === secureId).status).toBe(2)
  expect(users.find((u: any) => u.userId === owner.uuid).status).toBe(2)

  const restore = await owner.call(`/api/organizations/${id}/users/${plainId}/restore`, 'PUT')
  expect(restore.status).toBe(400)

  // A new invitee without two-step login cannot accept.
  const late = await actor('tf-late@example.com')
  const { mail } = await import('./org-helpers')
  const before = mail.sent.length
  await owner.call(`/api/organizations/${id}/users/invite`, 'POST', {
    emails: [late.email],
    type: 2,
  })
  const { linkParams } = await import('./org-helpers')
  const p = linkParams(mail.sent[before])
  const acc = await late.call(
    `/api/organizations/${id}/users/${p.get('organizationUserId')}/accept`,
    'POST',
    { token: p.get('token') },
  )
  expect(acc.status).toBe(400)

  // Once they enable two-step login the restore goes through.
  await env.DB.prepare(
    'insert into twofactor (uuid, user_uuid, atype, enabled, data, last_used) values (?, ?, 0, 1, ?, 0)',
  )
    .bind(crypto.randomUUID(), plain.uuid, 'secret')
    .run()
  expect(
    (await owner.call(`/api/organizations/${id}/users/${plainId}/restore`, 'PUT')).status,
  ).toBe(200)
})
