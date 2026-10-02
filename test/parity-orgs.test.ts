import { describe, expect, it } from 'vitest'
import { json } from './helpers'
import {
  actor,
  addMember,
  createOrg,
  enableRecoveryPolicy,
  linkParams,
  loginCipher,
  mail,
} from './org-helpers'

const orgCipher = async (owner: Awaited<ReturnType<typeof actor>>, orgId: string, col: string) =>
  owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.shared', { organizationId: orgId }),
    collectionIds: [col],
  })

describe('collection management settings', () => {
  it('persists, exposes and enforces the four settings', async () => {
    const owner = await actor('cm-owner@example.com')
    const user = await actor('cm-user@example.com')
    const { id, defaultCollectionId } = await createOrg(owner)
    const memberId = await addMember(owner, id, user, {
      collections: [{ id: defaultCollectionId, readOnly: false, hidePasswords: false }],
    })

    // Defaults: only privileged members create collections.
    expect(
      (await user.call(`/api/organizations/${id}/collections`, 'POST', { name: '2.c' })).status,
    ).toBe(403)

    const settings = {
      limitCollectionCreation: false,
      limitCollectionDeletion: false,
      limitItemDeletion: true,
      allowAdminAccessToAllCollectionItems: false,
    }
    // Members cannot change them.
    expect(
      (await user.call(`/api/organizations/${id}/collection-management`, 'PUT', settings)).status,
    ).toBe(403)
    const res = await owner.json(`/api/organizations/${id}/collection-management`, 'PUT', settings)
    expect(res).toMatchObject({ object: 'organization', id, ...settings })
    expect((await owner.json(`/api/organizations/${id}`)).limitItemDeletion).toBe(true)
    const profile = await user.json('/api/accounts/profile')
    expect(profile.organizations[0]).toMatchObject(settings)

    // Creation is open: the creator manages their collection and may delete it.
    const created = await user.json(`/api/organizations/${id}/collections`, 'POST', {
      name: '2.mine',
    })
    expect(created.id).toBeTruthy()
    // Deletion needs Manage: the member has edit-only access to the default collection.
    expect(
      (await user.call(`/api/organizations/${id}/collections/${defaultCollectionId}`, 'DELETE'))
        .status,
    ).toBe(403)
    expect(
      (await user.call(`/api/organizations/${id}/collections/${created.id}`, 'DELETE')).status,
    ).toBe(200)

    // Limit item deletion: edit access no longer deletes items.
    const item = await orgCipher(owner, id, defaultCollectionId)
    expect((await user.json(`/api/ciphers/${item.id}`)).permissions).toEqual({
      delete: false,
      restore: false,
    })
    expect((await user.call(`/api/ciphers/${item.id}`, 'DELETE')).status).toBe(403)

    // Admin access to all items off: an admin without assignments loses the admin endpoints.
    const admin = await actor('cm-admin@example.com')
    await addMember(owner, id, admin, { type: 1 })
    expect(
      (await admin.call(`/api/ciphers/organization-details?organizationId=${id}`)).status,
    ).toBe(403)
    await owner.call(`/api/organizations/${id}/collection-management`, 'PUT', {
      ...settings,
      allowAdminAccessToAllCollectionItems: true,
      limitItemDeletion: false,
    })
    expect(
      (await admin.call(`/api/ciphers/organization-details?organizationId=${id}`)).status,
    ).toBe(200)
    expect((await user.json(`/api/ciphers/${item.id}`)).permissions.delete).toBe(true)
    expect((await user.call(`/api/ciphers/${item.id}`, 'DELETE')).status).toBe(200)
    expect(memberId).toBeTruthy()
  })

  it('rejects a malformed body', async () => {
    const owner = await actor('cm-bad@example.com')
    const { id } = await createOrg(owner)
    expect(
      (await owner.call(`/api/organizations/${id}/collection-management`, 'PUT', {})).status,
    ).toBe(400)
  })
})

describe('organisation export', () => {
  it('exports collections and live items to permitted members only', async () => {
    const owner = await actor('exp-owner@example.com')
    const user = await actor('exp-user@example.com')
    const outsider = await actor('exp-out@example.com')
    const { id, defaultCollectionId } = await createOrg(owner)
    await addMember(owner, id, user)
    const item = await orgCipher(owner, id, defaultCollectionId)
    const gone = await orgCipher(owner, id, defaultCollectionId)
    await owner.call(`/api/ciphers/${gone.id}/delete`, 'PUT')

    const out = await owner.json(`/api/organizations/${id}/export`)
    expect(out.collections).toHaveLength(1)
    expect(out.collections[0]).toMatchObject({
      id: defaultCollectionId,
      name: '2.defaultCollection',
    })
    expect(out.ciphers).toHaveLength(1)
    expect(out.ciphers[0]).toMatchObject({ id: item.id, collectionIds: [defaultCollectionId] })

    expect((await user.call(`/api/organizations/${id}/export`)).status).toBe(403)
    expect((await outsider.call(`/api/organizations/${id}/export`)).status).toBe(404)

    const custom = await actor('exp-custom@example.com')
    await addMember(owner, id, custom, { type: 4, permissions: { accessImportExport: true } })
    // Without access to every item the export holds only what the member can reach.
    const limited = await custom.json(`/api/organizations/${id}/export`)
    expect(limited.ciphers).toEqual([])
    expect(limited.collections).toEqual([])
  })
})

describe('group membership removal', () => {
  it('removes one member from a group', async () => {
    const owner = await actor('gu-owner@example.com')
    const user = await actor('gu-user@example.com')
    const { id } = await createOrg(owner)
    const memberId = await addMember(owner, id, user)
    const group = await owner.json(`/api/organizations/${id}/groups`, 'POST', {
      name: 'Team',
      users: [memberId],
      collections: [],
    })
    const path = `/api/organizations/${id}/groups/${group.id}/user/${memberId}`
    expect((await user.call(path, 'DELETE')).status).toBe(403)
    expect((await owner.call(path, 'DELETE')).status).toBe(200)
    expect(await owner.json(`/api/organizations/${id}/groups/${group.id}/users`)).toEqual([])
    expect((await owner.call(path, 'DELETE')).status).toBe(404)
  })
})

describe('invite links', () => {
  it('creates, reads, updates, refreshes and deletes a link, and serves the public checks', async () => {
    const owner = await actor('il-owner@example.com')
    const user = await actor('il-user@example.com')
    const { id } = await createOrg(owner, 'Linked')
    await addMember(owner, id, user)
    const base = `/api/organizations/${id}/invite-link`

    expect((await owner.call(base)).status).toBe(404)
    const invite = 'invite.v1.wrapped'
    expect(
      (await user.call(base, 'POST', { allowedDomains: ['example.com'], invite })).status,
    ).toBe(403)
    const created = await owner.json(base, 'POST', {
      allowedDomains: ['Example.com'],
      invite,
      supportsConfirmation: false,
    })
    expect(created).toMatchObject({
      organizationId: id,
      allowedDomains: ['example.com'],
      invite,
      supportsConfirmation: false,
    })
    expect(created.code).toBeTruthy()
    expect(
      (await owner.call(base, 'POST', { allowedDomains: ['example.com'], invite })).status,
    ).toBe(400)
    expect(await owner.json(base)).toMatchObject({ id: created.id, code: created.code })

    const upd = await owner.json(base, 'PUT', { allowedDomains: ['example.com', 'example.org'] })
    expect(upd.allowedDomains).toEqual(['example.com', 'example.org'])
    expect((await owner.call(base, 'PUT', { allowedDomains: [] })).status).toBe(400)

    // Public routes need the right code.
    const status = await json('/api/organizations/invite-link/status', {
      organizationId: id,
      code: created.code,
    })
    expect(await status.json()).toMatchObject({
      organizationName: 'Linked',
      linksEnabled: true,
      seatsAvailable: true,
      sso: null,
    })
    expect(
      (await json('/api/organizations/invite-link/status', { organizationId: id, code: 'nope' }))
        .status,
    ).toBe(404)
    const pol = await json('/api/organizations/invite-link/policies', {
      organizationId: id,
      code: created.code,
    })
    expect(((await pol.json()) as { object: string }).object).toBe('list')
    const check = async (email: string) =>
      (
        (await (
          await json('/api/organizations/invite-link/validate-email-domain', {
            organizationId: id,
            code: created.code,
            email,
          })
        ).json()) as { isAllowed: boolean }
      ).isAllowed
    expect(await check('new@example.org')).toBe(true)
    expect(await check('new@example.net')).toBe(false)

    const refreshed = await owner.json(`${base}/refresh`, 'POST', { invite: 'v2' })
    expect(refreshed.code).not.toBe(created.code)
    expect(refreshed.invite).toBe('v2')
    expect(
      (
        await json('/api/organizations/invite-link/status', {
          organizationId: id,
          code: created.code,
        })
      ).status,
    ).toBe(404)
    const conf = await owner.json(`${base}/support-confirm`, 'PUT', {
      invite: 'v3',
      supportsConfirmation: true,
    })
    expect(conf.supportsConfirmation).toBe(true)

    expect((await user.call(base, 'DELETE')).status).toBe(403)
    expect((await owner.call(base, 'DELETE')).status).toBe(200)
    expect((await owner.call(base)).status).toBe(404)
  })
})

describe('organisation creation without payment', () => {
  it('creates an organisation owned by the caller', async () => {
    const owner = await actor('nopay@example.com')
    const org = await owner.json('/api/organizations/create-without-payment', 'POST', {
      name: 'Free',
      businessName: '',
      billingEmail: 'billing@example.com',
      planType: 0,
      key: '4.k',
      keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' },
      collectionName: '2.c',
      additionalSeats: 0,
      maxAutoscaleSeats: 0,
    })
    expect(org).toMatchObject({ object: 'organization', name: 'Free' })
    const profile = await owner.json('/api/accounts/profile')
    expect(profile.organizations[0]).toMatchObject({ id: org.id, type: 0, status: 2 })
    expect(
      (await owner.call('/api/organizations/create-without-payment', 'POST', { name: 'x' })).status,
    ).toBe(400)
  })
})

describe('accept-init', () => {
  it('lets an invited owner initialise an organisation without keys', async () => {
    const creator = await actor('ai-creator@example.com')
    const invitee = await actor('ai-owner@example.com')
    const org = await creator.json('/api/organizations', 'POST', {
      name: 'NoKeys',
      billingEmail: 'billing@example.com',
      key: '4.k',
    })
    await creator.call(`/api/organizations/${org.id}/users/invite`, 'POST', {
      emails: [invitee.email],
      type: 0,
    })
    const params = linkParams(await inviteMail(invitee.email))
    const ouId = params.get('organizationUserId') as string
    const body = {
      token: params.get('token'),
      key: '4.ownerKey',
      keys: { publicKey: 'pub', encryptedPrivateKey: '2.priv' },
      collectionName: '2.first',
    }
    const path = `/api/organizations/${org.id}/users/${ouId}/accept-init`
    expect((await creator.call(path, 'POST', body)).status).toBe(400)
    expect((await invitee.call(path, 'POST', { ...body, token: 'bad' })).status).toBe(400)
    expect((await invitee.call(path, 'POST', body)).status).toBe(200)
    const profile = await invitee.json('/api/accounts/profile')
    expect(profile.organizations[0]).toMatchObject({
      id: org.id,
      status: 2,
      key: '4.ownerKey',
      hasPublicAndPrivateKeys: true,
    })
    const sync = await invitee.json('/api/sync')
    expect(sync.collections.map((c: { name: string }) => c.name)).toContain('2.first')
    expect((await invitee.call(path, 'POST', body)).status).toBe(400)
  })
})

/** The invitation mail for `email` (other mail, such as account emails, may arrive meanwhile). */
const inviteMail = async (email: string) => {
  for (let i = 0; i < 40; i++) {
    const found = mail.sent.find((x) => x.to === email && x.text.includes('organizationUserId'))
    if (found) return found
    await new Promise((r) => setTimeout(r, 50))
  }
  throw new Error(`no invitation mail for ${email}`)
}

describe('auto-confirm', () => {
  it('lists accepted members and confirms them singly and in bulk', async () => {
    const owner = await actor('ac-owner@example.com')
    const a = await actor('ac-a@example.com')
    const b = await actor('ac-b@example.com')
    const { id } = await createOrg(owner)
    const ids: string[] = []
    for (const m of [a, b]) {
      await owner.call(`/api/organizations/${id}/users/invite`, 'POST', {
        emails: [m.email],
        type: 2,
      })
      const p = linkParams(await inviteMail(m.email))
      const ou = p.get('organizationUserId') as string
      await m.call(`/api/organizations/${id}/users/${ou}/accept`, 'POST', { token: p.get('token') })
      ids.push(ou)
    }
    expect((await a.call(`/api/organizations/${id}/users/pending-auto-confirm`)).status).toBe(404)
    // Nothing runs until the organisation turns the policy on.
    expect((await owner.call(`/api/organizations/${id}/users/pending-auto-confirm`)).status).toBe(
      400,
    )
    expect(
      (
        await owner.call(`/api/organizations/${id}/users/${ids[0]}/auto-confirm`, 'POST', {
          key: '4.k',
        })
      ).status,
    ).toBe(400)
    expect(
      (await owner.call(`/api/organizations/${id}/policies/18`, 'PUT', { enabled: true })).status,
    ).toBe(200)
    const pending = await owner.json(`/api/organizations/${id}/users/pending-auto-confirm`)
    expect(pending.data.map((r: { id: string }) => r.id).sort()).toEqual([...ids].sort())
    expect(pending.data[0].userId).toBeTruthy()

    expect(
      (
        await owner.call(`/api/organizations/${id}/users/${ids[0]}/auto-confirm`, 'POST', {
          key: '4.k',
        })
      ).status,
    ).toBe(200)
    const bulk = await owner.json(`/api/organizations/${id}/users/bulk-auto-confirm`, 'POST', {
      keys: [
        { id: ids[0], key: '4.k' },
        { id: ids[1], key: '4.k' },
      ],
    })
    expect(bulk.data).toEqual([
      expect.objectContaining({ id: ids[0], error: 'User is not ready to be confirmed.' }),
      expect.objectContaining({ id: ids[1], error: null }),
    ])
    expect((await owner.json(`/api/organizations/${id}/users/pending-auto-confirm`)).data).toEqual(
      [],
    )
  })
})

describe('joining through an invite link', () => {
  const join = (id: string, code: string, extra: Record<string, unknown> = {}) => ({
    organizationId: id,
    code,
    ...extra,
  })

  it('serves the invite, accepts, confirms and enforces the checks', async () => {
    const owner = await actor('jl-owner@example.com')
    const { id } = await createOrg(owner, 'Joinable')
    const base = `/api/organizations/${id}/invite-link`
    const link = await owner.json(base, 'POST', {
      allowedDomains: ['example.com'],
      invite: 'opaque-invite',
      supportsConfirmation: false,
    })
    const stranger = await actor('jl-stranger@example.com')
    expect(
      await stranger.json(
        '/api/organizations/users/invite-link/invite',
        'POST',
        join(id, link.code),
      ),
    ).toMatchObject({
      invite: 'opaque-invite',
    })
    expect(
      (await stranger.call('/api/organizations/users/invite-link/invite', 'POST', join(id, 'nope')))
        .status,
    ).toBe(404)
    expect(
      (await json('/api/organizations/users/invite-link/invite', join(id, link.code))).status,
    ).toBe(401)
    expect((await json('/api/organizations/invite-link/status', join(id, link.code))).status).toBe(
      200,
    )

    // Accept: the member waits for an administrator.
    const accept = '/api/organizations/users/invite-link/accept'
    expect((await stranger.call(accept, 'POST', join(id, link.code))).status).toBe(200)
    const again = await stranger.call(accept, 'POST', join(id, link.code))
    expect(again.status).toBe(400)
    expect(((await again.json()) as { message: string }).message).toBe(
      "You're already a member of Joinable.",
    )
    const members = await owner.json(`/api/organizations/${id}/users`)
    expect(members.data.find((m: { email: string }) => m.email === stranger.email)).toMatchObject({
      status: 1,
    })

    // Confirm needs a link that supports it.
    const other = await actor('jl-other@example.com')
    const confirm = '/api/organizations/users/invite-link/confirm'
    const body = join(id, link.code, { orgUserKey: '4.key', defaultUserCollectionName: '2.mine' })
    expect((await other.call(confirm, 'POST', body)).status).toBe(400)
    await owner.json(`${base}/support-confirm`, 'PUT', {
      invite: 'opaque-invite',
      supportsConfirmation: true,
    })
    // Joining without confirmation by an administrator needs the organisation's opt-in policy.
    const noPolicy = await other.call(confirm, 'POST', body)
    expect(noPolicy.status).toBe(400)
    expect(((await noPolicy.json()) as { message: string }).message).toMatch(/automatically/)
    await owner.call(`/api/organizations/${id}/policies/18`, 'PUT', { enabled: true })
    expect((await json('/api/organizations/invite-link/status', join(id, link.code))).status).toBe(
      200,
    )
    expect((await other.call(confirm, 'POST', { ...body, orgUserKey: '' })).status).toBe(400)
    expect((await other.call(confirm, 'POST', body)).status).toBe(200)
    const profile = await other.json('/api/accounts/profile')
    expect(profile.organizations[0]).toMatchObject({ id, status: 2, key: '4.key' })

    // A member who only manages users cannot make the link self-confirming.
    const manager = await actor('jl-manager@example.com')
    await addMember(owner, id, manager, { type: 4, permissions: { manageUsers: true } })
    expect(
      (
        await manager.call(`${base}/support-confirm`, 'PUT', {
          invite: 'x',
          supportsConfirmation: true,
        })
      ).status,
    ).toBe(403)
    expect(
      (
        await manager.call(`${base}/support-confirm`, 'PUT', {
          invite: 'x',
          supportsConfirmation: false,
        })
      ).status,
    ).toBe(200)

    // Domain and revocation checks.
    await owner.json(base, 'PUT', { allowedDomains: ['example.org'] })
    const third = await actor('jl-third@example.com')
    const refused = await third.call(accept, 'POST', join(id, link.code))
    expect(refused.status).toBe(400)
    expect(((await refused.json()) as { message: string }).message).toMatch(/email domain/)
  })

  it('requires an account recovery key when the policy auto-enrols', async () => {
    const owner = await actor('jl-reset-owner@example.com')
    const { id } = await createOrg(owner, 'Recover')
    const link = await owner.json(`/api/organizations/${id}/invite-link`, 'POST', {
      allowedDomains: ['example.com'],
      invite: 'i',
    })
    await enableRecoveryPolicy(owner, id, true)
    const user = await actor('jl-reset-user@example.com')
    const path = '/api/organizations/users/invite-link/accept'
    expect((await user.call(path, 'POST', join(id, link.code))).status).toBe(400)
    expect(
      (await user.call(path, 'POST', join(id, link.code, { resetPasswordKey: '4.reset' }))).status,
    ).toBe(200)
  })

  it('refuses auto-confirmation for members of other organisations', async () => {
    const ownerA = await actor('jl-ac-a@example.com')
    const ownerB = await actor('jl-ac-b@example.com')
    const orgA = await createOrg(ownerA, 'A')
    const orgB = await createOrg(ownerB, 'B')
    await ownerB.call(`/api/organizations/${orgB.id}/policies/18`, 'PUT', { enabled: true })
    const link = await ownerB.json(`/api/organizations/${orgB.id}/invite-link`, 'POST', {
      allowedDomains: ['example.com'],
      invite: 'i',
      supportsConfirmation: true,
    })
    const user = await actor('jl-ac-user@example.com')
    await addMember(ownerA, orgA.id, user)
    const res = await user.call('/api/organizations/users/invite-link/confirm', 'POST', {
      organizationId: orgB.id,
      code: link.code,
      orgUserKey: '4.k',
    })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { message: string }).message).toMatch(
      /until they leave all other organization vaults/,
    )
  })
})

describe('PAM and self-revocation', () => {
  it('enables PAM for members (admins only) and shows it in member details', async () => {
    const owner = await actor('pam-owner@example.com')
    const user = await actor('pam-user@example.com')
    const { id } = await createOrg(owner)
    const ou = await addMember(owner, id, user)
    const mgr = await actor('pam-custom@example.com')
    await addMember(owner, id, mgr, { type: 4, permissions: { manageUsers: true } })
    const bad = await mgr.json(`/api/organizations/${id}/users/enable-pam`, 'PUT', { ids: [ou] })
    expect(bad.data[0].error).toBeTruthy()
    const res = await owner.json(`/api/organizations/${id}/users/enable-pam`, 'PUT', { ids: [ou] })
    expect(res.data).toEqual([expect.objectContaining({ id: ou, error: null })])
    expect((await owner.json(`/api/organizations/${id}/users/${ou}`)).accessPam).toBe(true)
    expect(
      (await user.call(`/api/organizations/${id}/users/enable-pam`, 'PUT', { ids: [ou] })).status,
    ).toBe(403)
  })

  it('lets a member revoke themselves but not the last owner', async () => {
    const owner = await actor('rs-owner@example.com')
    const user = await actor('rs-user@example.com')
    const { id } = await createOrg(owner)
    const ou = await addMember(owner, id, user)
    expect((await owner.call(`/api/organizations/${id}/users/revoke-self`, 'PUT')).status).toBe(400)
    expect((await user.call(`/api/organizations/${id}/users/revoke-self`, 'PUT')).status).toBe(200)
    expect((await owner.json(`/api/organizations/${id}/users/${ou}`)).status).toBe(-1)
    expect((await user.call(`/api/organizations/${id}/users/revoke-self`, 'PUT')).status).toBe(404)
  })
})
