import { beforeAll, describe, expect, it } from 'vitest'
import type { OidcIdp } from './oidc-idp'
import { actor, createOrg, linkParams, mailbox } from './org-helpers'
import { configureOidc, startIdp } from './sso-helpers'

// TASKS #349: the web client only accepts an invite link that carries `initOrganization` and
// `orgUserHasExistingUser`.
let n = 0
const unique = (p: string) => `${p}-${Date.now()}-${++n}`

const invite = (
  owner: Awaited<ReturnType<typeof actor>>,
  orgId: string,
  emails: string[],
  type = 2,
) => owner.call(`/api/organizations/${orgId}/users/invite`, 'POST', { emails, type })

describe('organization invite link', () => {
  it('flags a new address on a keyed organization', async () => {
    const mb = mailbox()
    const owner = await actor(`${unique('il-owner')}@example.com`, mb)
    const { id } = await createOrg(owner)
    const email = `${unique('il-new')}@example.com`
    expect((await invite(owner, id, [email])).status).toBe(200)
    const p = linkParams(mb.sent.at(-1))
    expect(p.get('initOrganization')).toBe('false')
    expect(p.get('orgUserHasExistingUser')).toBe('false')
    expect(p.has('orgSsoIdentifier')).toBe(false)
  })

  it('flags an existing account, in the invite and in a resend', async () => {
    const mb = mailbox()
    const owner = await actor(`${unique('il-owner')}@example.com`, mb)
    const member = await actor(`${unique('il-member')}@example.com`, mb)
    const { id } = await createOrg(owner)
    expect((await invite(owner, id, [member.email])).status).toBe(200)
    expect(linkParams(mb.sent.at(-1)).get('orgUserHasExistingUser')).toBe('true')
    const ouId = linkParams(mb.sent.at(-1)).get('organizationUserId')
    const before = mb.sent.length
    expect(
      (await owner.call(`/api/organizations/${id}/users/${ouId}/reinvite`, 'POST')).status,
    ).toBe(200)
    expect(mb.sent).toHaveLength(before + 1)
    const p = linkParams(mb.sent.at(-1))
    expect(p.get('orgUserHasExistingUser')).toBe('true')
    expect(p.get('initOrganization')).toBe('false')
  })

  it('flags initialisation only for an invited owner of a key-less organization', async () => {
    const mb = mailbox()
    const creator = await actor(`${unique('il-creator')}@example.com`, mb)
    const org = await creator.json('/api/organizations', 'POST', {
      name: 'NoKeys',
      billingEmail: 'billing@example.com',
      key: '4.k',
    })
    const ownerEmail = `${unique('il-o')}@example.com`
    const adminEmail = `${unique('il-a')}@example.com`
    expect((await invite(creator, org.id, [ownerEmail], 0)).status).toBe(200)
    const o = linkParams(mb.sent.at(-1))
    expect(o.get('initOrganization')).toBe('true')
    expect(o.get('orgUserHasExistingUser')).toBe('false')
    expect((await invite(creator, org.id, [adminEmail], 1)).status).toBe(200)
    expect(linkParams(mb.sent.at(-1)).get('initOrganization')).toBe('false')
  })

  describe('with required single sign-on', () => {
    let idp: OidcIdp
    beforeAll(async () => {
      idp = await startIdp()
    })

    it('adds the SSO identifier', async () => {
      const mb = mailbox()
      const owner = await actor(`${unique('il-sso')}@example.com`, mb)
      const { id } = await createOrg(owner)
      const identifier = unique('acme')
      await configureOidc(owner, id, identifier, idp)
      for (const t of [3, 4])
        expect(
          (
            await owner.call(`/api/organizations/${id}/policies/${t}`, 'PUT', {
              enabled: true,
              data: null,
            })
          ).status,
        ).toBe(200)
      expect((await invite(owner, id, [`${unique('il-s')}@example.com`])).status).toBe(200)
      expect(linkParams(mb.sent.at(-1)).get('orgSsoIdentifier')).toBe(identifier)
    })
  })
})
