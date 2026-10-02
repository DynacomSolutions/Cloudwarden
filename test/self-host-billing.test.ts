import { SELF } from 'cloudflare:test'
import { describe, expect, it } from 'vitest'
import { BASE } from './helpers'
import { actor, addMember, createOrg } from './org-helpers'

const NO_BILLING = /Billing is not available on this self-hosted Cloudwarden server/

describe('account billing', () => {
  it('reports premium without a subscription and empty history', async () => {
    const a = await actor('bill-account@example.com')
    expect(await a.json('/api/accounts/subscription')).toMatchObject({
      object: 'subscription',
      storageGb: 0,
      subscription: null,
      license: null,
      expiration: null,
    })
    expect(await a.json('/api/accounts/billing/history')).toEqual({
      object: 'billingHistory',
      invoices: [],
      transactions: [],
    })
    expect(await a.json('/api/accounts/billing/invoices')).toEqual([])
    expect(await a.json('/api/accounts/billing/transactions')).toEqual([])
    expect(await a.json('/api/account/billing/vnext/address')).toBeNull()
    expect(await a.json('/api/account/billing/vnext/credit')).toBe(0)
    expect(await a.json('/api/account/billing/vnext/discounts')).toEqual([])
    expect(await a.json('/api/account/billing/vnext/payment-method')).toBeNull()
    expect((await a.call('/api/account/billing/vnext/subscription')).status).toBe(404)
    expect((await a.call('/api/account/billing/subscription/preview')).status).toBe(404)
  })

  it('honours premium purchase and licence upload, rejects paid changes', async () => {
    const a = await actor('bill-premium@example.com')
    const prem = await a.json('/api/accounts/premium', 'POST', {})
    expect(prem).toMatchObject({ success: true, paymentIntentClientSecret: null })
    expect(prem.userProfile).toMatchObject({ id: a.uuid, premium: true })
    expect((await a.call('/api/accounts/license', 'POST', {})).status).toBe(200)

    for (const [path, method] of [
      ['/api/accounts/cancel', 'POST'],
      ['/api/account/billing/vnext/payment-method', 'PUT'],
      ['/api/account/billing/vnext/premium/checkout', 'POST'],
      ['/api/account/billing/vnext/subscription/storage', 'PUT'],
      ['/api/billing/preview-invoice/premium/subscriptions/purchase', 'POST'],
      ['/api/setup-intent/card', 'POST'],
      ['/api/bitpay-invoice', 'POST'],
    ] as const) {
      const res = await a.call(path, method, {})
      expect(res.status, path).toBe(400)
      expect(((await res.json()) as { message: string }).message).toMatch(NO_BILLING)
    }
    expect((await a.call('/api/account/billing/vnext/license')).status).toBe(400)
  })

  it('needs authentication', async () => {
    for (const path of ['/api/accounts/subscription', '/api/plans', '/api/providers/x/users']) {
      expect((await SELF.fetch(`${BASE}${path}`)).status, path).toBe(401)
    }
  })
})

describe('plans', () => {
  it('lists the self-hosted plan and a free premium plan', async () => {
    const a = await actor('bill-plans@example.com')
    const plans = await a.json('/api/plans')
    expect(plans.data).toHaveLength(1)
    expect(plans.data[0]).toMatchObject({ type: 0, usersGetPremium: true, hasSelfHost: true })
    const premium = await a.json('/api/plans/premium')
    expect(premium.seat).toMatchObject({ price: 0, provided: 1 })
    expect(typeof premium.storage.stripePriceId).toBe('string')
  })
})

describe('organisation billing', () => {
  it('answers owners with no subscription and rejects paid changes', async () => {
    const owner = await actor('bill-org-owner@example.com')
    const { id } = await createOrg(owner)
    expect(await owner.json(`/api/organizations/${id}/billing`)).toMatchObject({
      balance: 0,
      paymentSource: null,
    })
    expect(await owner.json(`/api/organizations/${id}/billing/history`)).toMatchObject({
      invoices: [],
      transactions: [],
    })
    expect(await owner.json(`/api/organizations/${id}/billing/invoices`)).toEqual([])
    expect(await owner.json(`/api/organizations/${id}/billing/vnext/credit`)).toBe(0)
    expect(await owner.json(`/api/organizations/${id}/billing/vnext/payment-method`)).toBeNull()
    expect(
      await owner.json(`/api/organizations/${id}/billing/vnext/churn-mitigation-offer`),
    ).toBeNull()
    expect(await owner.json(`/api/organizations/${id}/billing/vnext/warnings`)).toMatchObject({
      freeTrial: null,
      inactiveSubscription: null,
    })
    expect(await owner.json(`/api/organizations/${id}/billing/vnext/metadata`)).toEqual({
      object: 'organizationBillingMetadata',
      isOnSecretsManagerStandalone: false,
      organizationOccupiedSeats: 1,
    })
    const sub = await owner.json(`/api/organizations/${id}/subscription`)
    expect(sub).toMatchObject({
      id,
      plan: { type: 0, name: 'Self-hosted' },
      subscription: null,
      expiration: null,
    })
    const sm = await owner.json(`/api/organizations/${id}/subscribe-secrets-manager`, 'POST', {})
    expect(sm).toMatchObject({ id, useSecretsManager: true, object: 'profileOrganization' })

    for (const path of ['seat', 'storage', 'upgrade', 'reinstate', 'cancel']) {
      const res = await owner.call(`/api/organizations/${id}/${path}`, 'POST', {})
      expect(res.status, path).toBe(400)
    }
    expect((await owner.call(`/api/organizations/${id}/license`)).status).toBe(400)
    expect((await owner.call('/api/organizations/licenses/self-hosted', 'POST', {})).status).toBe(
      400,
    )
  })

  it('refuses members who are not owners and unknown organisations', async () => {
    const owner = await actor('bill-org-owner2@example.com')
    const user = await actor('bill-org-user@example.com')
    const { id } = await createOrg(owner)
    await addMember(owner, id, user)
    expect((await user.call(`/api/organizations/${id}/billing`)).status).toBe(403)
    expect((await user.call(`/api/organizations/${id}/subscription`)).status).toBe(403)
    expect((await user.call(`/api/organizations/${id}/seat`, 'POST', {})).status).toBe(403)
    expect((await user.call(`/api/organizations/${id}/billing/vnext/warnings`)).status).toBe(200)
    const stranger = await actor('bill-org-stranger@example.com')
    expect(
      (await stranger.call(`/api/organizations/${id}/billing/vnext/warnings`)).status,
    ).not.toBe(200)
    expect(
      (await owner.call('/api/organizations/00000000-0000-0000-0000-000000000000/billing')).status,
    ).toBe(404)
  })
})

describe('sponsorships', () => {
  it('lists none and rejects offers', async () => {
    const owner = await actor('bill-sponsor@example.com')
    const { id } = await createOrg(owner)
    expect((await owner.json(`/api/organization/sponsorship/${id}/sponsored`)).data).toEqual([])
    expect(
      (await owner.json(`/api/organization/sponsorship/self-hosted/${id}/sponsored`)).data,
    ).toEqual([])
    expect(await owner.json(`/api/organization/sponsorship/${id}/sync-status`)).toMatchObject({
      lastSyncDate: null,
    })
    expect(
      await owner.json('/api/organization/sponsorship/validate-token?sponsorshipToken=x', 'POST'),
    ).toMatchObject({ isTokenValid: false })
    const res = await owner.call(
      `/api/organization/sponsorship/self-hosted/${id}/families-for-enterprise`,
      'POST',
      { sponsoredEmail: 'friend@example.com', friendlyName: 'Friend' },
    )
    expect(res.status).toBe(400)
    expect((await owner.call('/api/organization/sponsorship/redeem', 'POST', {})).status).toBe(400)
  })
})

describe('providers', () => {
  it('has no providers: lookups 404, lists are empty', async () => {
    const a = await actor('bill-provider@example.com')
    const pid = '00000000-0000-0000-0000-000000000000'
    expect((await a.call(`/api/providers/${pid}`)).status).toBe(404)
    expect((await a.call(`/api/providers/${pid}/billing/subscription`)).status).toBe(404)
    expect((await a.call(`/api/providers/${pid}/users/invite`, 'POST', {})).status).toBe(404)
    expect((await a.json(`/api/providers/${pid}/users`)).data).toEqual([])
    expect((await a.json(`/api/providers/${pid}/organizations`)).data).toEqual([])
    expect((await a.json(`/api/providers/${pid}/events`)).data).toEqual([])
  })
})
