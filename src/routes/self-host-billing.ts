// Billing, plans, licences and sponsorships for a self-hosted server (TASKS #231).
//
// Cloudwarden has no payment provider: every organisation behaves like a self-hosted enterprise
// one with every feature (see `orgs/views.ts`) and every user has premium (see `profileJson`).
// The official clients still call the billing API from settings, the Admin Console and the
// premium pages, so reads answer what a server without a subscription answers (no payment method,
// zero credit, no invoices, no sponsorships) in the response models the clients deserialise, and
// mutations that would need a payment provider or the cloud licensing service fail with a 400
// whose message the clients show in a toast. Requests that can be honoured locally succeed.
import { and, eq, isNotNull, sum } from 'drizzle-orm'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { createDb, type Db, schema } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { requireMember, requireOrg, requireOwner } from '../orgs/access'
import { authOnce } from '../orgs/util'
import { orgJson, profileOrgJson } from '../orgs/views'
import { profileJson } from './accounts'

export const selfHostBilling = new Hono<Env>()

type Ctx = Context<Env>

export const NO_BILLING_MESSAGE =
  'Billing is not available on this self-hosted Cloudwarden server. Every organisation has every feature and every account has premium, at no cost.'
const NO_LICENCE_MESSAGE =
  'Licence files are not used by this self-hosted Cloudwarden server. Every organisation has every feature and every account has premium; create organisations directly.'
const NO_SPONSORSHIP_MESSAGE =
  'Families sponsorships are not available on this self-hosted Cloudwarden server. Every account already has premium.'

const noBilling = (): never => {
  throw new ApiError(400, NO_BILLING_MESSAGE)
}
const noLicence = (): never => {
  throw new ApiError(400, NO_LICENCE_MESSAGE)
}
const noSponsorship = (): never => {
  throw new ApiError(400, NO_SPONSORSHIP_MESSAGE)
}

const emptyList = { object: 'list', data: [], continuationToken: null }

/** The single plan this server offers: free, self-hosted, every feature (`PlanResponse`). */
export const SELF_HOST_PLAN = {
  object: 'plan',
  type: 0,
  productTier: 3,
  name: 'Self-hosted',
  isAnnual: true,
  nameLocalizationKey: 'planNameEnterprise',
  descriptionLocalizationKey: 'planDescEnterprise',
  canBeUsedByBusiness: true,
  trialPeriodDays: null,
  hasSelfHost: true,
  hasPolicies: true,
  hasMyItems: false,
  hasInviteLinks: true,
  hasGroups: true,
  hasDirectory: false,
  hasEvents: true,
  hasTotp: true,
  hasApi: false,
  hasSso: false,
  hasResetPassword: false,
  usersGetPremium: true,
  upgradeSortOrder: 0,
  displaySortOrder: 0,
  legacyYear: null,
  disabled: false,
  passwordManager: {
    stripePlanId: null,
    stripeSeatPlanId: null,
    stripeStoragePlanId: null,
    stripePremiumAccessPlanId: null,
    basePrice: 0,
    seatPrice: 0,
    providerPortalSeatPrice: 0,
    baseSeats: 0,
    maxAdditionalSeats: null,
    premiumAccessOptionPrice: 0,
    maxSeats: null,
    additionalStoragePricePerGb: 0,
    hasAdditionalSeatsOption: false,
    baseStorageGb: null,
    maxCollections: null,
    hasAdditionalStorageOption: false,
    maxAdditionalStorage: null,
    hasPremiumAccessOption: false,
  },
  secretsManager: {
    stripeSeatPlanId: null,
    baseSeats: 0,
    basePrice: 0,
    seatPrice: 0,
    hasAdditionalSeatsOption: false,
    maxAdditionalSeats: null,
    maxSeats: null,
    stripeServiceAccountPlanId: null,
    baseServiceAccount: null,
    maxServiceAccount: null,
    maxAdditionalServiceAccounts: null,
    maxProjects: null,
  },
}

const GB = 1024 ** 3

function readableSize(bytes: number): string {
  const units = ['Bytes', 'KB', 'MB', 'GB', 'TB']
  let size = bytes
  let i = 0
  while (size >= 1024 && i < units.length - 1) {
    size /= 1024
    i++
  }
  return `${i === 0 ? size : size.toFixed(2)} ${units[i]}`
}

/** Attachment bytes owned by a user or an organisation. */
async function attachmentBytes(db: Db, by: { user: string } | { orgUuid: string }) {
  const where =
    'user' in by
      ? eq(schema.ciphers.userUuid, by.user)
      : eq(schema.ciphers.organizationUuid, by.orgUuid)
  const [row] = await db
    .select({ total: sum(schema.attachments.fileSize) })
    .from(schema.attachments)
    .innerJoin(schema.ciphers, eq(schema.attachments.cipherUuid, schema.ciphers.uuid))
    .where(and(where, isNotNull(schema.attachments.fileSize)))
  return Number(row?.total ?? 0)
}

const storageJson = (bytes: number) => ({
  storageName: bytes > 0 ? readableSize(bytes) : null,
  storageGb: Math.round((bytes / GB) * 100) / 100,
})

const orgParam = (c: Ctx) => c.req.param('orgId') ?? c.req.param('id') ?? ''

/** Billing pages are for owners: `canViewSubscription`, `canEditPaymentMethods` and
 * `canViewBillingHistory` in the client all reduce to owner when there is no provider. */
const owner = async (c: Ctx) => {
  const db = createDb(c.env.DB)
  const orgUuid = orgParam(c)
  await requireOrg(db, orgUuid)
  return { db, orgUuid, member: await requireOwner(db, c.var.user.uuid, orgUuid) }
}
const member = async (c: Ctx) => {
  const db = createDb(c.env.DB)
  const orgUuid = orgParam(c)
  await requireOrg(db, orgUuid)
  return { db, orgUuid, member: await requireMember(db, c.var.user.uuid, orgUuid) }
}

const r = selfHostBilling

// ----- plans -----

r.get('/api/plans', authOnce, (c) => c.json({ ...emptyList, data: [SELF_HOST_PLAN] }))

// Premium is included: price 0 with one seat. `Provided` storage is the allowance the premium
// pages describe; this server has no storage quota beyond the per-file upload limit.
r.get('/api/plans/premium', authOnce, (c) =>
  c.json({
    object: 'premiumPlan',
    name: 'Premium',
    available: true,
    legacyYear: null,
    seat: { stripePriceId: 'premium-self-hosted', price: 0, provided: 1 },
    storage: { stripePriceId: 'storage-gb-self-hosted', price: 0, provided: 1 },
  }),
)

// ----- account (premium) -----

// `SubscriptionResponse`: premium without a subscription, licence or expiry.
r.get('/api/accounts/subscription', authOnce, async (c) => {
  const bytes = await attachmentBytes(createDb(c.env.DB), { user: c.var.user.uuid })
  return c.json({
    object: 'subscription',
    ...storageJson(bytes),
    maxStorageGb: null,
    subscription: null,
    upcomingInvoice: null,
    customerDiscount: null,
    license: null,
    expiration: null,
  })
})

// Buying premium succeeds without payment: the account already has it (`PaymentResponse`).
r.post('/api/accounts/premium', authOnce, async (c) =>
  c.json({
    object: 'payment',
    userProfile: await profileJson(c, c.var.user),
    paymentIntentClientSecret: null,
    success: true,
  }),
)

// A premium licence file changes nothing: premium is always on. Accept it so the self-hosted
// "Update licence" dialog completes.
r.post('/api/accounts/license', authOnce, (c) => c.body(null, 200))

r.post('/api/accounts/cancel', authOnce, noBilling)

r.get('/api/accounts/billing/history', authOnce, (c) =>
  c.json({ object: 'billingHistory', invoices: [], transactions: [] }),
)
r.get('/api/accounts/billing/invoices', authOnce, (c) => c.json([]))
r.get('/api/accounts/billing/transactions', authOnce, (c) => c.json([]))

// ----- account billing vnext -----

const ACCOUNT_VNEXT = '/api/account/billing/vnext'
r.get(`${ACCOUNT_VNEXT}/address`, authOnce, (c) => c.json(null))
r.get(`${ACCOUNT_VNEXT}/credit`, authOnce, (c) => c.json(0))
r.get(`${ACCOUNT_VNEXT}/discounts`, authOnce, (c) => c.json([]))
r.get(`${ACCOUNT_VNEXT}/payment-method`, authOnce, (c) => c.json(null))
// No subscription: the client maps 404 to "none".
r.get(`${ACCOUNT_VNEXT}/subscription`, authOnce, () => {
  throw new ApiError(404, 'No subscription.')
})
// Premium licences are issued by the cloud for installing on a self-hosted server.
r.get(`${ACCOUNT_VNEXT}/license`, authOnce, noLicence)
for (const [method, path] of [
  ['put', 'address'],
  ['post', 'credit/bitpay'],
  ['put', 'payment-method'],
  ['post', 'payment-method/verify-bank-account'],
  ['post', 'portal-session'],
  ['post', 'premium/checkout'],
  ['post', 'subscription'],
  ['post', 'subscription/reinstate'],
  ['post', 'subscription/restart'],
  ['put', 'subscription/storage'],
  ['post', 'upgrade'],
] as const) {
  r[method](`${ACCOUNT_VNEXT}/${path}`, authOnce, noBilling)
}

// The preview-driven cart answers 404 when there is no subscription to preview.
r.get('/api/account/billing/subscription/preview', authOnce, () => {
  throw new ApiError(404, 'No subscription.')
})
for (const path of [
  '/api/account/billing/subscriptions/organizations/invoice/preview',
  '/api/account/billing/subscriptions/premium/invoice/preview',
  '/api/account/billing/subscriptions/premium/upgrade/invoice/preview',
  '/api/billing/preview-invoice/organizations/subscriptions/purchase',
  '/api/billing/preview-invoice/premium/subscriptions/purchase',
  '/api/billing/preview-invoice/premium/subscriptions/upgrade',
  '/api/bitpay-invoice',
  '/api/setup-intent/bank-account',
  '/api/setup-intent/card',
  '/api/setup-payment',
]) {
  r.post(path, authOnce, noBilling)
}

// ----- organisation billing -----

for (const path of [
  '/api/billing/preview-invoice/organizations/:orgId/subscription/plan-change',
  '/api/billing/preview-invoice/organizations/:orgId/subscription/update',
]) {
  r.post(path, authOnce, async (c) => {
    await owner(c)
    return noBilling()
  })
}

// `BillingResponse`: no balance, no payment source.
r.get('/api/organizations/:id/billing', authOnce, async (c) => {
  await owner(c)
  return c.json({ object: 'billing', balance: 0, paymentSource: null })
})
r.get('/api/organizations/:id/billing/history', authOnce, async (c) => {
  await owner(c)
  return c.json({ object: 'billingHistory', invoices: [], transactions: [] })
})
for (const path of [
  '/api/organizations/:id/billing/invoices',
  '/api/organizations/:id/billing/transactions',
]) {
  r.get(path, authOnce, async (c) => {
    await owner(c)
    return c.json([])
  })
}
r.get('/api/organizations/:orgId/billing/subscription/preview', authOnce, async (c) => {
  await owner(c)
  throw new ApiError(404, 'No subscription.')
})

const ORG_VNEXT = '/api/organizations/:orgId/billing/vnext'
r.get(`${ORG_VNEXT}/address`, authOnce, async (c) => {
  await owner(c)
  return c.json(null)
})
r.get(`${ORG_VNEXT}/credit`, authOnce, async (c) => {
  await owner(c)
  return c.json(0)
})
r.get(`${ORG_VNEXT}/payment-method`, authOnce, async (c) => {
  await owner(c)
  return c.json(null)
})
// No free trial, no inactive subscription, no renewal, no price increase, no tax ID problem.
r.get(`${ORG_VNEXT}/warnings`, authOnce, async (c) => {
  await member(c)
  return c.json({
    object: 'organizationWarnings',
    freeTrial: null,
    inactiveSubscription: null,
    resellerRenewal: null,
    scheduledPriceIncrease: null,
    taxId: null,
  })
})
// The clients read `null` as "no offer".
for (const path of ['annual-upgrade-offer', 'churn-mitigation-offer']) {
  r.get(`${ORG_VNEXT}/${path}`, authOnce, async (c) => {
    await owner(c)
    return c.json(null)
  })
}

for (const [method, path] of [
  ['post', `${ORG_VNEXT}/annual-upgrade-offer/redeem`],
  ['post', `${ORG_VNEXT}/churn-mitigation-offer/redeem`],
  ['put', `${ORG_VNEXT}/address`],
  ['post', `${ORG_VNEXT}/credit/bitpay`],
  ['put', `${ORG_VNEXT}/payment-method`],
  ['post', `${ORG_VNEXT}/payment-method/verify-bank-account`],
  ['post', `${ORG_VNEXT}/subscription/restart`],
  ['post', '/api/organizations/:orgId/billing/change-frequency'],
  ['post', '/api/organizations/:orgId/billing/restart-subscription'],
  ['post', '/api/organizations/:orgId/billing/subscription/plan-change/invoice/preview'],
  ['post', '/api/organizations/:id/billing/setup-business-unit'],
  ['post', '/api/organizations/:orgId/cancel'],
  ['post', '/api/organizations/:id/reinstate'],
  ['post', '/api/organizations/:id/seat'],
  ['post', '/api/organizations/:id/storage'],
  ['post', '/api/organizations/:id/upgrade'],
  ['post', '/api/organizations/:id/subscription'],
  ['post', '/api/organizations/:id/sm-subscription'],
] as const) {
  r[method](path, authOnce, async (c) => {
    await owner(c)
    return noBilling()
  })
}

// `OrganizationSubscriptionResponse`: the organisation, its plan and storage, no subscription and
// no licence expiry.
r.get('/api/organizations/:id/subscription', authOnce, async (c) => {
  const { db, orgUuid } = await owner(c)
  const org = await requireOrg(db, orgUuid)
  const bytes = await attachmentBytes(db, { orgUuid })
  return c.json({
    ...orgJson(org),
    object: 'organizationSubscription',
    plan: SELF_HOST_PLAN,
    ...storageJson(bytes),
    subscription: null,
    upcomingInvoice: null,
    customerDiscount: null,
    expiration: null,
    expirationWithoutGracePeriod: null,
    exemptFromBillingAutomation: true,
  })
})

// Secrets Manager is already enabled for every organisation (`useSecretsManager`), so subscribing
// succeeds without a charge and returns the caller's `ProfileOrganizationResponse`.
r.post('/api/organizations/:id/subscribe-secrets-manager', authOnce, async (c) => {
  const { db, orgUuid, member: m } = await owner(c)
  return c.json(profileOrgJson(await requireOrg(db, orgUuid), m))
})

// Organisation licences come from the cloud for installing on a self-hosted server.
r.get('/api/organizations/:id/license', authOnce, async (c) => {
  await owner(c)
  return noLicence()
})
r.post('/api/organizations/licenses/self-hosted', authOnce, noLicence)
for (const path of [
  '/api/organizations/licenses/self-hosted/:id',
  '/api/organizations/licenses/self-hosted/:id/sync/',
]) {
  r.post(path, authOnce, async (c) => {
    await owner(c)
    return noLicence()
  })
}

// ----- families sponsorships -----

const SPONSOR = '/api/organization/sponsorship'
for (const path of [`${SPONSOR}/:orgId/sponsored`, `${SPONSOR}/self-hosted/:orgId/sponsored`]) {
  r.get(path, authOnce, async (c) => {
    await member(c)
    return c.json(emptyList)
  })
}
// Never synchronised with the cloud.
r.get(`${SPONSOR}/:orgId/sync-status`, authOnce, async (c) => {
  await owner(c)
  return c.json({ object: 'organizationSponsorshipSyncStatus', lastSyncDate: null })
})
// No sponsorship token can be valid: this server never issues them.
r.post(`${SPONSOR}/validate-token`, authOnce, (c) =>
  c.json({
    object: 'preValidateSponsorship',
    isTokenValid: false,
    isFreeFamilyPolicyEnabled: false,
  }),
)
r.post(`${SPONSOR}/redeem`, authOnce, noSponsorship)
for (const [method, path] of [
  ['delete', `${SPONSOR}/:orgId`],
  ['delete', `${SPONSOR}/:orgId/:sponsoredFriendlyName/revoke`],
  ['post', `${SPONSOR}/:orgId/families-for-enterprise`],
  ['post', `${SPONSOR}/:orgId/families-for-enterprise/resend`],
  ['delete', `${SPONSOR}/self-hosted/:orgId`],
  ['delete', `${SPONSOR}/self-hosted/:orgId/:sponsoredFriendlyName/revoke`],
  ['post', `${SPONSOR}/self-hosted/:orgId/families-for-enterprise`],
  ['delete', `${SPONSOR}/sponsored/:orgId`],
] as const) {
  r[method](path, authOnce, async (c) => {
    await member(c)
    return noSponsorship()
  })
}
