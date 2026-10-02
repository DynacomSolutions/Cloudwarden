// Provider Portal routes (TASKS #231).
//
// Providers (managed service providers and resellers) are created by the cloud's billing team and
// do not exist on a self-hosted Cloudwarden server: the profile always reports `providers: []`.
// The clients therefore never hold a valid provider id. Lookups and writes answer 404 like an
// unknown id would, and the list endpoints answer an empty list so a stale link renders an empty
// page instead of an error.
import type { Context } from 'hono'
import { Hono } from 'hono'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { authOnce } from '../orgs/util'

export const providers = new Hono<Env>()

const notFound = (): never => {
  throw new ApiError(404, 'Provider not found.')
}
const emptyList = (c: Context<Env>) => c.json({ object: 'list', data: [], continuationToken: null })

const P = '/api/providers/:providerId'

for (const path of [
  `${P}/users`,
  `${P}/organizations`,
  `${P}/events`,
  `${P}/users/:id/events`,
  `${P}/clients/addable`,
]) {
  providers.get(path, authOnce, emptyList)
}

for (const [method, path] of [
  ['get', P],
  ['put', P],
  ['delete', P],
  ['post', `${P}/setup`],
  ['get', `${P}/billing/invoices`],
  ['get', `${P}/billing/invoices/:invoiceId`],
  ['get', `${P}/billing/subscription`],
  ['get', `${P}/billing/vnext/address`],
  ['put', `${P}/billing/vnext/address`],
  ['get', `${P}/billing/vnext/credit`],
  ['post', `${P}/billing/vnext/credit/bitpay`],
  ['get', `${P}/billing/vnext/payment-method`],
  ['put', `${P}/billing/vnext/payment-method`],
  ['post', `${P}/billing/vnext/payment-method/verify-bank-account`],
  ['post', `${P}/billing/vnext/subscription/restart`],
  ['post', `${P}/clients`],
  ['put', `${P}/clients/:orgId`],
  ['post', `${P}/clients/existing`],
  ['post', `${P}/organizations`],
  ['delete', `${P}/organizations/:id`],
  ['post', `${P}/organizations/add`],
  ['delete', `${P}/users`],
  ['get', `${P}/users/:id`],
  ['put', `${P}/users/:id`],
  ['delete', `${P}/users/:id`],
  ['post', `${P}/users/:id/accept`],
  ['post', `${P}/users/:id/confirm`],
  ['post', `${P}/users/:id/reinvite`],
  ['post', `${P}/users/confirm`],
  ['post', `${P}/users/invite`],
  ['post', `${P}/users/public-keys`],
  ['post', `${P}/users/reinvite`],
] as const) {
  providers[method](path, authOnce, notFound)
}
