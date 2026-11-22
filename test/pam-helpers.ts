import { env } from 'cloudflare:workers'
import { BASE } from './helpers'
import { raw } from './org-api-helpers'
import { type Actor, createOrg, loginCipher } from './org-helpers'

export const rot = (orgId: string, path = '') =>
  `/api/organizations/${orgId}/access-connectors/rotation${path}`

/** Registers a connector, signs it in and returns a caller for the connector-facing routes. */
export async function connectorFor(owner: Actor, orgId: string, name = 'daemon') {
  const reg = await owner.json(`/api/organizations/${orgId}/access-connectors`, 'POST', {
    name,
    encryptedPayload: '2.orgKeyForConnector',
    key: '2.connectorKey',
  })
  const login = await raw('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api.access-connector',
      client_id: `access-connector.${reg.apiKeyId}`,
      client_secret: reg.clientSecret,
    }).toString(),
  })
  const tok = (await login.json()) as Record<string, any>
  const call = (path: string, method = 'GET', body?: unknown) =>
    raw(`/api/access-connectors/rotation${path}`, {
      method,
      headers: { Authorization: `Bearer ${tok.access_token}` },
      body,
    })
  return { reg, login, tok, call }
}

export async function orgWithLogin(owner: Actor, name = 'Acme') {
  const org = await createOrg(owner, name)
  const cipher = await owner.json('/api/ciphers/create', 'POST', {
    cipher: loginCipher('2.vpn', { organizationId: org.id }),
    collectionIds: [org.defaultCollectionId],
  })
  return { ...org, cipherId: cipher.id as string }
}

export const sql = (q: string, ...args: unknown[]) =>
  env.DB.prepare(q)
    .bind(...args)
    .all<any>()
export { BASE }
