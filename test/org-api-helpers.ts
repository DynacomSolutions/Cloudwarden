import { env } from 'cloudflare:workers'
import { BASE } from './helpers'
import { type Actor, mail } from './org-helpers'

/** Calls the app with arbitrary headers (organisation tokens, SCIM keys). */
export async function raw(
  path: string,
  init: { method?: string; headers?: Record<string, string>; body?: unknown } = {},
) {
  const { default: app } = await import('../src/index')
  const hasBody = init.body !== undefined
  return app.fetch(
    new Request(`${BASE}${path}`, {
      method: init.method ?? 'GET',
      headers: {
        ...(hasBody ? { 'Content-Type': 'application/json' } : {}),
        ...init.headers,
      },
      ...(hasBody
        ? { body: typeof init.body === 'string' ? init.body : JSON.stringify(init.body) }
        : {}),
    }),
    { ...env, EMAIL: mail.EMAIL, MAIL_FROM: mail.MAIL_FROM },
  )
}

export const bearer = (token: string) => ({ Authorization: `Bearer ${token}` })

/** The organisation's Public API key (created on first call). */
export async function orgApiKey(owner: Actor, orgId: string, type = 0, rotate = false) {
  const res = await owner.call(
    `/api/organizations/${orgId}/${rotate ? 'rotate-api-key' : 'api-key'}`,
    'POST',
    { masterPasswordHash: 'client-derived-hash', type },
  )
  if (res.status !== 200) throw new Error(`api key failed: ${res.status}`)
  return ((await res.json()) as { apiKey: string }).apiKey
}

export async function orgToken(orgId: string, secret: string) {
  const res = await raw('/identity/connect/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api.organization',
      client_id: `organization.${orgId}`,
      client_secret: secret,
      deviceType: '21',
      deviceIdentifier: 'dc-device',
      deviceName: 'Directory Connector',
    }).toString(),
  })
  return { status: res.status, body: (await res.json()) as Record<string, any> }
}
