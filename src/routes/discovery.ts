import { Hono } from 'hono'
import { jwks } from '../auth/access-keys'
import { issuerFor } from '../auth/middleware'
import type { Env } from '../env'

/**
 * OpenID discovery for the identity service (TASKS #285): lets services such as a Key Connector
 * find the issuer and the keys that sign Cloudwarden access tokens.
 */
export const discovery = new Hono<Env>()

const doc = (c: import('hono').Context<Env>) => {
  const base = c.env.DOMAIN.replace(/\/+$/, '')
  const identity = `${base}/identity`
  return c.json({
    issuer: issuerFor(c.env.DOMAIN),
    jwks_uri: `${identity}/.well-known/openid-configuration/jwks`,
    authorization_endpoint: `${identity}/connect/authorize`,
    token_endpoint: `${identity}/connect/token`,
    response_types_supported: ['code'],
    grant_types_supported: [
      'authorization_code',
      'client_credentials',
      'refresh_token',
      'password',
      'webauthn',
    ],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['ES256'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['api', 'offline_access'],
  })
}
discovery.get('/identity/.well-known/openid-configuration', doc)
discovery.get('/identity/.well-known/openid-configuration/jwks', async (c) =>
  c.json(await jwks(c.env)),
)
