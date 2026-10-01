import { Hono } from 'hono'
import type { Env } from '../env'

export const appId = new Hono<Env>()

// FIDO U2F facet list used by the web vault. Upstream serves this from its configured domain, so
// it is generated here rather than shipped as a static file.
appId.get('/app-id.json', (c) => {
  const origin = new URL(c.env.DOMAIN).origin
  return c.json({ trustedFacets: [{ version: { major: 1, minor: 0 }, ids: [origin] }] })
})
