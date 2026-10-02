import type { Context } from 'hono'
import { Hono } from 'hono'
import * as oauth from 'oauth4webapi'
import { randomB64u } from '../auth/crypto'
import { signPurposeToken, verifyPurposeToken } from '../auth/purpose-token'
import { createDb } from '../db'
import type { Env } from '../env'
import { ApiError } from '../errors'
import { errorKind, log } from '../log'
import { eventStatement } from '../orgs/events'
import { batch } from '../orgs/util'
import { rateLimit } from '../ratelimit'
import { activeSso, loadSsoConfig, orgByIdentifier, parseConfigData, SsoType } from '../sso/config'
import { SsoError } from '../sso/errors'
import {
  CLIENT_IDS,
  clientRedirect,
  createFlow,
  FLOW_TTL_MS,
  flowCookie,
  isS256Challenge,
  issueCode,
  LINK_PURPOSE,
  PREVALIDATE_PURPOSE,
  PREVALIDATE_TTL_SECONDS,
  provisionSsoUser,
  recordAssertion,
  redirectAllowed,
  type SsoIdentity,
  takeFlow,
} from '../sso/flow'
import { completeOidc, oidcAuthorizationUrl } from '../sso/oidc'
import { buildAuthnRequest, newRequestId, spMetadata, validateSamlResponse } from '../sso/saml'
import { ensureSpKeys, SsoEventType } from '../sso/sp-keys'
import { esc } from '../sso/xml'

/**
 * Browser-facing SSO endpoints (TASKS #280 to #282): prevalidation, the authorize endpoint the
 * clients open, and the service provider callbacks for OpenID Connect and SAML 2.0.
 */
export const sso = new Hono<Env>()

type Ctx = Context<Env>

const PAGE_CSP =
  "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

/** A small HTML page for errors and the signed-out callback. Inputs are escaped. */
function page(c: Ctx, title: string, message: string, status: 200 | 400 = 400) {
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><style>body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#1b2029;background:#f3f6f9}h1{font-size:1.25rem}</style></head><body><h1>${esc(title)}</h1><p>${esc(message)}</p></body></html>`
  return c.html(body, status, {
    'Content-Security-Policy': PAGE_CSP,
    'Cache-Control': 'no-store',
    'Set-Cookie': flowCookie('', 0),
  })
}

/** An auto-submitting form (SAML HTTP-POST binding towards the identity provider). */
function postForm(c: Ctx, url: string, fields: Record<string, string>, cookie: string) {
  const nonce = randomB64u(16)
  const inputs = Object.entries(fields)
    .map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`)
    .join('')
  const origin = new URL(url).origin
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Signing in</title></head><body><form id="f" method="post" action="${esc(url)}">${inputs}<noscript><button type="submit">Continue</button></noscript></form><script nonce="${nonce}">document.getElementById('f').submit()</script></body></html>`
  return c.html(body, 200, {
    'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; form-action ${origin}; frame-ancestors 'none'; base-uri 'none'`,
    'Cache-Control': 'no-store',
    'Set-Cookie': cookie,
  })
}

const fail = (c: Ctx, err: unknown) => {
  if (!(err instanceof SsoError)) throw err
  log('warn', 'sso.failed', { reason: err.message, errorKind: errorKind(err.cause) }, c.env)
  return page(c, 'Single sign-on failed', err.message)
}

// ----- 1. Prevalidation -----

sso.get('/identity/sso/prevalidate', rateLimit('sso'), async (c) => {
  const db = createDb(c.env.DB)
  const identifier = c.req.query('domainHint') ?? ''
  const org = await orgByIdentifier(db, identifier)
  if (!org || !(await activeSso(db, org.uuid))) {
    throw new ApiError(400, 'Organization not found or SSO configuration not enabled.')
  }
  const token = await signPurposeToken(
    c.env,
    PREVALIDATE_PURPOSE,
    { sub: org.uuid, email: '' },
    PREVALIDATE_TTL_SECONDS,
  )
  return c.json({ token, object: 'ssoPreValidate' })
})

// ----- 2. Authorize -----

sso.get('/identity/connect/authorize', rateLimit('sso'), async (c) => {
  const q = c.req.query()
  const clientId = q.client_id ?? ''
  const redirectUri = q.redirect_uri ?? ''
  // The redirect URI is checked before anything else, and errors never redirect, so this
  // endpoint cannot be used as an open redirect.
  if (!CLIENT_IDS.has(clientId) || !redirectAllowed(c.env, clientId, redirectUri)) {
    return page(c, 'Single sign-on failed', 'The client or its redirect address is not allowed.')
  }
  try {
    if (q.response_type !== 'code')
      throw new SsoError('Only the authorization code flow is supported.')
    if (!(q.scope ?? '').split(' ').includes('api'))
      throw new SsoError('The requested scope is not allowed.')
    if (q.code_challenge_method !== 'S256' || !isS256Challenge(q.code_challenge ?? '')) {
      throw new SsoError('A PKCE S256 code challenge is required.')
    }
    if (!q.state || q.state.length > 2048)
      throw new SsoError('The state parameter is missing or too long.')
    if (q.response_mode && q.response_mode !== 'query')
      throw new SsoError('Only the query response mode is supported.')

    const db = createDb(c.env.DB)
    const org = await orgByIdentifier(db, q.domain_hint ?? '')
    const cfg = org ? await activeSso(db, org.uuid) : null
    if (!org || !cfg)
      throw new SsoError('No organization with single sign-on was found for this identifier.')
    const pre = await verifyPurposeToken(c.env, PREVALIDATE_PURPOSE, q.ssoToken ?? '')
    if (!pre || pre.sub !== org.uuid)
      throw new SsoError('The sign-in request has expired. Start again.')

    let linkUserUuid: string | null = null
    if (q.user_identifier) {
      const link = await verifyPurposeToken(c.env, LINK_PURPOSE, q.user_identifier)
      if (!link) throw new SsoError('The account link request has expired.')
      linkUserUuid = link.sub
    }

    const isSaml = cfg.data.configType === SsoType.Saml2
    if (!isSaml && cfg.data.configType !== SsoType.OpenIdConnect) {
      throw new SsoError('Single sign-on is not configured for this organization.')
    }
    const nonce = isSaml ? null : oauth.generateRandomNonce()
    const idpCodeVerifier = isSaml ? null : oauth.generateRandomCodeVerifier()
    const samlRequestId = isSaml ? newRequestId() : null
    const { flow, cookie } = await createFlow(db, {
      organizationUuid: org.uuid,
      clientId,
      redirectUri,
      codeChallenge: q.code_challenge ?? '',
      clientState: q.state,
      nonce,
      idpCodeVerifier,
      samlRequestId,
      linkUserUuid,
    })
    const setCookie = flowCookie(cookie, FLOW_TTL_MS / 1000)

    if (isSaml) {
      const sp = await ensureSpKeys(db, cfg.row)
      const out = await buildAuthnRequest(
        c.env,
        org.uuid,
        cfg.data,
        sp,
        samlRequestId as string,
        flow.uuid,
      )
      if (out.binding === 'post') return postForm(c, out.url, out.fields, setCookie)
      return c.body(null, 302, {
        Location: out.url,
        'Set-Cookie': setCookie,
        'Cache-Control': 'no-store',
      })
    }
    const url = await oidcAuthorizationUrl(c.env, org.uuid, cfg.data, {
      state: flow.uuid,
      nonce: nonce as string,
      codeVerifier: idpCodeVerifier as string,
    })
    return c.body(null, 302, {
      Location: url.toString(),
      'Set-Cookie': setCookie,
      'Cache-Control': 'no-store',
    })
  } catch (err) {
    return fail(c, err)
  }
})

// ----- 3. Callbacks -----

async function finish(c: Ctx, flow: Awaited<ReturnType<typeof takeFlow>>, identity: SsoIdentity) {
  const db = createDb(c.env.DB)
  const { user, firstLogin } = await provisionSsoUser(
    db,
    flow.organizationUuid,
    identity,
    flow.linkUserUuid,
  )
  const code = await issueCode(db, flow, user.uuid)
  if (firstLogin) {
    await batch(db, [
      eventStatement(
        db,
        c,
        {
          type: SsoEventType.OrganizationUserFirstSsoLogin,
          organizationUuid: flow.organizationUuid,
          userUuid: user.uuid,
        },
        user.uuid,
      ),
    ])
  }
  return c.body(null, 302, {
    Location: clientRedirect(flow, code),
    'Set-Cookie': flowCookie('', 0),
    'Cache-Control': 'no-store',
  })
}

const oidcCallback = async (c: Ctx) => {
  try {
    const params =
      c.req.method === 'POST'
        ? new URLSearchParams(
            Object.entries(await c.req.parseBody()).filter(
              (e): e is [string, string] => typeof e[1] === 'string',
            ),
          )
        : new URL(c.req.url).searchParams
    const db = createDb(c.env.DB)
    const flow = await takeFlow(db, params.get('state') ?? '', c.req.header('Cookie'))
    const cfg = await activeSso(db, flow.organizationUuid)
    if (
      !cfg ||
      cfg.data.configType !== SsoType.OpenIdConnect ||
      !flow.nonce ||
      !flow.idpCodeVerifier
    ) {
      throw new SsoError('Single sign-on is no longer configured for this organization.')
    }
    const identity = await completeOidc(c.env, flow.organizationUuid, cfg.data, params, {
      state: flow.uuid,
      nonce: flow.nonce,
      codeVerifier: flow.idpCodeVerifier,
    })
    return await finish(c, flow, identity)
  } catch (err) {
    return fail(c, err)
  }
}
sso.get('/sso/oidc-signin', rateLimit('sso'), oidcCallback)
sso.post('/sso/oidc-signin', rateLimit('sso'), oidcCallback)

sso.get('/sso/oidc-signedout', (c) =>
  page(c, 'Signed out', 'You have been signed out. You can close this window.', 200),
)

sso.post('/sso/saml2/:orgId/Acs', rateLimit('sso'), async (c) => {
  try {
    const form = await c.req.parseBody()
    const samlResponse = typeof form.SAMLResponse === 'string' ? form.SAMLResponse : ''
    const relayState = typeof form.RelayState === 'string' ? form.RelayState : ''
    if (!samlResponse) throw new SsoError('No SAML response was received.')
    const db = createDb(c.env.DB)
    const flow = await takeFlow(db, relayState, c.req.header('Cookie'))
    if (flow.organizationUuid !== c.req.param('orgId') || !flow.samlRequestId) {
      throw new SsoError('The SAML response was sent to the wrong organization.')
    }
    const cfg = await activeSso(db, flow.organizationUuid)
    if (!cfg || cfg.data.configType !== SsoType.Saml2) {
      throw new SsoError('Single sign-on is no longer configured for this organization.')
    }
    const sp = await ensureSpKeys(db, cfg.row)
    const result = await validateSamlResponse(
      c.env,
      flow.organizationUuid,
      cfg.data,
      sp,
      samlResponse,
      {
        requestId: flow.samlRequestId,
        now: Date.now(),
      },
    )
    if (!(await recordAssertion(db, result.assertionKey, result.expiresAt))) {
      throw new SsoError('This SAML assertion was already used.')
    }
    return await finish(c, flow, result.identity)
  } catch (err) {
    return fail(c, err)
  }
})

/** Service provider metadata, for administrators to give their identity provider. */
sso.get('/sso/saml2/:orgId', async (c) => {
  const db = createDb(c.env.DB)
  const orgId = c.req.param('orgId')
  const row = await loadSsoConfig(db, orgId)
  if (!row) return page(c, 'Not found', 'This organization has no SSO configuration.')
  const sp = await ensureSpKeys(db, row)
  return c.body(spMetadata(c.env, orgId, parseConfigData(row), sp.certificateDer), 200, {
    'Content-Type': 'application/samlmetadata+xml; charset=utf-8',
    'Cache-Control': 'no-store',
  })
})
