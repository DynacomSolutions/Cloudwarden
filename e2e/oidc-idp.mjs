// A mock OpenID Connect provider for the end-to-end run (TASKS #288): discovery, an authorize
// endpoint that signs the configured user in without a page, a token endpoint with client
// authentication and PKCE, RS256 ID tokens and JWKS. Listens on 127.0.0.1 only.
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto'
import { createServer } from 'node:http'

const b64u = (buf) => Buffer.from(buf).toString('base64url')

export async function startOidcIdp({ clientId, clientSecret, user }) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'e2e-1', alg: 'RS256', use: 'sig' }
  const codes = new Map()
  let issuer = ''

  const json = (res, status, body) => {
    res.writeHead(status, { 'Content-Type': 'application/json' })
    res.end(JSON.stringify(body))
  }
  const readBody = (req) =>
    new Promise((ok) => {
      let data = ''
      req.on('data', (d) => {
        data += d
      })
      req.on('end', () => ok(new URLSearchParams(data)))
    })
  const idToken = (claims) => {
    const head = b64u(JSON.stringify({ alg: 'RS256', kid: 'e2e-1', typ: 'JWT' }))
    const body = b64u(JSON.stringify(claims))
    return `${head}.${body}.${b64u(sign('sha256', Buffer.from(`${head}.${body}`), privateKey))}`
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, issuer)
    if (url.pathname === '/.well-known/openid-configuration') {
      return json(res, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic'],
      })
    }
    if (url.pathname === '/jwks') return json(res, 200, { keys: [jwk] })
    if (url.pathname === '/authorize') {
      const q = url.searchParams
      if (q.get('client_id') !== clientId) return json(res, 400, { error: 'invalid_client' })
      const code = b64u(randomBytes(16))
      codes.set(code, {
        redirectUri: q.get('redirect_uri'),
        nonce: q.get('nonce'),
        challenge: q.get('code_challenge'),
      })
      const back = new URL(q.get('redirect_uri'))
      back.searchParams.set('code', code)
      back.searchParams.set('state', q.get('state') ?? '')
      res.writeHead(302, { Location: back.toString() })
      return res.end()
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      const form = await readBody(req)
      const [id, secret] = Buffer.from(
        (req.headers.authorization ?? '').replace(/^Basic /, ''),
        'base64',
      )
        .toString()
        .split(':')
        .map(decodeURIComponent)
      if (id !== clientId || secret !== clientSecret)
        return json(res, 401, { error: 'invalid_client' })
      const pending = codes.get(form.get('code'))
      codes.delete(form.get('code'))
      const verifier = form.get('code_verifier') ?? ''
      if (
        !pending ||
        pending.redirectUri !== form.get('redirect_uri') ||
        b64u(createHash('sha256').update(verifier).digest()) !== pending.challenge
      ) {
        return json(res, 400, { error: 'invalid_grant' })
      }
      const now = Math.floor(Date.now() / 1000)
      return json(res, 200, {
        access_token: b64u(randomBytes(16)),
        token_type: 'Bearer',
        expires_in: 300,
        id_token: idToken({
          iss: issuer,
          aud: clientId,
          iat: now,
          exp: now + 300,
          nonce: pending.nonce,
          ...user,
        }),
      })
    }
    json(res, 404, { error: 'not_found' })
  })
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok))
  issuer = `http://127.0.0.1:${server.address().port}`
  return { issuer, close: () => new Promise((ok) => server.close(ok)) }
}
