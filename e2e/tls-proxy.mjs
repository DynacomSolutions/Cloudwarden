// The official CLI refuses non-HTTPS server URLs (a hard-coded production build check), so the
// local dev server is fronted by a throwaway TLS proxy (own throwaway CA) that the CLI trusts through
// NODE_EXTRA_CA_CERTS (or SSL_CERT_FILE for `bws`).
import { spawnSync } from 'node:child_process'
import { readFileSync, writeFileSync } from 'node:fs'
import { request } from 'node:http'
import { createServer } from 'node:https'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * Creates a throwaway CA and a server certificate for 127.0.0.1 signed by it. Clients trust `ca`
 * (NODE_EXTRA_CA_CERTS, SSL_CERT_FILE); rustls-based clients such as `bws` reject a self-signed
 * certificate that is also the trust anchor ("CA used as end entity"), hence two certificates.
 */
export function makeCert(dir) {
  const key = join(dir, 'key.pem')
  const cert = join(dir, 'cert.pem')
  const ca = join(dir, 'ca.pem')
  const caKey = join(dir, 'ca-key.pem')
  const csr = join(dir, 'server.csr')
  const ext = join(dir, 'server.ext')
  writeFileSync(
    ext,
    'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n',
  )
  const openssl = (...args) => {
    const res = spawnSync('openssl', args, { encoding: 'utf8' })
    if (res.status !== 0) throw new Error(`openssl ${args[0]} failed: ${res.stderr}`)
  }
  openssl(
    ...['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', caKey, '-out', ca],
    ...['-days', '1', '-subj', '/CN=Cloudwarden e2e CA'],
  )
  openssl(
    ...['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr],
    ...['-subj', '/CN=127.0.0.1'],
  )
  openssl(
    ...['x509', '-req', '-in', csr, '-CA', ca, '-CAkey', caKey, '-CAcreateserial', '-out', cert],
    ...['-days', '1', '-extfile', ext],
  )
  return { key, cert, ca }
}

// Runs as its own process (`node tls-proxy.mjs <dir> <port> <target>`): the runner blocks its
// event loop on synchronous CLI calls, so the proxy cannot live in it.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [dir, port, target] = process.argv.slice(2)
  await startProxy(
    { key: join(dir, 'key.pem'), cert: join(dir, 'cert.pem') },
    Number(port),
    Number(target),
  )
}

/** Listens on `port` (HTTPS) and forwards every request to http://127.0.0.1:`target`. */
export function startProxy({ key, cert }, port, target) {
  const server = createServer({ key: readFileSync(key), cert: readFileSync(cert) }, (req, res) => {
    const upstream = request(
      { host: '127.0.0.1', port: target, method: req.method, path: req.url, headers: req.headers },
      (up) => {
        // Request line and status only (never bodies), for diagnosing client failures.
        if (process.env.E2E_VERBOSE)
          console.error(`proxy ${req.method} ${req.url.split('?')[0]} ${up.statusCode}`)
        res.writeHead(up.statusCode ?? 502, up.headers)
        up.pipe(res)
      },
    )
    upstream.on('error', () => {
      res.writeHead(502)
      res.end()
    })
    req.pipe(upstream)
  })
  return new Promise((ok) => server.listen(port, '127.0.0.1', () => ok(server)))
}
