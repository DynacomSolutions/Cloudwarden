// Shared by the traffic capture scripts (TASKS #367, #387): a recording proxy in front of the dev
// server and the conversion of raw recordings into sanitised, replayable fixtures.
import { spawnSync } from 'node:child_process'
import { readlinkSync } from 'node:fs'
import { createServer, request } from 'node:http'
import { createServer as netServer } from 'node:net'
import { join } from 'node:path'
import { createSanitiser } from './traffic-sanitise.mjs'

export const freePort = () =>
  new Promise((ok, fail) => {
    const srv = netServer()
    srv.once('error', fail)
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => ok(port))
    })
  })

// Request headers worth keeping; everything else (user agent, host, cookies) is dropped.
export const KEEP_REQUEST_HEADERS = [
  'bitwarden-client-name',
  'bitwarden-client-version',
  'device-type',
  'x-device-identifier',
]

/** `X-Request-Email` carries the address as unpadded base64url; it is sanitised decoded. */
const sanitiseRequestEmail = (san, value) =>
  Buffer.from(san.string(Buffer.from(value, 'base64url').toString('utf8'), 'email')).toString(
    'base64url',
  )

/** Recording proxy: forwards to the dev server and notes every exchange of the open bucket. */
export function startRecorder(port, target) {
  let bucket = null // exchanges of the scenario being recorded, or null when not recording
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => {
      const body = Buffer.concat(chunks)
      const up = request(
        {
          host: '127.0.0.1',
          port: target,
          method: req.method,
          path: req.url,
          headers: req.headers,
        },
        (upRes) => {
          const out = []
          upRes.on('data', (c) => out.push(c))
          upRes.on('end', () => {
            const resBody = Buffer.concat(out)
            res.writeHead(upRes.statusCode ?? 502, upRes.headers)
            res.end(resBody)
            if (bucket) bucket.push({ req, body, status: upRes.statusCode, upRes, resBody })
          })
        },
      )
      up.on('error', () => {
        res.writeHead(502)
        res.end()
      })
      up.end(body)
    })
  })
  /** Starts a new bucket; `take()` ends it and returns what was recorded. */
  server.open = () => {
    bucket = []
  }
  server.take = () => {
    const raw = bucket ?? []
    bucket = null
    return raw
  }
  return new Promise((ok) => server.listen(port, '127.0.0.1', () => ok(server)))
}

/** Turns raw recordings into sanitised, replayable exchanges. */
export function toFixture(meta, raw) {
  const san = createSanitiser()
  const exchanges = []
  for (const { req, body, status, upRes, resBody } of raw) {
    const path = String(req.url)
    if (!/^\/(api|identity)\//.test(path)) continue
    const reqType = String(req.headers['content-type'] ?? '').split(';')[0]
    const resType = String(upRes.headers['content-type'] ?? '').split(';')[0]
    const headers = {}
    for (const h of KEEP_REQUEST_HEADERS)
      if (req.headers[h]) headers[h] = san.string(String(req.headers[h]), h)
    if (req.headers['x-request-email'])
      headers['x-request-email'] = sanitiseRequestEmail(san, String(req.headers['x-request-email']))
    if (req.headers.authorization) {
      headers.authorization = `Bearer ${san.string(String(req.headers.authorization).replace(/^Bearer /i, ''), 'access_token')}`
    }
    const ex = { method: req.method, path: san.string(path), headers }
    if (body.length) {
      if (reqType === 'application/json')
        ex.requestBody = san.value(JSON.parse(body.toString('utf8')))
      else if (reqType === 'application/x-www-form-urlencoded') {
        ex.requestForm = san.value(Object.fromEntries(new URLSearchParams(body.toString('utf8'))))
      } else continue // multipart uploads are not recorded
    }
    ex.status = status
    if (resBody.length && resType === 'application/json') {
      ex.responseBody = san.value(JSON.parse(resBody.toString('utf8')))
    }
    exchanges.push(ex)
  }
  return { ...meta, exchanges }
}

/** Every descendant pid of `pid` (workerd is not in the dev server's process group). */
export function descendants(pid) {
  const out = spawnSync('pgrep', ['-P', String(pid)], { encoding: 'utf8' }).stdout
  const kids = out.split('\n').filter(Boolean).map(Number)
  return kids.flatMap((k) => [k, ...descendants(k)])
}

/** Kills the given pids, ignoring those that are already gone. */
export function killAll(pids, signal = 'SIGKILL') {
  for (const pid of pids) {
    try {
      process.kill(pid, signal)
    } catch {}
  }
}

/**
 * Kills workerd processes started from `root`. They are orphaned from the dev server (re-parented
 * to init) before its descendants can be collected, so they are found by working directory.
 */
export function killStrayWorkerd(root) {
  const out = spawnSync('pgrep', ['-f', 'workerd serve'], { encoding: 'utf8' }).stdout
  const strays = []
  for (const pid of out.split('\n').filter(Boolean).map(Number)) {
    try {
      if (readlinkSync(`/proc/${pid}/cwd`) === root) strays.push(pid)
    } catch {}
  }
  killAll(strays)
}

/** Formats written fixtures the way `pnpm lint` expects them (Biome). */
export function formatFiles(root, files) {
  const res = spawnSync(
    join(root, 'node_modules', '.bin', 'biome'),
    ['format', '--write', ...files],
    {
      cwd: root,
      encoding: 'utf8',
    },
  )
  if (res.status !== 0) throw new Error(`biome format failed: ${res.stderr}`)
}
