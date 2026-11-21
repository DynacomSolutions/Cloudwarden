// Builds docs/parity-matrix.md from the client call inventories in docs/parity/*.tsv and the routes
// registered under src/. Run: node scripts/parity-matrix.mjs (TASKS #231).
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const root = path.resolve(import.meta.dirname, '..')

/**
 * Replaces Hono regex constraints with a plain placeholder: `:id{[0-9a-fA-F-]{36}}` becomes `:id`.
 * The braces nest (a quantifier inside the constraint), so a flat pattern cannot match them.
 */
export function stripConstraints(p) {
  let out = ''
  for (let i = 0; i < p.length; i++) {
    const m = /^:\w+/.exec(p.slice(i))
    if (m && p[i + m[0].length] === '{') {
      let depth = 0
      let j = i + m[0].length
      for (; j < p.length; j++) {
        if (p[j] === '{') depth++
        else if (p[j] === '}' && --depth === 0) break
      }
      out += m[0]
      i = j
    } else out += p[i]
  }
  return out
}

export const norm = (p) =>
  stripConstraints(p)
    .replace(/\?.*$/, '')
    .replace(/\/+$/, '')
    .replace(/\([^)]*\)|\{[^}]*\}|:[A-Za-z_]+|\$\{[^}]*\}/g, '{}')
    .toLowerCase()

/**
 * Routes registered inside `for (const x of [...]) { router.get(x, ...) }` style loops, where the
 * path (and for tuples the method) is computed. Handles the three shapes used under src/routes:
 * `for (const path of [...]) router.post(path)`, the same with a template such as
 * `${PREFIX}/${path}`, and `for (const [method, path] of [...]) router[method](path)`. String
 * constants (`const P = '/api/x'`) are substituted, also inside template literals.
 */
export function loopRoutes(src) {
  const consts = new Map()
  const resolve = (t, extra = {}) =>
    t.replace(/\$\{(\w+)\}/g, (all, n) => extra[n] ?? consts.get(n) ?? all)
  for (const m of src.matchAll(/^(?:export )?const\s+(\w+)\s*=\s*(['`])([^'`]*)\2/gm))
    consts.set(m[1], resolve(m[3]))
  const out = []
  for (const loop of src.matchAll(/^for \(const (\[\s*\w+\s*,\s*\w+\s*\]|\w+) of \[/gm)) {
    // The array: balanced square brackets from the opening one.
    let i = loop.index + loop[0].length
    let depth = 1
    const start = i
    while (i < src.length && depth > 0) {
      if (src[i] === '[') depth++
      else if (src[i] === ']') depth--
      i++
    }
    const array = src.slice(start, i - 1)
    const end = src.indexOf('\n}', i)
    const body = src.slice(i, end < 0 ? src.length : end)
    const vars = loop[1].match(/\w+/g)
    const items = []
    if (vars.length === 2) {
      for (const t of array.matchAll(/\[\s*'(\w+)'\s*,\s*(?:(['`])([^'`]*)\2|(\w+))\s*\]/g))
        items.push([t[1], resolve(t[3] ?? consts.get(t[4]) ?? '')])
    } else {
      for (const t of array.matchAll(/(['`])([^'`]*)\1/g)) items.push([null, resolve(t[2])])
    }
    const pathVar = vars[vars.length - 1]
    for (const call of body.matchAll(
      /\b\w+(?:\.(get|post|put|delete|patch)|\[(\w+)\])\(\s*(?:(['`])([^'`]*)\3|(\w+))/g,
    )) {
      const literal = call[4]
      if (literal === undefined && call[5] !== pathVar) continue
      for (const [method, path] of items) {
        const m = call[1] ?? (call[2] === vars[0] ? method : null)
        if (!m) continue
        out.push([
          m,
          literal === undefined ? path : resolve(literal, { [pathVar]: path }),
          loop.index,
        ])
      }
    }
  }
  return out
}

/**
 * Every route registered in one source file: `{ method, path, pos }` with the path as written
 * (constants substituted, regex constraints kept) and `pos` the offset of the registration.
 */
export function fileRoutes(s) {
  const consts = new Map()
  const resolve = (t) => t.replace(/\$\{(\w+)\}/g, (all, n) => consts.get(n) ?? all)
  for (const m of s.matchAll(/^(?:export )?const\s+(\w+)\s*=\s*(['`])([^'`]*)\2/gm))
    consts.set(m[1], resolve(m[3]))
  const out = []
  const add = (method, r, pos) => {
    const path = resolve(r)
    if (path.startsWith('/')) out.push({ method: method.toUpperCase(), path, pos })
  }
  for (const m of s.matchAll(
    /\.(get|post|put|delete|patch)\(\s*(?:(['`])([^'`]+)\2|([A-Z][A-Z0-9_]*)\b)/g,
  ))
    add(m[1], m[3] ?? consts.get(m[4]) ?? '', m.index)
  for (const m of s.matchAll(
    /\.on\(\s*\[([^\]]+)\]\s*,\s*(?:(['`])([^'`]+)\2|([A-Z][A-Z0-9_]*)\b)/g,
  ))
    for (const v of m[1].matchAll(/'(\w+)'/g)) add(v[1], m[3] ?? consts.get(m[4]) ?? '', m.index)
  for (const [method, r, pos] of loopRoutes(s)) add(method, r, pos)
  return out
}

/** Mount order of the routers in `src/index.ts`: source file (relative to `src/`) to rank. */
export function mountOrder(index) {
  const files = new Map()
  for (const m of index.matchAll(/^import \{([^}]+)\} from '(\.\/[^']+)'/gm))
    for (const name of m[1].split(','))
      files.set(
        name
          .trim()
          .split(/\s+as\s+/)
          .pop(),
        m[2],
      )
  const rank = new Map()
  for (const m of index.matchAll(/app\.route\(\s*'\/'\s*,\s*(\w+)\s*\)/g)) {
    const file = files.get(m[1])
    if (file && !rank.has(file)) rank.set(`${file.replace(/^\.\//, '')}.ts`, rank.size)
  }
  return rank
}

/** Every route registered under src/ with its file, offset and the mount rank of the file. */
export function collectRoutes() {
  const out = []
  const srcDir = path.join(root, 'src')
  const rank = mountOrder(fs.readFileSync(path.join(srcDir, 'index.ts'), 'utf8'))
  const walk = (dir) => {
    for (const f of fs.readdirSync(dir)) {
      const p = path.join(dir, f)
      if (fs.statSync(p).isDirectory()) walk(p)
      else if (p.endsWith('.ts')) {
        const file = path.relative(srcDir, p)
        const s = fs.readFileSync(p, 'utf8')
        const usesNext = /\bnext\(\)/.test(s)
        for (const r of fileRoutes(s)) out.push({ ...r, file, rank: rank.get(file), usesNext })
      }
    }
  }
  walk(srcDir)
  return out
}

/** `METHOD normalised-path` for every route registered in src/. */
function serverRoutes(routes) {
  return new Set(routes.map((r) => `${r.method} ${norm(r.path)}`))
}

const segmentsOf = (p) =>
  p
    .replace(/\?.*$/, '')
    .split('/')
    .filter(Boolean)
    .map((seg) => {
      if (!seg.startsWith(':')) return { literal: seg.toLowerCase() }
      return { param: true, constrained: seg.includes('{') }
    })

/**
 * Routes that a wildcard route registered earlier answers first. A route `P` shadows `L` when both
 * have the same method and segment count, every segment of `P` is a parameter or equals the one of
 * `L`, at least one parameter of `P` is a literal in `L`, and `P` comes first: earlier in the same
 * file, or in a router that is mounted earlier. A parameter with a regex constraint is skipped,
 * because it may reject the literal. A handler that calls `next()` still lets `L` answer; the
 * report lists the pairs so that a person checks those.
 */
export function findShadows(routes) {
  const before = (a, b) =>
    a.file === b.file
      ? a.pos < b.pos
      : a.rank !== undefined && b.rank !== undefined && a.rank < b.rank
  const parsed = routes.map((r) => ({ ...r, segs: segmentsOf(r.path) }))
  const out = []
  for (const l of parsed) {
    if (l.segs.some((s) => s.param && s.constrained)) continue
    for (const p of parsed) {
      if (p === l || p.method !== l.method || p.segs.length !== l.segs.length) continue
      if (p.segs.some((s) => s.constrained)) continue
      let wider = false
      let covers = true
      for (let i = 0; i < p.segs.length && covers; i++) {
        const [ps, ls] = [p.segs[i], l.segs[i]]
        if (ps.param) wider ||= !ls.param
        else covers = !ls.param && ps.literal === ls.literal
      }
      if (covers && wider && before(p, l))
        out.push({
          method: l.method,
          path: l.path,
          shadowedBy: p.path,
          file: l.file,
          by: p.file,
          handsOn: p.file !== l.file && p.usesNext === true,
        })
    }
  }
  const unique = new Map(
    out.map((s) => [`${s.method} ${s.path} ${s.shadowedBy} ${s.file} ${s.by}`, s]),
  )
  return [...unique.values()].sort((a, b) =>
    `${a.path} ${a.method}`.localeCompare(`${b.path} ${b.method}`),
  )
}

/**
 * The first wildcard route (in mount order) that answers `METHOD path` although no route is
 * registered for it: the request falls into the wildcard with the literal as the parameter value.
 * `path` is a client path where a parameter is `{id}`, `${id}` or `:id`.
 */
export function findCapturing(method, clientPath, routes) {
  const want = clientPath
    .replace(/\?.*$/, '')
    .split('/')
    .filter(Boolean)
    .map((seg) =>
      /^\{.*\}$|^\$\{|^:/.test(seg) ? { param: true } : { literal: seg.toLowerCase() },
    )
  const order = (a, b) => (a.rank ?? 1e9) - (b.rank ?? 1e9) || a.pos - b.pos
  for (const p of [...routes].sort((a, b) => (a.file === b.file ? a.pos - b.pos : order(a, b)))) {
    if (p.method !== method.toUpperCase()) continue
    const segs = segmentsOf(p.path)
    if (segs.length !== want.length || segs.some((x) => x.constrained)) continue
    let wider = false
    const covers = segs.every((x, i) => {
      if (x.param) {
        wider ||= !want[i].param
        return true
      }
      return !want[i].param && x.literal === want[i].literal
    })
    if (covers && wider) return p
  }
  return null
}

function main() {
  const readTsv = (f) =>
    fs
      .readFileSync(path.join(root, 'docs/parity', f), 'utf8')
      .split('\n')
      .filter((l) => l && !l.startsWith('METHOD\t'))
      .map((l) => l.split('\t'))

  const rows = new Map()
  const add = (m, p, caller) => {
    if (!m || !p?.startsWith('/')) return
    const k = `${m.toUpperCase()} ${norm(p)}`
    const r = rows.get(k) ?? {
      method: m.toUpperCase(),
      path: p.replace(/\?.*$/, ''),
      callers: new Set(),
    }
    r.callers.add(caller)
    rows.set(k, r)
  }
  for (const [m, p] of readTsv('web-calls.tsv')) add(m, p, 'web')
  for (const [m, p, c] of readTsv('clients-calls.tsv')) add(m, p, c)
  for (const [m, p, c] of readTsv('mobile-calls.tsv')) add(m, p, c)
  for (const [m, p, , b] of readTsv('sdk-calls.tsv')) add(m, p, b === 'bws' ? 'bws' : 'sdk')
  add('POST', '/identity/connect/token', 'bws')

  /** Manual classification: METHOD, PATH, STATUS, OWNER, NOTE. Wins over the derived values. */
  const notes = new Map(
    readTsv('notes.tsv').map(([m, p, status, owner, note]) => [
      `${m} ${norm(p)}`,
      { status, owner, note },
    ]),
  )

  // Rows owned by the workstreams in flight; G is this audit (TASKS #231).
  const OWNERS = [
    [
      'A',
      /^\/api\/push\/|\/accounts\/verify-email|\/installations|password-hint|delete-recover|request-otp|verify-otp|new-device-otp|web-push-auth/,
    ],
    ['B', /^\/api\/sends|\/sends\/\{\}\/events|^\/api\/ciphers\/(\{\}\/)?(un)?archive/],
    [
      'C',
      /reset-password|recover-account|account-recovery|\/organizations\/\{\}\/auth-requests|admin-request|auto-enroll-status|^\/api\/organizations\/\{\}\/public-key|update-temp-password/,
    ],
    [
      'D',
      /duo|yubikey|^\/api\/secret-versions|\/secrets\/\{\}\/versions|^\/api\/sm\/\{\}\/(import|export)/,
    ],
    [
      'E',
      /sso|key-connector|\/devices\/\{\}\/(keys|retrieve-keys)|\/devices\/(update-trust|untrust|lost-trust)|clear-token|\/domain(\/|$)|update-tde-offboarding|delete-account|connect\/authorize|\/accounts\/set-password/,
    ],
    [
      'F',
      /^\/api\/public\/|^\/scim\/|api-key-information|\/organizations\/\{\}\/(rotate-api-key|api-key)$|\/organizations\/\{\}\/import$|\/integrations|\/organizations\/connections/,
    ],
  ]

  const routes = collectRoutes()
  const implemented = serverRoutes(routes)
  const shadows = findShadows(routes)
  const out = []
  for (const r of [...rows.values()].sort(
    (a, b) => norm(a.path).localeCompare(norm(b.path)) || a.method.localeCompare(b.method),
  )) {
    const k = `${r.method} ${norm(r.path)}`
    const n = norm(r.path)
    let status = implemented.has(k) ? 'implemented' : 'missing'
    let owner = OWNERS.find(([, re]) => re.test(n))?.[0] ?? (status === 'implemented' ? '' : 'G')
    let note = ''
    const callers = [...r.callers].sort()
    if (status === 'missing' && owner === 'G' && callers.every((c) => c === 'sdk')) {
      status = 'not called'
      owner = '-'
      note = 'Generated in the SDK API client only; no GPL client calls it'
    }
    const manual = notes.get(k)
    if (manual) {
      status = manual.status || status
      owner = manual.owner || owner
      note = manual.note || note
    }
    const capturedBy = implemented.has(k) ? null : findCapturing(r.method, r.path, routes)
    out.push({ ...r, callers: callers.join(', '), status, owner, note, capturedBy })
  }

  const captured = out.filter((r) => r.capturedBy)
  const count = (f) => out.filter(f).length
  const summary = {
    total: out.length,
    implemented: count((r) => r.status.startsWith('implemented') || r.status === 'self-host'),
    ownedAF: count((r) => /^[A-F]$/.test(r.owner) && !r.status.startsWith('implemented')),
    remaining: count(
      (r) => r.owner === 'G' && !r.status.startsWith('implemented') && r.status !== 'self-host',
    ),
    notCalled: count((r) => r.status === 'not called'),
    notApplicable: count((r) => r.status === 'not applicable'),
  }

  const md = `# Bitwarden client parity matrix

Generated by \`node scripts/parity-matrix.mjs\` (TASKS #231). Do not edit by hand: change
\`docs/parity/notes.tsv\` or the call inventories and regenerate.

## Sources

Every HTTP call to a Bitwarden server made by the official clients, read from GPL-3.0 sources only
(nothing under \`bitwarden_license/\`):

| Inventory | Source | Method |
|---|---|---|
| \`docs/parity/web-calls.tsv\` | Vendored web client \`web/\` (bitwarden/clients \`web-v2026.9.1\`), \`libs/**\` and \`apps/web/**\` | Every \`send(...)\` call plus direct \`fetch\` calls (token, events, notifications hub, icons) |
| \`docs/parity/clients-calls.tsv\` | bitwarden/clients \`cli-v2026.9.0\`, \`browser-v2026.9.0\`, \`desktop-v2026.9.0\` (\`apps/cli\`, \`apps/browser\`, \`apps/desktop\`) | Calls made by app code; shared libraries are identical to the vendored copy |
| \`docs/parity/mobile-calls.tsv\` | bitwarden/android and bitwarden/ios \`v2026.9.0-bwpm\` | Retrofit interfaces; iOS request types |
| \`docs/parity/sdk-calls.tsv\` | bitwarden/sdk-internal \`9acb7241\`, generated \`bitwarden-api-api\` and \`bitwarden-api-identity\` crates (GPL-3.0 dual licence) | Every generated operation; \`bws\` marks the Secrets Manager subset |

Status is derived from the routes registered under \`src/\`. **implemented** means a real handler;
**self-host** means the endpoint answers with the self-hosted behaviour of the official server (no
billing provider, no Provider Portal), so clients never see an error page; **not called** means only
the generated SDK client has the operation and no GPL client calls it; **not applicable** means the endpoint is not served by the official self-hosted server either (for example the
relay side endpoints of Bitwarden's cloud push relay, which this server calls as a client).

Owners: A push relay and account emails; B Sends, archive, favourites; C account recovery and device
approvals; D Duo, YubiKey, Secrets Manager history and import or export, importer, alias forwarders,
translations; E SSO, TDE, Key Connector, claimed domains; F organisation API key, Public API,
Directory Connector, SCIM, event integrations; G this audit.

## Summary

| | Rows |
|---|---|
| Distinct method and path pairs | ${summary.total} |
| Implemented (including self-host answers) | ${summary.implemented} |
| Owned by workstreams A to F, not yet implemented | ${summary.ownedAF} |
| Remaining for G | ${summary.remaining} |
| Not called by any client (SDK-generated only) | ${summary.notCalled} |
| Not applicable (not served by the official self-hosted server either) | ${summary.notApplicable} |

## Matrix

| Method | Path | Callers | Status | Owner | Note |
|---|---|---|---|---|---|
${out.map((r) => `| ${r.method} | \`${r.path}\` | ${r.callers} | ${r.status} | ${r.owner} | ${r.note} |`).join('\n')}

## Routes shadowed by a wildcard

Two cases. A client call with no route of its own that a wildcard route answers with the literal as
the parameter value. A route that a wildcard route of the same method answers first, because the
wildcard is registered earlier in the same file or in a router mounted earlier; a wildcard handler
that calls \`next()\` for ids it does not own still lets the literal route answer.

| Method | Path | Shadowed by | Where |
|---|---|---|---|
${captured.map((r) => `| ${r.method} | \`${r.path}\` | \`${r.capturedBy.path}\` | \`${r.capturedBy.file}\`, no route of its own |`).join('\n')}${captured.length && shadows.length ? '\n' : ''}${shadows.map((x) => `| ${x.method} | \`${x.path}\` | \`${x.shadowedBy}\` | \`${x.file}\`${x.by === x.file ? '' : ` after \`${x.by}\`${x.handsOn ? ', which calls `next()`' : ''}`} |`).join('\n')}
`
  fs.writeFileSync(path.join(root, 'docs/parity-matrix.md'), md)
  console.log(JSON.stringify({ ...summary, shadowed: shadows.length + captured.length }))
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main()
