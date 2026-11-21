import assert from 'node:assert'
import { test } from 'node:test'
import {
  fileRoutes,
  findCapturing,
  findShadows,
  mountOrder,
  norm,
  stripConstraints,
} from './parity-matrix.mjs'

test('norm strips Hono regex constraints with nested braces', () => {
  assert.strictEqual(stripConstraints('/api/devices/:id{[0-9a-fA-F-]{36}}'), '/api/devices/:id')
  assert.strictEqual(norm('/api/devices/:id{[0-9a-fA-F-]{36}}'), '/api/devices/{}')
  assert.strictEqual(norm('/api/devices/{id}'), '/api/devices/{}')
  assert.strictEqual(norm('/api/a/:x{[a-z]+}/b/:y'), '/api/a/{}/b/{}')
  assert.strictEqual(norm('/api/ciphers/:id/'), '/api/ciphers/{}')
})

test('fileRoutes reads literals, constants, templates, on() and loops', () => {
  const src = `
const DEVICE_ID = '/api/devices/:id{[0-9a-fA-F-]{36}}'
const BASE = '/api/things'
devices.get(DEVICE_ID, requireAuth, h)
devices.put(DEVICE_ID, requireAuth, h)
r.get(\`\${BASE}/list\`, h)
r.on(['PUT', 'POST'], '/api/ciphers/move', h)
r.on(['PUT', 'POST'], BASE, h)
for (const path of ['/api/x', '/api/y']) {
  r.post(path, h)
}
`
  const routes = fileRoutes(src).map((r) => `${r.method} ${r.path}`)
  assert.deepStrictEqual(routes.sort(), [
    'GET /api/devices/:id{[0-9a-fA-F-]{36}}',
    'GET /api/things/list',
    'POST /api/ciphers/move',
    'POST /api/things',
    'POST /api/x',
    'POST /api/y',
    'PUT /api/ciphers/move',
    'PUT /api/devices/:id{[0-9a-fA-F-]{36}}',
    'PUT /api/things',
  ])
  // A constant that is not a string (a handler, a variable) is not read as a path.
  assert.deepStrictEqual(fileRoutes('r.get(Handler, h)'), [])
})

test('mountOrder follows the app.route calls of the index', () => {
  const index = `
import { a } from './routes/a'
import { b as bee } from './routes/b'
import { c } from './routes/c'
app.route('/', bee)
app.route('/', a)
`
  const rank = mountOrder(index)
  assert.strictEqual(rank.get('routes/b.ts'), 0)
  assert.strictEqual(rank.get('routes/a.ts'), 1)
  assert.strictEqual(rank.has('routes/c.ts'), false)
})

const route = (method, path, file, pos, rank) => ({ method, path, file, pos, rank })

test('findShadows reports a literal route registered after a wildcard', () => {
  const shadows = findShadows([
    route('POST', '/api/ciphers/:id', 'routes/org.ts', 10, 0),
    route('POST', '/api/ciphers/move', 'routes/ciphers.ts', 5, 1),
    route('POST', '/api/ciphers/:id/share', 'routes/org.ts', 20, 0),
  ])
  assert.deepStrictEqual(
    shadows.map((s) => `${s.method} ${s.path} <- ${s.shadowedBy}`),
    ['POST /api/ciphers/move <- /api/ciphers/:id'],
  )
})

test('findShadows is silent when the literal route comes first or the method differs', () => {
  assert.deepStrictEqual(
    findShadows([
      route('POST', '/api/ciphers/move', 'routes/ciphers.ts', 5, 1),
      route('POST', '/api/ciphers/:id', 'routes/ciphers.ts', 10, 1),
      route('GET', '/api/ciphers/:id', 'routes/ciphers.ts', 1, 1),
      route('PUT', '/api/ciphers/share', 'routes/org.ts', 99, 0),
    ]),
    [],
  )
})

test('findShadows ignores a constrained parameter that rejects the literal', () => {
  assert.deepStrictEqual(
    findShadows([
      route('GET', '/api/devices/:id{[0-9a-fA-F-]{36}}', 'routes/devices.ts', 1, 0),
      route('GET', '/api/devices/knowndevice', 'routes/devices.ts', 9, 0),
    ]),
    [],
  )
})

test('findShadows compares files only when both are mounted', () => {
  assert.deepStrictEqual(
    findShadows([
      route('GET', '/api/x/:id', 'a.ts', 1, undefined),
      route('GET', '/api/x/list', 'b.ts', 1, 3),
    ]),
    [],
  )
})

test('findCapturing finds the wildcard that answers a client call with no route', () => {
  const routes = [
    route('GET', '/api/organizations/:orgId/collections/:id', 'routes/collections.ts', 4, 2),
    route('GET', '/api/organizations/:orgId/collections', 'routes/collections.ts', 1, 2),
  ]
  assert.strictEqual(
    findCapturing('get', '/api/organizations/{id}/collections/access', routes)?.path,
    '/api/organizations/:orgId/collections/:id',
  )
  // A parameter in the client path is not captured by a parameter-only match.
  assert.strictEqual(findCapturing('GET', '/api/organizations/{id}/collections/{id}', routes), null)
  assert.strictEqual(
    findCapturing('POST', '/api/organizations/{id}/collections/access', routes),
    null,
  )
})

test('findCapturing skips regex-constrained wildcards', () => {
  assert.strictEqual(
    findCapturing('GET', '/api/devices/knowndevice', [
      route('GET', '/api/devices/:id{[0-9a-fA-F-]{36}}', 'routes/devices.ts', 1, 0),
    ]),
    null,
  )
})
