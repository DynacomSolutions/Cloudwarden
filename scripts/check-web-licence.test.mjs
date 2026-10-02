import assert from 'node:assert/strict'
import { test } from 'node:test'
import { checkFiles } from './check-web-licence.mjs'

const read = (map) => (f) => map[f] ?? ''

test('rejects bitwarden_license paths under web/', () => {
  const p = checkFiles(['web/bitwarden_license/bit-web/src/x.ts'], read({}))
  assert.equal(p.length, 1)
})

test('rejects imports of Bitwarden License packages', () => {
  const f = 'web/apps/web/src/a.ts'
  const p = checkFiles([f], read({ [f]: 'import { X } from "@bitwarden/bit-common/foo"' }))
  assert.equal(p.length, 1)
})

test('accepts GPL code and ignores paths outside web/', () => {
  const f = 'web/libs/common/src/a.ts'
  assert.deepEqual(
    checkFiles([f, 'bitwarden_license/x.ts'], read({ [f]: 'import "@bitwarden/common"' })),
    [],
  )
})
