import assert from 'node:assert/strict'
import { test } from 'node:test'
import { checkFiles } from './check-web-licence.mjs'

const read = (map) => (f) => map[f] ?? ''
const one = (f, text) => checkFiles([f], read({ [f]: text }))

test('rejects bitwarden_license paths under web/', () => {
  assert.equal(checkFiles(['web/bitwarden_license/bit-web/src/x.ts'], read({})).length, 1)
})

test('rejects every form of Bitwarden License package reference', () => {
  for (const text of [
    'import { X } from "@bitwarden/bit-common/foo"',
    'const m = await import("@bitwarden/bit-web")',
    'require("@bitwarden/bit-browser")',
    'import "@bitwarden/bit-new-thing";',
  ]) {
    assert.equal(one('web/apps/web/src/a.ts', text).length, 1, text)
  }
})

test('rejects bare bitwarden_license/ paths in config files', () => {
  assert.equal(one('web/angular.json', '{"root": "bitwarden_license/bit-web"}').length, 1)
  assert.equal(one('web/apps/web/tailwind.config.js', '"../../bitwarden_license/x"').length, 1)
})

test('finds a licence notice anywhere in the file', () => {
  const text = `${'x\n'.repeat(5000)}// Licensed under the Bitwarden License, Version 1.0`
  assert.equal(one('web/libs/a.ts', text).length, 1)
})

test('accepts GPL code, the licence file name string, and paths outside web/', () => {
  assert.deepEqual(one('web/libs/common/src/a.ts', 'import "@bitwarden/common"'), [])
  assert.deepEqual(one('web/apps/web/src/a.html', '"bitwarden_license.json"'), [])
  assert.deepEqual(checkFiles(['bitwarden_license/x.ts'], read({})), [])
})

test('rejects the proprietary commercial SDK package in any form', () => {
  for (const text of [
    '"@bitwarden/commercial-sdk-internal": "0.2.0"',
    'import init from "@bitwarden/commercial-sdk-internal"',
    'rm -rf node_modules/@bitwarden/sdk-internal-commercial',
  ]) {
    assert.equal(one('web/package.json', text).length, 1, text)
  }
})

test('rejects dependencies licensed under a Bitwarden licence in a lockfile', () => {
  for (const licence of [
    'BITWARDEN SOFTWARE DEVELOPMENT KIT LICENSE AGREEMENT',
    'Bitwarden License v1.0',
  ]) {
    const lock = `{"packages":{"node_modules/x":{"license": "${licence}"}}}`
    assert.ok(one('web/package-lock.json', lock).length >= 1, licence)
  }
  assert.deepEqual(one('web/package-lock.json', '{"license": "GPL-3.0"}'), [])
})
