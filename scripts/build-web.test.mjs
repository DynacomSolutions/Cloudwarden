import assert from 'node:assert/strict'
import { test } from 'node:test'
import { HEADERS, notice } from './build-web.mjs'

const csp = /Content-Security-Policy: (.*)/.exec(HEADERS)?.[1] ?? ''
const directive = (name) =>
  csp
    .split(';')
    .map((d) => d.trim())
    .find((d) => d.startsWith(`${name} `)) ?? ''

test('connect-src has no scheme-wide wss: or https: source', () => {
  const sources = directive('connect-src').split(/\s+/).slice(1)
  assert.ok(sources.includes("'self'"))
  for (const s of sources) assert.ok(!/^(wss?|https?):$/.test(s), `bare scheme ${s}`)
})

test('scripts are same-origin only, with no inline or eval allowances', () => {
  const sources = directive('script-src').split(/\s+/).slice(1)
  assert.deepEqual(sources.sort(), ["'self'", "'wasm-unsafe-eval'"].sort())
})

test('frames allow the vault itself and Duo for two-step login', () => {
  const frame = directive('frame-src')
  assert.match(frame, /'self'/)
  assert.match(frame, /duosecurity\.com/)
  assert.match(directive('frame-ancestors'), /'self'/)
})

test('licence notice names the source and licence', () => {
  const text = notice('1.2.3', 'abc')
  assert.match(text, /GPL-3\.0/)
  assert.match(text, /commit abc/)
})
