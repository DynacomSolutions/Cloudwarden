import assert from 'node:assert/strict'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { injectOverlay, OVERLAY_PATH, sri } from './fetch-web-vault.mjs'

const INDEX = '<!doctype html><html><head><title>Vault</title></head><body></body></html>\n'

function vault() {
  const dir = mkdtempSync(join(tmpdir(), 'cw-vault-'))
  writeFileSync(join(dir, 'index.html'), INDEX)
  return dir
}

test('copies the admin link script and adds one tag with integrity', async () => {
  const dir = vault()
  await injectOverlay(dir)
  const script = readFileSync(join(dir, OVERLAY_PATH))
  assert.ok(existsSync(join(dir, OVERLAY_PATH)))
  assert.deepEqual(
    script,
    readFileSync(new URL('../web-vault-overlay/admin-link.js', import.meta.url)),
  )
  const html = readFileSync(join(dir, 'index.html'), 'utf8')
  const tags = html.match(/<script src="cloudwarden\/admin-link\.js"[^>]*>/g) ?? []
  assert.equal(tags.length, 1)
  assert.ok(tags[0].includes(`integrity="${sri(script)}"`))
  assert.ok(tags[0].includes(' defer'))
  assert.ok(html.indexOf(tags[0]) < html.indexOf('</head>'))
})

test('is idempotent and replaces a stale tag', async () => {
  const dir = vault()
  await injectOverlay(dir)
  const first = readFileSync(join(dir, 'index.html'), 'utf8')
  await injectOverlay(dir)
  assert.equal(readFileSync(join(dir, 'index.html'), 'utf8'), first)

  const other = join(dir, 'other.js')
  writeFileSync(other, 'void 0\n')
  await injectOverlay(dir, other)
  const html = readFileSync(join(dir, 'index.html'), 'utf8')
  assert.equal((html.match(/cloudwarden\/admin-link\.js/g) ?? []).length, 1)
  assert.ok(html.includes(sri(Buffer.from('void 0\n'))))
})

test('refuses an index.html without a head', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'cw-vault-'))
  writeFileSync(join(dir, 'index.html'), '<html></html>')
  await assert.rejects(injectOverlay(dir), /no <\/head>/)
})
