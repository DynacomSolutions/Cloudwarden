import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'

const LOCALES = join(import.meta.dirname, '..', 'web', 'apps', 'web', 'src', 'locales')
const read = (p) => JSON.parse(readFileSync(p, 'utf8'))
const en = read(join(LOCALES, 'en', 'messages.json'))

// Cloudwarden adds strings (instance admin, Secrets Manager) to the English catalogue only. The
// client's translation service falls back to English for any key a locale lacks, so other
// locales never render an empty label. These tests pin both halves of that arrangement.
test('the translation service falls back to the English catalogue', () => {
  const src = readFileSync(
    join(
      import.meta.dirname,
      '..',
      'web',
      'libs',
      'common',
      'src',
      'platform',
      'services',
      'translation.service.ts',
    ),
    'utf8',
  )
  assert.match(src, /this\.defaultMessages\[id\]/)
  assert.match(src, /loadMessages\(this\.defaultLocale, this\.defaultMessages\)/)
})

test('every Cloudwarden string has English text with matching placeholders', () => {
  const own = Object.keys(en).filter((k) => k.startsWith('cw'))
  assert.ok(own.length > 0)
  for (const key of own) {
    assert.ok(en[key].message?.trim(), `${key} has no English message`)
    for (const name of Object.keys(en[key].placeholders ?? {})) {
      assert.ok(en[key].message.includes(`$${name.toUpperCase()}$`), `${key} placeholder ${name}`)
    }
  }
})
