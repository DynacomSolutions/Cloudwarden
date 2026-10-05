#!/usr/bin/env node

/**
 * Licence guard for the vendored web client (TASKS #210, docs/web-client.md).
 *
 * Only GPL-3.0 upstream code may live under web/. Upstream keeps code under the Bitwarden License
 * v1.0 in `bitwarden_license/` directories and `@bitwarden/bit-*` packages, and ships the commercial
 * SDK (`@bitwarden/commercial-sdk-internal`) under the proprietary Bitwarden SDK licence. Any
 * dependency whose lockfile `license` is a Bitwarden licence is rejected too. This fails when any
 * tracked or untracked file under web/ sits in such a path, or when a source or config file under
 * web/ references such a path or package in any form (import, dynamic import, require, side
 * effect import, config path) or carries a Bitwarden License header anywhere in the file.
 *
 * Usage: node scripts/check-web-licence.mjs
 */

import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

const FORBIDDEN_PATH = /(^|\/)bitwarden_license(\/|$)/
const FORBIDDEN_REFERENCES = [
  [/@bitwarden\/bit-[\w-]+/, 'references a Bitwarden License package'],
  [
    /@bitwarden\/(commercial-sdk-internal|sdk-internal-commercial|[\w-]*commercial[\w-]*)/i,
    'references a proprietary Bitwarden commercial SDK package',
  ],
  [
    /"license"\s*:\s*"[^"]*bitwarden[^"]*licen[sc]e[^"]*"/i,
    'declares a Bitwarden SDK or Bitwarden License dependency licence',
  ],
  [/bitwarden_license\//, 'references a bitwarden_license/ path'],
  [/Bitwarden License,?\s+v?(ersion\s+)?1\.0/i, 'carries a Bitwarden License notice'],
]
const SOURCE = /\.(ts|tsx|js|mjs|cjs|json|html|scss|css)$/
// Our own guard documentation and the upstream licence index describe the excluded licence.
const EXEMPT = new Set(['web/LICENSE.txt', 'web/NOTICE.md'])

export function checkFiles(files, read) {
  const problems = []
  for (const f of files) {
    if (!f.startsWith('web/') || EXEMPT.has(f)) continue
    if (FORBIDDEN_PATH.test(f)) {
      problems.push(`${f}: Bitwarden License path`)
      continue
    }
    if (!SOURCE.test(f) || f.includes('/node_modules/')) continue
    const text = read(f)
    for (const [re, what] of FORBIDDEN_REFERENCES) {
      if (re.test(text)) problems.push(`${f}: ${what}`)
    }
  }
  return problems
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const files = execSync('git ls-files --cached --others --exclude-standard -- web', {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
  })
    .split('\n')
    .filter(Boolean)
  const problems = checkFiles(files, (f) => readFileSync(join(ROOT, f), 'utf8'))
  if (problems.length > 0) {
    console.error('Non GPL-3.0 upstream code found under web/:')
    for (const p of problems) console.error(`  ${p}`)
    process.exit(1)
  }
  console.log(`web/ licence check passed (${files.length} files)`)
}
