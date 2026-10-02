#!/usr/bin/env node

/**
 * Licence guard for the vendored web client (TASKS #210, docs/web-client.md).
 *
 * Only GPL-3.0 upstream code may live under web/. Upstream keeps code under the Bitwarden License
 * v1.0 in `bitwarden_license/` directories and `@bitwarden/bit-*` packages. This fails when any
 * tracked or untracked file under web/ sits in such a path, or when source under web/ imports
 * those packages or declares the Bitwarden License in a header.
 *
 * Usage: node scripts/check-web-licence.mjs
 */

import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')

const FORBIDDEN_PATH = /(^|\/)bitwarden_license(\/|$)/
const FORBIDDEN_IMPORT = /from\s+["']@bitwarden\/bit-(common|web|browser|cli|desktop)\b/
const FORBIDDEN_HEADER = /Bitwarden License,?\s+v?1\.0/i
const SOURCE = /\.(ts|js|mjs|cjs|html|scss|css)$/

export function checkFiles(files, read) {
  const problems = []
  for (const f of files) {
    if (!f.startsWith('web/')) continue
    if (FORBIDDEN_PATH.test(f)) {
      problems.push(`${f}: Bitwarden License path`)
      continue
    }
    if (!SOURCE.test(f) || f.includes('/node_modules/')) continue
    const text = read(f)
    if (FORBIDDEN_IMPORT.test(text)) problems.push(`${f}: imports a Bitwarden License package`)
    if (FORBIDDEN_HEADER.test(text.slice(0, 2000))) problems.push(`${f}: Bitwarden License header`)
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
