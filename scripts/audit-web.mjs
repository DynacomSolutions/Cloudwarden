#!/usr/bin/env node

/**
 * Production dependency audit for the vendored web client (TASKS #406). Fails on any high or
 * critical advisory that is not in ACCEPTED. The upstream root manifest lists build tooling
 * under `dependencies`, so `npm audit --omit=dev` still reports it; those advisories are
 * accepted one by one here. Most affect build or dev-server tooling only. node-forge is the
 * exception: it ships in the bundle, but the vault never uses its signature verification.
 * Review the list whenever web/ is upgraded.
 */

import { spawnSync } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const ACCEPTED = new Set([
  'GHSA-xvcm-6775-5m9r', // immutable, build tooling
  'GHSA-v56q-mh7h-f735', // immutable, build tooling
  'GHSA-wc9g-mqfw-jrwm', // multer, dev server tooling
  'GHSA-qfvm-cv95-jqjf', // multer, dev server tooling
  'GHSA-535w-7cp7-47q4', // multer, dev server tooling
  'GHSA-86w9-cpqp-85rv', // node-forge, runtime-shipped; vault never calls its RSA signature verify; revisit when patched
  'GHSA-c2c7-rcm5-vvqj', // picomatch, build tooling
  'GHSA-68fv-2mgg-jv7q', // source-map-js, build tooling
  'GHSA-ph9p-34f9-6g65', // tmp, build tooling
  'GHSA-fx2h-pf6j-xcff', // vite, dev server (Windows only)
  'GHSA-96hv-2xvq-fx4p', // ws, dev server and signalr client in Node
])

/** High or critical advisories in an `npm audit --json` report that are not accepted. */
export function blocking(report, accepted = ACCEPTED) {
  if (report.auditReportVersion !== 2) throw new Error('unexpected npm audit report format')
  const found = new Map()
  for (const v of Object.values(report.vulnerabilities ?? {})) {
    for (const via of v.via) {
      if (typeof via !== 'object' || !['high', 'critical'].includes(via.severity)) continue
      const id = via.url.split('/').pop()
      if (!accepted.has(id)) found.set(id, `${via.name}: ${via.title}`)
    }
  }
  return found
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const cwd = join(dirname(fileURLToPath(import.meta.url)), '..', 'web')
  const r = spawnSync('npm', ['audit', '--omit=dev', '--json'], {
    cwd,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
  // npm audit exits 1 when it finds anything; only unparsable output is a tool failure.
  let report
  try {
    report = JSON.parse(r.stdout)
  } catch {
    console.error(`audit-web: no JSON from npm audit\n${r.stderr}`)
    process.exit(2)
  }
  if (report.error || report.auditReportVersion !== 2) {
    console.error(`audit-web: ${report.error?.summary ?? 'unexpected report format'}`)
    process.exit(2)
  }
  const found = blocking(report)
  for (const [id, text] of found) console.error(`${id} ${text}`)
  console.log(`web audit: ${found.size} unaccepted high or critical advisories`)
  process.exit(found.size ? 1 : 0)
}
