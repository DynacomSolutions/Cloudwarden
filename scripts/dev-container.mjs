#!/usr/bin/env node

/**
 * Entrypoint of the dev container image (TASKS #12, see docs/local-dev.md).
 *
 * Applies the D1 migrations to the simulated local database, then runs the Vite dev server (the
 * Worker, D1, R2 and the Durable Object, all in workerd) on every interface. Nothing here names
 * a host: the public URL and extra settings arrive through environment variables at run time.
 *
 * Environment (all optional):
 *   PORT or DEVDEPLOY_PORT  listen port, default 8080
 *   JWT_SECRET              token signing key; generated once and kept in the state dir when unset
 *   DEPLOY_DOMAIN           host Cloudwarden reports as its own (becomes DOMAIN)
 *   DEV_ALLOWED_HOSTS       Host headers Vite accepts: `*` (default here), or a comma separated list
 *   SIGNUPS_ALLOWED, ADMIN_ENABLED, ...  as in the README configuration table
 */

import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { migrateLocal } from './local-migrate.mjs'

const root = resolve(import.meta.dirname, '..')
const state = join(root, '.cloudflare', 'state')
const port = process.env.PORT || process.env.DEVDEPLOY_PORT || '8080'

mkdirSync(state, { recursive: true })

function signingSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET
  const file = join(state, 'jwt-secret')
  if (existsSync(file)) return readFileSync(file, 'utf8').trim()
  const secret = randomBytes(36).toString('base64url')
  writeFileSync(file, `${secret}\n`, { mode: 0o600 })
  return secret
}

const env = {
  ...process.env,
  LOCAL_DEV_SECRETS: 'true',
  JWT_SECRET: signingSecret(),
  DEV_ALLOWED_HOSTS: process.env.DEV_ALLOWED_HOSTS || '*',
}

await migrateLocal(root, env, state)
console.log('local D1 migrations applied')

const server = spawn(
  join(root, 'node_modules', '.bin', 'vite'),
  ['dev', '--host', '0.0.0.0', '--port', port, '--strictPort'],
  { cwd: root, env, stdio: 'inherit' },
)
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.kill(signal))
server.on('exit', (code, signal) => process.exit(code ?? (signal ? 1 : 0)))
