import { Hono } from 'hono'
import type { Env } from '../env'

export const stubs = new Hono<Env>()

const notImplemented = (c: import('hono').Context<Env>) =>
  c.json({ message: 'Not implemented' }, 501)

// TODO(TASKS #1): authentication (password grant, refresh, 2FA)
stubs.post('/identity/connect/token', notImplemented)

// TODO(TASKS #2): full vault sync
stubs.get('/api/sync', notImplemented)

// TODO(TASKS #3): ciphers CRUD
stubs.all('/api/ciphers', notImplemented)
stubs.all('/api/ciphers/*', notImplemented)

// TODO(TASKS #4): folders CRUD
stubs.all('/api/folders', notImplemented)
stubs.all('/api/folders/*', notImplemented)

// TODO(TASKS #5): Sends (text and file, R2-backed)
stubs.all('/api/sends', notImplemented)
stubs.all('/api/sends/*', notImplemented)

// TODO(TASKS #6): organizations, collections, members
stubs.all('/api/organizations', notImplemented)
stubs.all('/api/organizations/*', notImplemented)

// TODO(TASKS #7): live sync notifications via the NotificationHub Durable Object
stubs.all('/notifications/hub', notImplemented)
stubs.all('/notifications/hub/*', notImplemented)
