import { Hono } from 'hono'
import type { Env } from '../env'

export const stubs = new Hono<Env>()

const notImplemented = (c: import('hono').Context<Env>) =>
  c.json({ message: 'Not implemented' }, 501)

// TODO(TASKS #5): Sends (text and file, R2-backed)
stubs.all('/api/sends', notImplemented)
stubs.all('/api/sends/*', notImplemented)

// TODO(TASKS #6): organizations, collections, members
stubs.all('/api/organizations', notImplemented)
stubs.all('/api/organizations/*', notImplemented)

// TODO(TASKS #7): live sync notifications via the NotificationHub Durable Object
stubs.all('/notifications/hub', notImplemented)
stubs.all('/notifications/hub/*', notImplemented)
