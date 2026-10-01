import { Hono } from 'hono'
import type { Env } from '../env'

export const stubs = new Hono<Env>()

const notImplemented = (c: import('hono').Context<Env>) =>
  c.json({ message: 'Not implemented' }, 501)

