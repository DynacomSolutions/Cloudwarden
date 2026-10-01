import { Hono } from 'hono'
import type { Env } from '../env'

export const alive = new Hono<Env>()

// Vaultwarden behaviour: respond with the current time as a JSON string.
alive.get('/alive', (c) => c.json(new Date().toISOString()))
alive.get('/api/alive', (c) => c.json(new Date().toISOString()))
