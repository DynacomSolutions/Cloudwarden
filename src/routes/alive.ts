import { Hono } from 'hono'
import type { Env } from '../env'

export const alive = new Hono<Env>()

// Respond with the current time as a JSON string (see the API contract, TASKS #14).
alive.get('/alive', (c) => c.json(new Date().toISOString()))
alive.get('/api/alive', (c) => c.json(new Date().toISOString()))
alive.get('/identity/alive', (c) => c.json(new Date().toISOString()))

// `now` is the obsolete name of `alive`; the official server still answers it on every service.
alive.get('/now', (c) => c.json(new Date().toISOString()))
alive.get('/api/now', (c) => c.json(new Date().toISOString()))
alive.get('/identity/now', (c) => c.json(new Date().toISOString()))
