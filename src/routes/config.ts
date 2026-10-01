import { Hono } from 'hono'
import type { Env } from '../env'

export const config = new Hono<Env>()

export const SERVER_VERSION = '2025.1.0'

config.get('/api/config', (c) => {
  const base = c.env.DOMAIN.replace(/\/+$/, '')
  return c.json({
    object: 'config',
    version: SERVER_VERSION,
    gitHash: 'unknown',
    server: null,
    environment: {
      vault: base,
      api: `${base}/api`,
      identity: `${base}/identity`,
      notifications: `${base}/notifications`,
      sso: '',
    },
    featureStates: {},
  })
})
