// Peer registry, signed outbound calls and inbound signature checks (TASKS #301).
import { eq, lt } from 'drizzle-orm'
import type { Context, MiddlewareHandler } from 'hono'
import { rateLimit } from '../admin/security'
import { utf8 } from '../auth/crypto'
import { createDb, schema } from '../db'
import type { Bindings, Env } from '../env'
import { ApiError } from '../errors'
import {
  baseUrl,
  type Descriptor,
  federationEnabled,
  fingerprintOf,
  loadIdentity,
  PROTOCOL,
  PROTOCOL_VERSION,
  WELL_KNOWN_PATH,
} from './identity'
import { parsePeerDomain, readJson, safeFetch } from './net'
import {
  DEVICE_HEADER,
  MAX_SKEW_SECONDS,
  parseSignature,
  signRequest,
  USER_HEADER,
  verifyRequest,
} from './signature'

export type Peer = typeof schema.federationPeers.$inferSelect
export const PeerStatus = { Pending: 'pending', Active: 'active', Suspended: 'suspended' } as const

/** Inbound signed calls per peer per minute. */
export const PEER_RATE_LIMIT = 600
/** Largest signed request body accepted (forwarded attachment uploads included). */
export const MAX_INBOUND_BYTES = 26 * 1024 * 1024
/** Unsigned-peer pairing attempts per client address per minute. */
export const PAIR_RATE_LIMIT = 10

export const isActive = (p: Peer | undefined | null): boolean =>
  !!p && p.status === PeerStatus.Active && p.localApproved && p.remoteApproved

export async function getPeer(env: Bindings, uuid: string): Promise<Peer | undefined> {
  const [p] = await createDb(env.DB)
    .select()
    .from(schema.federationPeers)
    .where(eq(schema.federationPeers.uuid, uuid))
    .limit(1)
  return p
}

export async function peerByDomain(env: Bindings, domain: string): Promise<Peer | undefined> {
  const [p] = await createDb(env.DB)
    .select()
    .from(schema.federationPeers)
    .where(eq(schema.federationPeers.domain, domain))
    .limit(1)
  return p
}

export async function listPeers(env: Bindings): Promise<Peer[]> {
  return createDb(env.DB).select().from(schema.federationPeers)
}

export async function peerJson(p: Peer) {
  return {
    object: 'federationPeer',
    id: p.uuid,
    instanceId: p.instanceId,
    domain: p.domain,
    fingerprint: p.fingerprint,
    protocolVersion: p.protocolVersion,
    status: p.status,
    localApproved: p.localApproved,
    remoteApproved: p.remoteApproved,
    active: isActive(p),
    lastSeenDate: p.lastSeenAt === null ? null : new Date(p.lastSeenAt).toISOString(),
    lastError: p.lastError,
    acceptedAutomatically: p.acceptedAutomatically,
    creationDate: new Date(p.createdAt).toISOString(),
  }
}

/** Fetches and validates a peer's public descriptor over https. */
export async function fetchDescriptor(env: Bindings, domain: string): Promise<Descriptor> {
  const res = await safeFetch(env, new Request(`${baseUrl(domain)}${WELL_KNOWN_PATH}`))
  if (!res.ok) throw new ApiError(502, 'The peer does not offer federation.')
  const d = await readJson<Descriptor>(res, 64 * 1024)
  if (
    d?.protocol !== PROTOCOL ||
    d.version !== PROTOCOL_VERSION ||
    d.algorithm !== 'ed25519' ||
    typeof d.publicKey !== 'string' ||
    typeof d.instanceId !== 'string' ||
    !/^[0-9a-f-]{36}$/.test(d.instanceId) ||
    String(d.domain).toLowerCase() !== domain
  ) {
    throw new ApiError(502, 'The peer descriptor is invalid or names another domain.')
  }
  return { ...d, fingerprint: await fingerprintOf(d.publicKey) }
}

async function touchPeer(env: Bindings, peer: Peer, error: string | null) {
  await createDb(env.DB)
    .update(schema.federationPeers)
    .set(error === null ? { lastSeenAt: Date.now(), lastError: null } : { lastError: error })
    .where(eq(schema.federationPeers.uuid, peer.uuid))
}

export interface CallOptions {
  method?: string
  body?: unknown
  rawBody?: Uint8Array
  contentType?: string
  /** The local user the call is made for (serving side) or about (hosting side). */
  user?: string
  device?: string | null
  /** Allow calls to a peer that is not (yet) active: pairing only. */
  allowInactive?: boolean
}

/**
 * Signs and sends a request to a peer. Throws ApiError for transport failures; returns the
 * response otherwise (the caller decides what a non-2xx means).
 */
export async function peerFetch(
  env: Bindings,
  peer: Peer,
  path: string,
  opts: CallOptions = {},
): Promise<Response> {
  if (!federationEnabled(env)) throw new ApiError(404, 'Federation is not enabled on this server.')
  if (!opts.allowInactive && !isActive(peer)) {
    throw new ApiError(
      503,
      peer.status === PeerStatus.Suspended
        ? 'The peer instance is suspended.'
        : 'The peer instance is not paired.',
    )
  }
  const id = await loadIdentity(env)
  const method = opts.method ?? (opts.body === undefined && !opts.rawBody ? 'GET' : 'POST')
  const body =
    opts.rawBody ?? (opts.body === undefined ? new Uint8Array() : utf8(JSON.stringify(opts.body)))
  const url = `${baseUrl(peer.domain)}${path}`
  const headers = new Headers()
  if (body.byteLength > 0 || method !== 'GET') {
    headers.set('content-type', opts.contentType ?? 'application/json')
  }
  if (opts.user) headers.set(USER_HEADER, opts.user)
  if (opts.device) headers.set(DEVICE_HEADER, opts.device.replace(/[^\w.:-]/g, '').slice(0, 128))
  await signRequest(method, url, headers, body, id.instanceId, id.privateKey)
  try {
    const res = await safeFetch(
      env,
      new Request(url, {
        method,
        headers,
        body: method === 'GET' || method === 'HEAD' ? undefined : body,
      }),
    )
    await touchPeer(env, peer, res.status >= 500 ? `HTTP ${res.status}` : null)
    return res
  } catch (err) {
    await touchPeer(env, peer, err instanceof ApiError ? err.message : 'unreachable').catch(
      () => {},
    )
    throw err
  }
}

/** `peerFetch` that requires a 2xx and returns the JSON body. */
export async function peerJsonCall<T>(
  env: Bindings,
  peer: Peer,
  path: string,
  opts: CallOptions = {},
): Promise<T> {
  const res = await peerFetch(env, peer, path, opts)
  if (!res.ok) {
    const err = await readJson<{ message?: string }>(res, 64 * 1024).catch(() => null)
    throw new ApiError(
      res.status === 404 ? 404 : res.status >= 500 ? 502 : 400,
      `The peer refused the request: ${String(err?.message ?? `HTTP ${res.status}`).slice(0, 300)}`,
    )
  }
  if (res.status === 204) return undefined as T
  return readJson<T>(res)
}

// ----- inbound -----

export interface Verified {
  peer: Peer
  /** Value of the federated user header, or null. */
  user: string | null
  device: string | null
  body: Uint8Array
}

declare module 'hono' {
  interface ContextVariableMap {
    federation: Verified
  }
}

const deny = (status: 401 | 403 | 429, message: string) => new ApiError(status, message)

/** Verifies the signature of the current request against a known public key. */
export async function verifyInbound(
  c: Context<Env>,
  publicKey: string,
  body: Uint8Array,
): Promise<string> {
  const parsed = parseSignature(c.req.raw.headers)
  if (!parsed) throw deny(401, 'Missing or malformed federation signature.')
  const failure = await verifyRequest(
    { method: c.req.method, url: c.req.url, headers: c.req.raw.headers },
    body,
    parsed,
    publicKey,
  )
  if (failure) throw deny(401, `Federation signature rejected (${failure}).`)
  return parsed.params.nonce
}

/** Records a nonce; false when it was already used (a replay). */
export async function claimNonce(env: Bindings, peerUuid: string, nonce: string) {
  const db = createDb(env.DB)
  const now = Date.now()
  const inserted = await db
    .insert(schema.federationNonces)
    .values({ peerUuid, nonce, expiresAt: now + 2 * MAX_SKEW_SECONDS * 1000 })
    .onConflictDoNothing()
    .returning({ nonce: schema.federationNonces.nonce })
  if (Math.random() < 0.05) {
    await db.delete(schema.federationNonces).where(lt(schema.federationNonces.expiresAt, now))
  }
  return inserted.length === 1
}

/**
 * Middleware for `/federation/v1/*`: the request must be signed by an active, allowlisted peer,
 * fresh, not replayed and within the per-peer rate limit.
 */
export const requirePeer: MiddlewareHandler<Env> = async (c, next) => {
  if (!federationEnabled(c.env)) throw new ApiError(404, 'Not found')
  const parsed = parseSignature(c.req.raw.headers)
  if (!parsed) throw deny(401, 'Missing or malformed federation signature.')
  const [peer] = await createDb(c.env.DB)
    .select()
    .from(schema.federationPeers)
    .where(eq(schema.federationPeers.instanceId, parsed.params.keyid))
    .limit(1)
  if (!peer) throw deny(403, 'Unknown peer.')
  if (!isActive(peer)) throw deny(403, 'The peer is not active on this instance.')
  if (!(await rateLimit(c.env.DB, `fed:${peer.uuid}`, PEER_RATE_LIMIT, 60_000, Date.now()))) {
    throw deny(429, 'Too many federation requests.')
  }
  if (Number(c.req.header('content-length') ?? '0') > MAX_INBOUND_BYTES) {
    throw new ApiError(413, 'Federation request too large.')
  }
  const body = new Uint8Array(await c.req.raw.clone().arrayBuffer())
  if (body.byteLength > MAX_INBOUND_BYTES) throw new ApiError(413, 'Federation request too large.')
  const nonce = await verifyInbound(c, peer.publicKey, body)
  if (!(await claimNonce(c.env, peer.uuid, nonce))) throw deny(401, 'Replayed federation request.')
  const user = c.req.header(USER_HEADER)
  const device = c.req.header(DEVICE_HEADER)
  c.set('federation', {
    peer,
    user: user && user !== '-' ? user : null,
    device: device && device !== '-' ? device : null,
    body,
  })
  await touchPeer(c.env, peer, null)
  await next()
}

export const normaliseDomainOrThrow = (input: string) => {
  const d = parsePeerDomain(input)
  if (!d) throw new ApiError(400, 'Enter a domain name such as vault.example.com.')
  return d
}
