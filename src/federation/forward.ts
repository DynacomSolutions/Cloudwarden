// Serving side request forwarding (TASKS #304). Official clients talk only to their own server;
// requests that touch a federated organisation or one of its items are sent on to the hosting
// instance as the signed federated identity, which applies its normal authorisation and revision
// checks. Folders stay local. After a successful write the replica is refreshed before the
// response returns, so a following sync already shows the change.
import { and, eq } from 'drizzle-orm'
import type { Context, MiddlewareHandler } from 'hono'
import { authenticateAccessToken } from '../auth/middleware'
import { createDb, type Db, runBatch, schema } from '../db'
import type { Env, User } from '../env'
import { ApiError } from '../errors'
import { MAX_IMPORT_BODY } from '../limits'
import { errorKind, log } from '../log'
import { assertBodyWithin } from '../validation'
import { requireFolder } from '../vault/ciphers'
import { FederationEvent, federationEventStatement } from './events'
import { NOT_FEDERATED, NOT_FEDERATED_MESSAGE } from './hosting'
import { federationEnabled } from './identity'
import { isActive, type Peer, PeerStatus, peerFetch } from './peers'
import {
  federatedCipherOrgs,
  folderOverlay,
  replicaOrg,
  rewriteLinks,
  syncUserFromPeer,
} from './replica'
import { sanitizeCipher } from './sanitize'

type Ctx = Context<Env>

/** Largest request body forwarded (attachment uploads are buffered to be signed). */
export const MAX_FORWARD_BYTES = 25 * 1024 * 1024

const ORG_PATH = /^\/api\/organizations\/([0-9a-f-]{36})(\/.*)?$/
const CIPHER_ID_PATH = /^\/api\/ciphers\/([0-9a-f-]{36})(\/.*)?$/
// Privileged access (PAM): leases and access requests belong to the instance that hosts the item.
const PAM_PATH = /^\/api\/(leases|access-requests)(\/|$)/
const LEASE_CIPHER_PATH = /^\/api\/leases\/ciphers\/([0-9a-fA-F-]{36})(\/.*)?$/
const PAM_ID_PATH = /^\/api\/(leases|access-requests)\/([0-9a-fA-F-]{36})(\/.*)?$/
const PAM_LISTS = new Set([
  '/api/leases/mine',
  '/api/leases/active',
  '/api/leases/history',
  '/api/access-requests/inbox',
  '/api/access-requests/mine',
  '/api/access-requests/history',
])
const PAM_LIST_LIMIT = 200
const BULK_IDS = new Set([
  '/api/ciphers/delete',
  '/api/ciphers/restore',
  '/api/ciphers/delete-admin',
  '/api/ciphers/restore-admin',
  '/api/ciphers/admin',
  '/api/ciphers',
  '/api/ciphers/move',
  '/api/ciphers/archive',
  '/api/ciphers/unarchive',
])
const CREATE = new Set(['/api/ciphers', '/api/ciphers/create', '/api/ciphers/admin'])

/** A row of a peer's PAM list: a plain object that carries a string `id`. */
const isListRow = (row: unknown): boolean =>
  typeof row === 'object' &&
  row !== null &&
  !Array.isArray(row) &&
  typeof (row as { id?: unknown }).id === 'string'

async function readBody(c: Ctx): Promise<Uint8Array> {
  if (c.req.method === 'GET' || c.req.method === 'HEAD') return new Uint8Array()
  // The org import keeps its local cap when the target is a federated organisation.
  const imports = new URL(c.req.url).pathname === '/api/ciphers/import-organization'
  await assertBodyWithin(c, imports ? MAX_IMPORT_BODY : MAX_FORWARD_BYTES, () =>
    imports
      ? new ApiError(400, 'You cannot import this much data at once.')
      : new ApiError(413, 'Federated items accept uploads up to 25 MB.'),
  )
  return new Uint8Array(await c.req.raw.clone().arrayBuffer())
}

const parseJson = (b: Uint8Array): Record<string, unknown> | null => {
  try {
    const v = JSON.parse(new TextDecoder().decode(b))
    return v && typeof v === 'object' && !Array.isArray(v) ? v : null
  } catch {
    return null
  }
}

const pick = (o: unknown, ...keys: string[]): unknown => {
  if (!o || typeof o !== 'object') return undefined
  for (const k of keys) if (k in (o as object)) return (o as Record<string, unknown>)[k]
  return undefined
}

const orgIdOf = (body: Record<string, unknown> | null) => {
  const v =
    pick(body, 'organizationId', 'OrganizationId') ??
    pick(pick(body, 'cipher', 'Cipher'), 'organizationId', 'OrganizationId')
  return typeof v === 'string' ? v : null
}

/**
 * Removes `folderId` from a cipher body (top level or under `cipher`): the hosting side cannot see
 * the user's folders. Returns the new body and the folder the user asked for (undefined: none given).
 */
function stripFolder(body: Record<string, unknown> | null): {
  body: Record<string, unknown> | null
  folder: string | null | undefined
} {
  if (!body) return { body, folder: undefined }
  let folder: string | null | undefined
  const take = (o: Record<string, unknown>) => {
    for (const k of ['folderId', 'FolderId']) {
      if (k in o) {
        folder = typeof o[k] === 'string' && o[k] ? (o[k] as string) : null
        o[k] = null
      }
    }
  }
  const copy = structuredClone(body)
  take(copy)
  const inner = pick(copy, 'cipher', 'Cipher')
  if (inner && typeof inner === 'object') take(inner as Record<string, unknown>)
  return { body: copy, folder }
}

async function setFolder(db: Db, user: User, cipherUuid: string, folder: string | null) {
  const del = db
    .delete(schema.federationItemFolders)
    .where(
      and(
        eq(schema.federationItemFolders.userUuid, user.uuid),
        eq(schema.federationItemFolders.cipherUuid, cipherUuid),
      ),
    )
  await runBatch(db, [
    del,
    ...(folder
      ? [
          db
            .insert(schema.federationItemFolders)
            .values({ userUuid: user.uuid, cipherUuid, folderUuid: folder }),
        ]
      : []),
  ] as never)
}

// `cipherAccessState` (PAM) is the state of an item for a member, not an item.
const NOT_A_CIPHER = new Set(['cipherAccessState'])
const isCipher = (o: unknown): o is Record<string, unknown> =>
  !!o &&
  typeof o === 'object' &&
  typeof (o as Record<string, unknown>).object === 'string' &&
  ((o as Record<string, unknown>).object as string).startsWith('cipher') &&
  !NOT_A_CIPHER.has((o as Record<string, unknown>).object as string)

async function overlayFolders(db: Db, user: User, value: unknown): Promise<unknown> {
  const items: Record<string, unknown>[] = []
  if (isCipher(value)) items.push(value)
  const data = pick(value, 'data')
  if (Array.isArray(data)) items.push(...data.filter(isCipher))
  if (items.length === 0) return value
  const folders = await folderOverlay(
    db,
    user.uuid,
    items.map((i) => i.id as string),
  )
  for (const i of items) i.folderId = folders.get(i.id as string) ?? null
  return value
}

const notReachable = (peer: Peer) =>
  new ApiError(
    503,
    peer.status === PeerStatus.Suspended
      ? "This organisation's home instance is suspended by your server's administrator."
      : "This organisation's home instance is not reachable through federation.",
  )

interface ForwardOptions {
  path?: string
  method?: string
  body?: Uint8Array
  /** Cipher whose local folder to set from the request (`'new'`: the id in the response). */
  folderFor?: string
  /** Extra work after a successful response. */
  after?: (json: unknown) => Promise<void>
}

/**
 * Cipher views in a forwarded answer go through the same allowlist as the replica: they must
 * belong to an organisation this peer serves to the user (and be the item asked for); other
 * items are dropped, and a single bad item fails the call.
 */
export async function sanitizeResponse(
  db: Db,
  user: User,
  peer: Peer,
  json: unknown,
  expectId: string | undefined,
): Promise<unknown> {
  const orgs = await db
    .select()
    .from(schema.federationReplicaOrgs)
    .where(
      and(
        eq(schema.federationReplicaOrgs.userUuid, user.uuid),
        eq(schema.federationReplicaOrgs.peerUuid, peer.uuid),
      ),
    )
  const cols = new Map(
    orgs.map((o) => [
      o.organizationUuid,
      new Set((JSON.parse(o.collectionsJson) as { id: string }[]).map((x) => x.id)),
    ]),
  )
  const clean = (item: Record<string, unknown>) => {
    const org = item.organizationId
    const set = typeof org === 'string' ? cols.get(org) : undefined
    return set ? sanitizeCipher(item, org as string, set, peer.domain) : null
  }
  const bad = () => new ApiError(502, 'The home instance of the organisation sent an invalid item.')
  if (isCipher(json)) {
    const out = clean(json)
    if (!out || (expectId && out.id !== expectId)) throw bad()
    return out
  }
  if (json && typeof json === 'object') {
    const o = { ...(json as Record<string, unknown>) }
    if (isCipher(o.cipherResponse)) {
      const out = clean(o.cipherResponse)
      if (!out || (expectId && out.id !== expectId)) throw bad()
      o.cipherResponse = out
    }
    if (Array.isArray(o.data) && o.data.some(isCipher)) {
      o.data = o.data.flatMap((d) => (isCipher(d) ? (clean(d) ?? []) : [d]))
    }
    return o
  }
  return json
}

/** Sends the current request (or a rewritten one) to the hosting side and relays the answer. */
export async function forward(
  c: Ctx,
  peer: Peer,
  user: User,
  opts: ForwardOptions = {},
): Promise<Response> {
  if (!isActive(peer)) throw notReachable(peer)
  const url = new URL(c.req.url)
  const path = opts.path ?? url.pathname
  if (NOT_FEDERATED.test(path)) throw new ApiError(400, NOT_FEDERATED_MESSAGE)
  const method = opts.method ?? c.req.method
  const db = createDb(c.env.DB)
  let body = opts.body ?? (await readBody(c))
  const contentType = c.req.header('content-type') ?? 'application/json'
  let folder: string | null | undefined
  if (contentType.includes('json') && body.byteLength > 0) {
    const stripped = stripFolder(parseJson(body))
    if (stripped.body) {
      folder = stripped.folder
      body = new TextEncoder().encode(JSON.stringify(stripped.body))
    }
    if (folder) await requireFolder(db, user.uuid, folder)
  }
  const res = await peerFetch(
    c.env,
    peer,
    `/federation/v1/members/${user.uuid}/proxy${path}${url.search}`,
    {
      method,
      rawBody: body,
      contentType,
      user: user.uuid,
      device: c.var.auth?.deviceIdentifier ?? null,
    },
  )
  const write = method !== 'GET' && method !== 'HEAD'
  const type = res.headers.get('content-type') ?? ''
  if (!type.includes('json')) {
    if (res.ok && write) await refresh(c, user, peer)
    // Never the peer's own type or disposition: nothing a peer returns runs on this origin.
    const headers = new Headers({
      'content-type': 'application/octet-stream',
      'content-disposition': 'attachment',
      'content-security-policy': "sandbox; default-src 'none'",
      'x-content-type-options': 'nosniff',
    })
    return new Response(res.body, { status: res.status, headers })
  }
  let json: unknown = null
  try {
    json = JSON.parse(await res.text())
  } catch {
    json = null
  }
  if (res.ok) {
    const expectId = opts.folderFor && opts.folderFor !== 'new' ? opts.folderFor : undefined
    json = await sanitizeResponse(db, user, peer, json, expectId)
    json = JSON.parse(rewriteLinks(JSON.stringify(json), c.env, peer))
  }
  if (res.ok) {
    const target =
      opts.folderFor === 'new' ? (pick(json, 'id') as string | undefined) : opts.folderFor
    if (folder !== undefined && target) await setFolder(db, user, target, folder)
    if (opts.after) await opts.after(json)
    if (write) await refresh(c, user, peer)
    json = await overlayFolders(db, user, json)
  }
  return c.json(json as never, res.status as never)
}

async function refresh(c: Ctx, user: User, peer: Peer) {
  try {
    await syncUserFromPeer(c.env, user, peer)
  } catch (err) {
    log('warn', 'federation.refresh_failed', { errorKind: errorKind(err) }, c.env)
  }
}

/** Re-dispatches the request locally with another JSON body (the non-federated part of a bulk call). */
async function dispatchLocal(c: Ctx, body: Record<string, unknown>): Promise<Response> {
  const { app } = await import('../index')
  const headers = new Headers(c.req.raw.headers)
  headers.set('content-type', 'application/json')
  headers.delete('content-length')
  let ctx: ExecutionContext | undefined
  try {
    ctx = c.executionCtx as ExecutionContext
  } catch {
    ctx = undefined
  }
  return app.fetch(
    new Request(c.req.url, { method: c.req.method, headers, body: JSON.stringify(body) }),
    c.env,
    ctx,
  )
}

async function peerForOrg(db: Db, user: User, orgUuid: string) {
  const row = await replicaOrg(db, user.uuid, orgUuid)
  return row?.p
}

/** Bulk calls: federated ids go to their hosting instances, the rest is handled locally. */
async function bulk(c: Ctx, user: User, path: string): Promise<Response | null> {
  const db = createDb(c.env.DB)
  const raw = await readBody(c)
  const body = parseJson(raw)
  const ids = pick(body, 'ids', 'Ids')
  if (!body || !Array.isArray(ids)) return null
  const fed = await federatedCipherOrgs(
    db,
    user.uuid,
    ids.filter((i): i is string => typeof i === 'string'),
  )
  if (fed.size === 0) return null
  if (path === '/api/ciphers/archive' || path === '/api/ciphers/unarchive') {
    throw new ApiError(400, 'Archiving is not available for items of federated organisations.')
  }
  const local = ids.filter((i) => typeof i !== 'string' || !fed.has(i))
  const results: Response[] = []
  if (path === '/api/ciphers/move') {
    const folder = pick(body, 'folderId', 'FolderId')
    const folderId = typeof folder === 'string' && folder ? folder : null
    if (folderId) await requireFolder(db, user.uuid, folderId)
    for (const id of fed.keys()) await setFolder(db, user, id, folderId)
    await db
      .update(schema.users)
      .set({ updatedAt: Date.now() })
      .where(eq(schema.users.uuid, user.uuid))
  } else {
    const byPeer = new Map<string, { peer: Peer; ids: string[] }>()
    for (const [id, org] of fed) {
      const peer = await peerForOrg(db, user, org)
      if (!peer) continue
      const entry = byPeer.get(peer.uuid) ?? { peer, ids: [] }
      entry.ids.push(id)
      byPeer.set(peer.uuid, entry)
    }
    for (const { peer, ids: part } of byPeer.values()) {
      const res = await forward(c, peer, user, {
        body: new TextEncoder().encode(JSON.stringify({ ...body, ids: part })),
      })
      if (!res.ok) return res
      results.push(res)
    }
  }
  if (local.length > 0) {
    const res = await dispatchLocal(c, { ...body, ids: local })
    if (!res.ok) return res
    results.push(res)
  }
  // Restore answers with the restored items; the other bulk calls answer with an empty body.
  const lists = await Promise.all(
    results.map(async (r) =>
      (r.headers.get('content-type') ?? '').includes('json')
        ? await r.json().catch(() => null)
        : null,
    ),
  )
  const data = lists.flatMap((l) =>
    Array.isArray(pick(l, 'data')) ? (pick(l, 'data') as unknown[]) : [],
  )
  if (lists.some((l) => l !== null)) {
    return c.json({ object: 'list', data, continuationToken: null })
  }
  return c.body(null, 200)
}

/** Moves a personal item into a federated organisation: created there, then removed here. */
async function shareInto(
  c: Ctx,
  user: User,
  peer: Peer,
  cipherUuid: string,
  body: Record<string, unknown>,
) {
  const db = createDb(c.env.DB)
  const [own] = await db
    .select()
    .from(schema.ciphers)
    .where(and(eq(schema.ciphers.uuid, cipherUuid), eq(schema.ciphers.userUuid, user.uuid)))
    .limit(1)
  if (!own) throw new ApiError(404, 'Cipher not found.')
  const [att] = await db
    .select({ id: schema.attachments.id })
    .from(schema.attachments)
    .where(eq(schema.attachments.cipherUuid, cipherUuid))
    .limit(1)
  if (att) {
    throw new ApiError(
      400,
      'Items with attachments cannot be moved to an organisation on another instance. Remove the attachments first.',
    )
  }
  const cipher = { ...(pick(body, 'cipher', 'Cipher') as Record<string, unknown>) }
  delete cipher.id
  const collectionIds = pick(body, 'collectionIds', 'CollectionIds') ?? []
  return forward(c, peer, user, {
    method: 'POST',
    path: '/api/ciphers/create',
    body: new TextEncoder().encode(JSON.stringify({ cipher, collectionIds })),
    folderFor: 'new',
    after: async () => {
      const now = Date.now()
      await runBatch(db, [
        db.delete(schema.ciphers).where(eq(schema.ciphers.uuid, cipherUuid)),
        db.update(schema.users).set({ updatedAt: now }).where(eq(schema.users.uuid, user.uuid)),
        federationEventStatement(db, {
          type: FederationEvent.WriteForwarded,
          userUuid: user.uuid,
          actingUserUuid: user.uuid,
          cipherUuid,
          peerDomain: peer.domain,
        }),
      ])
    },
  })
}

/** Every peer that serves the user an organisation, once each. */
async function peersOf(db: Db, user: User): Promise<Peer[]> {
  const rows = await db
    .select({ p: schema.federationPeers })
    .from(schema.federationReplicaOrgs)
    .innerJoin(
      schema.federationPeers,
      eq(schema.federationPeers.uuid, schema.federationReplicaOrgs.peerUuid),
    )
    .where(eq(schema.federationReplicaOrgs.userUuid, user.uuid))
  return [...new Map(rows.map((r) => [r.p.uuid, r.p])).values()]
}

/** True when a lease or an access request with this id exists on this instance. */
async function localPamRow(db: Db, kind: string, id: string): Promise<boolean> {
  const table = kind === 'leases' ? schema.pamLeases : schema.pamAccessRequests
  const [row] = await db.select({ id: table.uuid }).from(table).where(eq(table.uuid, id)).limit(1)
  return row !== undefined
}

/**
 * Lease and access request calls. Calls keyed by an item go to the instance that hosts it. Calls
 * keyed by a lease or request id run locally when this instance holds that row; else the hosting
 * instances are asked in turn and the first one that knows the id answers. The six list routes
 * show the local rows and the rows of every peer that serves the member an organisation.
 */
async function pamCall(
  c: Ctx,
  db: Db,
  user: User,
  path: string,
  next: () => Promise<void>,
): Promise<Response | undefined> {
  const method = c.req.method
  const item = LEASE_CIPHER_PATH.exec(path)?.[1]?.toLowerCase()
  if (item) {
    const org = (await federatedCipherOrgs(db, user.uuid, [item])).get(item)
    const peer = org ? await peerForOrg(db, user, org) : undefined
    return peer ? forward(c, peer, user) : undefined
  }
  const byId = PAM_ID_PATH.exec(path)
  if (byId) {
    const id = (byId[2] as string).toLowerCase()
    if (await localPamRow(db, byId[1] as string, id)) return undefined
    let failure: unknown
    for (const peer of await peersOf(db, user)) {
      try {
        const res = await forward(c, peer, user)
        if (res.status !== 404) return res
      } catch (err) {
        failure ??= err
      }
    }
    // No peer knows the id: a peer that could not be asked may have it, else the local 404 stands.
    if (failure) throw failure
    return undefined
  }
  if (PAM_LISTS.has(path) && method === 'GET') {
    await next()
    const peers = await peersOf(db, user)
    if (peers.length === 0 || c.res.status !== 200) return c.res
    const local = (await c.res
      .clone()
      .json()
      .catch(() => null)) as { data?: unknown[] } | null
    const merged: unknown[] = Array.isArray(local?.data) ? [...local.data] : []
    for (const peer of peers) {
      try {
        const res = await forward(c, peer, user)
        const part = res.ok ? ((await res.json()) as { data?: unknown[] }) : null
        // A peer is not trusted: keep only rows that look like list rows (an object with an id).
        if (Array.isArray(part?.data)) merged.push(...part.data.filter(isListRow))
      } catch (err) {
        // A peer that cannot answer leaves its rows out; the local rows still show.
        log('warn', 'federation.pam_list_failed', { errorKind: errorKind(err) }, c.env)
      }
    }
    const stamp = (row: unknown) => {
      const v = pick(row, 'submittedAt', 'notBefore')
      return typeof v === 'string' ? Date.parse(v) || 0 : 0
    }
    merged.sort((a, b) => stamp(b) - stamp(a))
    return c.json({
      object: 'list',
      data: merged.slice(0, PAM_LIST_LIMIT),
      continuationToken: null,
    })
  }
  return undefined
}

/**
 * Middleware on `/api/ciphers*`, `/api/leases*`, `/api/access-requests*` and `/api/organizations/*`. Does nothing unless federation is on
 * and the caller holds a federated organisation, so normal requests pay one indexed lookup.
 */
export const federationForwarder: MiddlewareHandler<Env> = async (c, next) => {
  if (!federationEnabled(c.env)) return next()
  const match = /^Bearer\s+(\S+)$/i.exec(c.req.header('Authorization') ?? '')
  if (!match?.[1]) return next()
  const authed = await authenticateAccessToken(c.env, match[1])
  if (!authed) return next()
  c.set('user', authed.user)
  c.set('auth', { claims: authed.claims, deviceIdentifier: authed.claims.device })
  const user = authed.user
  const db = createDb(c.env.DB)
  const [any] = await db
    .select({ id: schema.federationReplicaOrgs.organizationUuid })
    .from(schema.federationReplicaOrgs)
    .where(eq(schema.federationReplicaOrgs.userUuid, user.uuid))
    .limit(1)
  if (!any) return next()

  const url = new URL(c.req.url)
  const path = url.pathname.replace(/\/+$/, '') || '/'
  const method = c.req.method

  const om = ORG_PATH.exec(path)
  if (om) {
    const peer = await peerForOrg(db, user, om[1] as string)
    return peer ? forward(c, peer, user) : next()
  }
  if (PAM_PATH.test(path)) {
    const res = await pamCall(c, db, user, path, next)
    if (res) {
      // A merged list replaces the local answer; any other answer comes from a peer.
      if (res !== c.res) c.res = res
      return res
    }
    return next()
  }
  if (!path.startsWith('/api/ciphers')) return next()

  const queryOrg = url.searchParams.get('organizationId')
  if (queryOrg) {
    const peer = await peerForOrg(db, user, queryOrg)
    if (peer) return forward(c, peer, user)
  }

  const cm = CIPHER_ID_PATH.exec(path)
  if (cm) {
    const id = cm[1] as string
    const rest = cm[2] ?? ''
    const fed = await federatedCipherOrgs(db, user.uuid, [id])
    const org = fed.get(id)
    if (org) {
      const peer = await peerForOrg(db, user, org)
      if (!peer) return next()
      if (rest === '/archive' || rest === '/unarchive') {
        throw new ApiError(400, 'Archiving is not available for items of federated organisations.')
      }
      return forward(c, peer, user, { folderFor: id })
    }
    if (rest === '/share' && (method === 'PUT' || method === 'POST')) {
      const body = parseJson(await readBody(c))
      const target = orgIdOf(body)
      const peer = target ? await peerForOrg(db, user, target) : undefined
      if (peer && body) return shareInto(c, user, peer, id, body)
    }
    return next()
  }

  if (CREATE.has(path) && method === 'POST') {
    const target = orgIdOf(parseJson(await readBody(c)))
    const peer = target ? await peerForOrg(db, user, target) : undefined
    if (peer) return forward(c, peer, user, { folderFor: 'new' })
  }
  if (path === '/api/ciphers/share' && (method === 'PUT' || method === 'POST')) {
    const body = parseJson(await readBody(c))
    const ciphers = pick(body, 'ciphers', 'Ciphers')
    const first = Array.isArray(ciphers) ? orgIdOf(ciphers[0] as Record<string, unknown>) : null
    if (first && (await peerForOrg(db, user, first))) {
      throw new ApiError(400, 'Move items to an organisation on another instance one at a time.')
    }
  }
  if (path === '/api/ciphers/bulk-collections') {
    const target = orgIdOf(parseJson(await readBody(c)))
    const peer = target ? await peerForOrg(db, user, target) : undefined
    if (peer) return forward(c, peer, user)
  }
  if (BULK_IDS.has(path) && method !== 'GET') {
    const res = await bulk(c, user, path)
    if (res) return res
  }
  return next()
}
