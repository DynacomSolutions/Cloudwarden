// D1 Sessions API wrapper (TASKS #165). Read replication is off, so this is inert by default;
// `D1_SESSIONS=true` opts in. See docs/d1-sessions.md.
import type { MiddlewareHandler } from 'hono'
import type { Bindings, Env } from '../env'

/** Request and response header carrying the D1 bookmark. */
export const D1_BOOKMARK_HEADER = 'x-d1-bookmark'

export const sessionsEnabled = (env: Pick<Bindings, 'D1_SESSIONS'>): boolean =>
  env.D1_SESSIONS === 'true'

// Bookmarks are opaque dash separated hex words. Anything else is ignored, never trusted.
const BOOKMARK = /^[0-9A-Za-z._-]{1,256}$/

/**
 * Where a session starts. A valid client bookmark lets reads use any replica that has caught
 * up to it. Without one the session starts on the primary, so a client that cannot send
 * bookmarks (the official ones cannot) never reads behind its own writes.
 */
export const sessionConstraint = (header: string | undefined): string =>
  header && BOOKMARK.test(header) ? header : 'first-primary'

/**
 * Runs the request on a D1 session and returns the session bookmark in `x-d1-bookmark`.
 * Handlers keep calling `createDb(c.env.DB)`; they receive the session in place of the binding.
 * Only `prepare` and `batch` are used by the data layer, which the session provides.
 */
export const d1Sessions: MiddlewareHandler<Env> = async (c, next) => {
  const db = c.env.DB
  if (!sessionsEnabled(c.env) || typeof db.withSession !== 'function') return next()
  const session = db.withSession(sessionConstraint(c.req.header(D1_BOOKMARK_HEADER)))
  c.env = { ...c.env, DB: session as unknown as D1Database }
  await next()
  const bookmark = session.getBookmark()
  if (bookmark) {
    try {
      c.res.headers.set(D1_BOOKMARK_HEADER, bookmark)
    } catch {
      // Immutable responses (WebSocket upgrades) carry no bookmark.
    }
  }
}
