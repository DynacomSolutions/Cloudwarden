# D1 read replication and the Sessions API

## Status

D1 **read replication is off** for Cloudwarden. Every query runs on the primary, so reads always
see the latest write and revision dates cannot go backwards. Nothing in this repository enables
replication, and the deploy guide does not ask for it.

Replication is not needed at personal or small-team scale (a vault is a few hundred KB and a sync
is a handful of queries). It only lowers read latency for users far from the primary.

## If you turn replication on anyway

Querying the plain `DB` binding still reaches the primary only, even with replication enabled, so
turning it on does not by itself change behaviour. To let reads use replicas without ever showing
a client older data than it wrote (a stale `revisionDate` makes the next edit fail the
`lastKnownRevisionDate` check and breaks sync), requests must run on a D1 session that carries a
bookmark. `src/db/sessions.ts` is a thin wrapper for that, gated by a variable:

| Variable | Default | Effect |
|---|---|---|
| `D1_SESSIONS` | `false` | `true` runs every request on `DB.withSession(...)` and returns the session bookmark in the `x-d1-bookmark` response header |

How it behaves when enabled:

- A request carrying a plausible `x-d1-bookmark` header starts its session at that bookmark, so
  reads may use any replica that has caught up to it.
- A request without one (every official Bitwarden client, which cannot send custom headers) starts
  with `first-primary`, so its first query goes to the primary. This keeps those clients
  consistent but means they gain nothing from replicas.
- Headers that are not bookmark shaped (letters, digits, `.`, `_`, `-`, at most 256 characters)
  are ignored.
- Handlers are unchanged: the middleware replaces `c.env.DB` with the session, and the data layer
  only uses `prepare` and `batch`, which a session provides. Scheduled jobs and Durable Objects
  keep using the plain binding (primary).
- Writes always go to the primary, whatever the session says.

Because only bookmark aware callers (scripts, the admin UI, a custom client) can use replicas,
enabling this is only worthwhile with such a caller. Tests in `test/d1-sessions.test.ts` check the
default is inert, the constraint choice, bookmark round trips and that revision dates never regress
and stale updates are still rejected with the wrapper on.
