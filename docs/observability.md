# Observability

Cloudwarden logs structured JSON lines through `src/log.ts` and relies on Workers Logs to store and query
them. The Worker handles encrypted vault data and credentials, so the rule is: log metadata, never content.

## What is logged

One line per request, emitted after the handler finishes:

```json
{"ts":"<ISO timestamp>","level":"info","event":"request","requestId":"...","method":"GET","route":"/api/config","status":200,"durationMs":3}
```

- `requestId` is the inbound `cf-ray` value when it is well formed, otherwise a random UUID. It is also returned
  as the `X-Request-Id` response header so a user can quote it in a report.
- `route` is the matched route pattern (`/icons/:domain/icon.png`), not the raw path, so ids and domains in URLs
  do not enter the log. Unmatched requests log `unmatched`.
- Other events: `unhandled` (error class only), `icon.refused` (reason code only), `backup.done`,
  `backup.failed`.

## What is never logged

Request or response bodies, query strings, headers, tokens, cookies, passwords and hashes, emails, names,
ciphertext, keys, IP addresses. Enforcement:

- `log()` drops any field whose key matches `pass`, `token`, `secret`, `auth`, `cookie`, `email`, `body`, `hash`,
  `key`, `salt`, `stamp`, `cipher`, `name`, `hint` or ends in `ip`; only strings, numbers, booleans and null are
  kept; strings are cut at 200 characters.
- Errors are logged by class (`errorKind`), never by message, because messages can echo input.
- `test/log.test.ts` asserts that a request carrying a secret body, query and email produces a line containing
  none of them.

Code review rule: never call `console.*` directly with request-derived data; use `log()`.

## Configuration

`cloudflare.config.ts` enables Workers Logs (`observability.enabled`, `logs.enabled`, invocation logs, sampling
rate 1). Lower `headSamplingRate` if volume or cost matters. `LOG_LEVEL` (`debug`, `info`, `warn`, `error`;
default `info`) filters at the source.

Workers Logs retention and query limits depend on your Cloudflare plan. Tail live with `cf workers tail` or
search `cf cli search "tail worker logs"` for the exact command in your `cf` version.

## Workers Analytics

Request counts, error rates, CPU time and subrequests are available in the dashboard under the Worker's
Metrics tab without any code. Useful alerts: 5xx rate, scheduled-handler failures (backup), and a drop in
requests to `/identity/connect/token`.

## Log review checklist

Before a release, search the last day of logs for: `Bearer`, `@`, `masterPasswordHash`, `access_token`,
`refresh_token`, and base64 runs longer than 40 characters. Any hit is a bug in the log call that produced it.
