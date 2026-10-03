# Organisation API, Directory Connector, SCIM and event integrations

TASKS #270 to #276. Everything here is per organisation and needs no extra Cloudflare binding.

## Organisation API key and Public API

An owner opens **Admin Console, Settings, Organization info, API key** (the upstream web client
page) and confirms their master password. The dialog shows:

| Field | Value |
|---|---|
| `client_id` | `organization.<organization id>` |
| `client_secret` | the 30 character API key |
| `scope` | `api.organization` |
| `grant_type` | `client_credentials` |

`POST /identity/connect/token` with those fields returns an organisation token (one hour). It is
accepted only by the Public API; user endpoints reject it, and member tokens are rejected by the
Public API. **Rotate API key** replaces the key and revokes every token issued from the old one.
Keys are stored sealed (see below), never in clear.

The Public API is served at `<base>/api/public/*` (the self-hosted layout) and `<base>/public/*`
(the cloud layout), with Bitwarden's documented models:

| Resource | Operations |
|---|---|
| `members` | list, invite, get, update (type, permissions, collections, groups, external id), remove, `group-ids` get and set, `reinvite`, `revoke`, `restore` |
| `groups` | list, create, get, update, delete, `member-ids` get and set |
| `collections` | list, get, update (external id and group access), delete. Creating a collection needs its encrypted name, so it stays in the web client |
| `policies` | list, get, update |
| `events` | list with `start`, `end`, `actingUserId`, `itemId`, `continuationToken` |
| `organization/import` | directory import, below |

Policies saved through the Public API go through the same code as the Admin Console (for example,
requiring two-step login revokes non-compliant members). An organisation that no longer exists
(or, once organisations can be disabled, is disabled) is refused at token issue and on every
request. Changes made through the Public API act with admin authority: owners can be neither created nor
changed, matching an admin in the web client. Events they raise carry `systemUser: 3` and no
acting user. Billing endpoints (`organization/subscription`) are not served: there is no billing.

The contract is in `docs/api/openapi.yaml` (tag `PublicApi`) and checked by
`test/public-api.test.ts`.

## Directory Connector

The official Bitwarden Directory Connector (GPL-3.0, github.com/bitwarden/directory-connector)
works unchanged. Point it at the server (`bwdc config server https://vault.example.com`), log in
with the organisation `client_id` and `client_secret`, configure the directory and run
`bwdc sync`. It sends `POST /public/organization/import`:

- members are matched by external id, then by email; unknown addresses are invited (an email is
  sent unless the connector's "invite users after provisioning" option is off);
- `deleted: true` entries are removed from the organisation;
- groups are matched by external id, renamed and their membership replaced;
- with **Remove and re-add organization users during the next sync** (`overwriteExisting`),
  members and groups whose external id is not in the import are removed;
- owners are never removed, and admins and custom members are not removed either unless the
  request sets `removePrivilegedMembers: true` (a Cloudwarden extension the connector does not
  send), so a directory mistake cannot lock the administrators out. Large imports arrive in several
  requests and are applied in slices.

`pnpm e2e` runs the connector's Linux CLI (`bwdc`, pinned with a checksum in `e2e/bwdc.lock.json`)
against a small LDAP server (`e2e/ldap-server.mjs`) and checks the members and groups it creates.

## SCIM 2.0

**Admin Console, Settings, SCIM provisioning** (Cloudwarden's own page) enables SCIM, shows the
SCIM URL and shows or rotates the SCIM API key (key type 2 of the organisation API key endpoints,
separate from the Public API key). The endpoint is

    https://vault.example.com/scim/v2/<organization id>

(`/v2/<organization id>` works too). Identity providers send the key as a Bearer token:

- **Microsoft Entra ID**: Enterprise application, Provisioning, Automatic. Tenant URL is the SCIM
  URL, Secret token is the SCIM API key. Keep the default attribute mappings (`userName`,
  `active`, `emails[type eq "work"].value`, `externalId`, `displayName`; groups `displayName`,
  `members`, `externalId`).
- **Okta**: SCIM 2.0 app integration with header authentication. Base URL is the SCIM URL, API
  token is the SCIM API key, unique identifier field `userName`. Enable Create Users,
  Update User Attributes, Deactivate Users and Push Groups.

What the provider's operations do:

| SCIM | Cloudwarden |
|---|---|
| `POST /Users` | invite the address as a user (409 `uniqueness` when the email or external id is already a member) |
| `PATCH` or `PUT /Users/{id}` with `active: false` | revoke the member |
| ... with `active: true` | restore the member (to invited, accepted or confirmed, as before) |
| `DELETE /Users/{id}` | remove the member |
| `POST`, `PUT`, `PATCH`, `DELETE /Groups` | create, rename, change membership of, delete the group |

Filters follow RFC 7644 (`eq ne co sw ew gt ge lt le pr`, `and`, `or`, `not`, parentheses, value
paths such as `emails[type eq "work"]`, case-insensitive except `id` and `externalId`), as do
PATCH operations (paths, value filters, sub-attributes, URN-qualified names, operations without a
path, Entra ID's `"True"` and `"False"` strings). `startIndex`, `count`, `attributes` and
`excludedAttributes` are supported; bulk, sorting and ETags are not
(`/ServiceProviderConfig` says so). Owners cannot be revoked or removed through SCIM. Events carry
`systemUser: 1`. Failed SCIM authentication is rate limited per client address and organisation
(HTTP 429 once exceeded).

## Event export and integrations

The event log (**Reporting, Event logs**) exports to CSV in the upstream web client; it pages
through `GET /api/organizations/{id}/events`.

**Admin Console, Integrations** (Cloudwarden's own page, owners and admins) forwards events as they
are written:

| Type | Request |
|---|---|
| Webhook | one `POST` per event to an https URL, JSON body (the event log object plus `id`), headers `X-Cloudwarden-Event-Id`, `X-Cloudwarden-Timestamp` (Unix seconds) and `X-Cloudwarden-Signature: v1=<hex HMAC-SHA256 of "<timestamp>.<body>" under the signing secret>`, plus one optional header of your choice (for example `Authorization`) |
| Splunk HTTP Event Collector | `POST <HEC URL>/services/collector/event`, `Authorization: Splunk <token>`, one event object per line with `time`, `host`, `source`, `sourcetype`, optional `index` |
| Datadog | `POST https://http-intake.logs.<site>/api/v2/logs`, `DD-API-KEY`, `ddsource: cloudwarden`, optional service and tags |
| Microsoft Sentinel | client credentials token from Entra ID (`https://monitor.azure.com/.default`), then the Logs Ingestion API: `POST <endpoint>/dataCollectionRules/<dcr id>/streams/<stream>?api-version=2023-01-01` with `TimeGenerated`, `EventId`, `EventType` and `Event` columns |

To verify a webhook, recompute the HMAC over the timestamp header, a full stop and the raw body,
compare in constant time, and reject old timestamps (for example older than five minutes). The
signing secret is shown once when the webhook is created or rotated.

Delivery runs from a one-minute cron trigger (`* * * * *`). Each integration keeps a cursor over
the events table, so events go out in the order they were written, starting from the moment the
integration was created. A failed request (non-2xx answer, timeout or network error) leaves the
cursor where it was and retries after 30 seconds, doubling up to six hours; nothing is dropped. A
five minute lease stops overlapping runs sending twice. **Send test event** sends a synthetic
event straight away. Optional event type filters (for example `1100-1116, 1500`) limit what is
sent.

Destination URLs must be https on a public DNS name (IP literals and reserved names such as
`localhost` are refused). Before each run's first request to a host, the host name is resolved
over DNS over HTTPS and refused if any address is private, loopback, link-local or otherwise not
public, which narrows DNS rebinding (the Workers runtime then resolves again itself; Workers
cannot reach private networks in any case). Every request times out after 10 seconds, up to six
integrations are delivered at once, and a run starts no new batch after 25 seconds, so one slow
receiver cannot hold up other organisations. Response bodies are never stored or logged; the page
shows only the HTTP status of the last failure. **Send test event** is rate limited.

When an edit changes where events go (webhook URL, Splunk URL, Datadog site, Sentinel tenant,
client or endpoint), stored tokens are not carried over and must be entered again, so a token can
never be redirected to another host. The webhook signing secret stays, since it is never sent.

**Personal data.** Events contain member, item and collection ids, the acting user id, the device
type and the client IP address. Tick **Leave out IP addresses** on an integration to send events
without `ipAddress`. Choose destinations whose retention suits your data protection duties.

## Secrets at rest

Organisation API keys, SCIM keys and integration tokens are encrypted with AES-256-GCM
(`src/orgs/sealed.ts`) under a key derived with HKDF-SHA256 from the `DATA_ENCRYPTION_KEY` Worker
secret (32 or more characters):

    openssl rand -base64 48 | cf workers secrets update DATA_ENCRYPTION_KEY

Without it the key is derived from `JWT_SECRET` under a separate label, so nothing breaks, but a
leaked `JWT_SECRET` would then also expose these values. Each value records which source sealed
it, so setting `DATA_ENCRYPTION_KEY` later keeps older values readable; rotate the API keys and
re-save the integrations afterwards to move them to the new key. Rotating `JWT_SECRET` while
`DATA_ENCRYPTION_KEY` is unset makes those values unreadable: set `DATA_ENCRYPTION_KEY` first.

## Client integrations API

`/api/organizations/{orgId}/integrations` and its `/configurations` (the generated clients' API)
sit on the same storage as `/event-integrations`. Type 5 (Hec) is a Splunk destination, 6 a Datadog
site (the `uri` must be a Datadog log intake address) and 4 a signed webhook whose address and
credential arrive on its single configuration. Tokens and keys are write-only: responses carry the
settings without them, and an update that moves the destination must send the token again.
Delivery starts with the first configuration and sends the configured event types (a configuration
without an event type means all). `template` and `filters` are stored and returned, but events keep
the fixed formats above. Slack and Teams (types 3 and 7, redirect, callback and channel endpoints)
answer 400: this server has no Slack or Teams app. `POST /api/installations` is a cloud service
that the official self-hosted server does not expose, so Cloudwarden does not either.
