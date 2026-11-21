# Privileged access management

Cloudwarden serves the privileged access area of the Bitwarden client API: access connectors that rotate credentials, access rules, access requests and leases. The wire contract is the generated `bitwarden-api-api` crate of github.com/bitwarden/sdk-internal (GPL-3.0 or the Bitwarden SDK License, dual): request and response models, enums and routes. No client code from `bitwarden_license/` and no Bitwarden server code was read or copied. The sign-in scheme, the rule `conditions`, and every state rule are Cloudwarden designs, written from the model shapes and the doc comments of the generated client. The routes are in `docs/api/openapi.yaml` under the `PrivilegedAccess` tag.

Everything is end-to-end encrypted as before. The server stores ciphertext (`sealedData`, `wrappedKey`, items) and never reads it.

## Roles

| Who | Can do |
|---|---|
| Owner or admin | Administer connectors, target systems, rotation configurations and access rules. Decide any request. Revoke any lease. |
| Member with Manage access to a collection | Decide requests and revoke leases for items in that collection. |
| Member with privileged access (`PUT /api/organizations/{id}/users/enable-pam`) | Request leases on items that an access rule covers. |
| Access connector | Call only the connector-facing rotation routes. |

Nobody can decide their own request.

## Access connectors and rotation

### Objects

- **Target system.** A system whose credentials get rotated. Method `Automatic` (a connector rotates) or `Manual` (an operator rotates and records it). A new target system is `PendingSeal`. A client seals it with `PUT .../target-systems/{id}` (`sealedData`, `wrappedKey`), which makes it `Active`. A target system can be disabled and enabled. A configuration still uses it: delete answers 409.
- **Access connector.** A daemon. Registration returns `apiKeyId` and `clientSecret` once. Only a SHA-256 hash of the secret is stored. A connector works only on target systems assigned to it. Disabling a connector is reversible and releases its running jobs. Deleting it removes its credential.
- **Rotation configuration.** One per organisation item (a login). It names the target system, holds the sealed settings, an optional five-field UTC cron schedule and `rotateOnAccessEnd`.
- **Rotation job.** One unit of work for a configuration. Source `Scheduled`, `OnDemand` or `AccessEnd`. A partial unique index allows one open job (Pending or Claimed) per configuration.
- **Attempt.** One try at a job by one connector.

### Connector sign-in

A connector reuses the machine account design. It sends to `POST /identity/connect/token`:

```
grant_type=client_credentials
scope=api.access-connector
client_id=access-connector.<apiKeyId>
client_secret=<clientSecret>
```

The answer holds a one hour bearer token (`type` claim `AccessConnector`) and the opaque `encrypted_payload` and `key` stored at registration. The server reads the connector row on every request, so disable and delete take effect at once. User tokens are refused on connector routes. Connector tokens are refused on every other route.

### Job state machine

```
Pending --claim--> Claimed --success--> Succeeded
   |                  |  \--failure--> Failed
   |                  \--release (connector disabled, deleted, unassigned, silent) --> Pending
   \--lifetime ends (6 hours)--> TimedOut   (also from Claimed)
```

- **Poll.** `GET /api/access-connectors/rotation/jobs` lists the Pending jobs on the assigned, active targets of enabled configurations. It is also the heartbeat. A connector counts as connected for two minutes after its last call.
- **Claim.** `POST .../jobs/{id}/claim` is one guarded `UPDATE ... WHERE status = Pending`, batched with the attempt insert. The first claim wins. 409: another connector won. 404: not eligible (no assignment, other organisation, disabled target or configuration). The answer holds the sealed target and configuration data and `executeBy` (five minutes).
- **Read and write.** `GET .../attempts/{id}/cipher` returns the item (`object: cipherMini`) for an attempt that still holds its claim. `PUT` writes the rotated login. The body is a login item request with `lastKnownRevisionDate` from the read. The item key and organisation must stay the same. The write is guarded on the revision and on the claim. A moved revision or lost claim answers 409 and is audited as `write_rejected`.
- **Report.** `success` needs a written item first (otherwise 409, audited `report_rejected`). `failure` takes `syncState`, a code up to 64 characters and a detail up to 256. The two are joined and cut to 300 characters.
- **Sweep.** The minute cron releases claims whose five minute lease ended while the connector is silent, times out jobs after six hours, and queues `Scheduled` jobs for due configurations.
- **Manual targets.** A rotate request, or a due schedule, sets `awaitingManualRotation`. `record-manual` clears it.
- **On demand.** `POST .../rotate` has a one minute cooldown per configuration (429). With a job already open it answers 409.

## Access rules, requests and leases

### Access rule

A rule names collections (a collection belongs to at most one rule). Where several rules cover one item, the first of these wins: human approval, then the smallest maximum lease, then the oldest rule and the lease terms: default and maximum duration, `singleActiveLease`, extensions (`allowsExtensions`, `maxExtensionDurationSeconds`), and `conditions`. `conditions` is an opaque JSON object. Cloudwarden reads `approvalMode`: `"Automatic"` grants at once, anything else (default) needs a human. A disabled rule stops new requests. Existing leases continue. Deleting a rule cancels its pending requests.

### Request and lease state machine

```
request: Pending --approve--> Approved --activate--> (lease Active)
            |  \--deny--> Denied            Approved --revoke / deadline--> Cancelled / Expired
            \--revoke--> Cancelled          Pending  --deadline (7 days)--> Expired
lease:   Active --time--> Expired    Active --approver--> Revoked    Active --requester--> Cancelled
```

- **Create.** `POST /api/leases/ciphers/{id}` needs an item in a collection that an enabled rule covers, access to that item, and privileged access. With `start` and `end` the window is fixed. Otherwise `durationSeconds` (default from the rule, at most the maximum). One open request per member and item (partial unique index). A live lease of the member also blocks a new request.
- **Automatic rule.** The request, an automatic decision and the lease are written in one batch. The result is `approvalMode: 0` and a produced lease.
- **Human rule.** The request is `Pending`. Approvers see it in `inbox`. `decision` is one guarded update `WHERE status = Pending AND not expired`. One approver wins, the other gets 409. Approval is valid for 24 hours, or until the requested window ends. A window that starts later gets its 24 hours from its start.
- **Activate.** Only the requester. One guarded insert: it succeeds only while the request is Approved and in time, has no lease yet (unique index on the request), and under `singleActiveLease` no other live lease exists on the item. Zero rows inserted answers 409.
- **Extend.** `POST /api/leases/{id}/extend` needs a rule that allows extensions and a reason. The duration is at most the maximum extension, and the whole lease (from `notBefore` to the new `notAfter`) never passes the maximum lease length of the rule. An automatic rule moves `notAfter` at once. A human rule creates a Pending request (one per lease). Approval moves `notAfter` in the same batch, only while the lease is live.
- **Revoke.** `POST /api/leases/{id}/revoke`. The requester cancels (status 3), an approver revokes (status 2). `POST /api/access-requests/{id}/revoke` withdraws a request without a lease, or ends its lease.
- **Read clock.** Status is derived at read time: a stored Active lease past `notAfter` reads as Expired. A Pending or Approved request past its deadline reads as Expired.
- **Sweep.** The minute cron stores those expiries and queues an `AccessEnd` rotation job when the item has a configuration with `rotateOnAccessEnd`. Revocation queues it at once.
- **Lists.** `mine` lists the caller's open requests or live leases. `inbox` lists Pending requests the caller may decide. `active` lists live leases the caller holds or may revoke. `history` lists the ended ones. Lists hold at most 200 rows and have no continuation token.

### Pre-check and state

`GET /api/leases/ciphers/{id}/pre-check` answers the approval mode, the duration limits, whether a lease can start, and (under a single lease rule) when the slot frees. `GET .../state` answers the caller's live lease, pending or approved request, and whether extensions and new requests are possible.

## Lease enforcement

A lease is enforced on the server. The model follows the official clients: an item that an enabled access rule covers reaches a member without a live lease only as a **reduced row** (a "restricted" or "partial" cipher), and a live lease turns it into the full item. The clients cannot request a lease for an item they cannot see, so the row keeps the name.

- **Who is restricted.** A member who is not an owner or admin of the organisation, holds no Manage access to a covered collection (a decider), and holds no live lease on the item. An item is restricted when any of its collections is covered, even when the member also reaches it through a collection that no rule covers. An item in no covered collection is never restricted.
- **The reduced row.** `partialData` is a JSON string with the encrypted `name` and, for a login, the encrypted `uris`. The cipher `key` stays, so the client can decrypt the name. `login`, `card`, `identity`, `secureNote`, `sshKey`, `notes`, `fields`, `passwordHistory`, `data` and `attachments` are null. `edit` and `viewPassword` are false, and `permissions.delete` and `permissions.restore` are false.
- **Where it applies.** `/api/sync`, the item routes (`GET /api/ciphers/{id}` and the bulk and admin variants), `organization-details`, the organisation export, the federation feed and every attachment route. Writes to a restricted item answer 403, and attachments answer 403.
- **Live lease.** Status Active, between `notBefore` and `notAfter`. A lease on a scheduled window gives nothing before `notBefore`. A revoke or cancel takes the item back at the next sync. Expiry takes it back as soon as `notAfter` passes: the server checks the time on every read, and the minute sweep only stores the status.
- **Resync.** Activating, revoking, cancelling or expiring a lease moves the member revision date and pushes a sync, so clients fetch the new row at once. Creating, changing or deleting a rule moves the revision date of every member.
- **Limits.** Custom members with the "manage all items" permission are restricted like members on the item routes, but owners and admins are not. Items the member already holds on a device stay on that device until the next sync: the server cannot recall a copy that a client has decrypted.

## Limits of this implementation

- Rotation changes only the stored ciphertext. The connector changes the real credential on the target system.
- No Bitwarden event type exists for this area, so no organisation events are written. The server keeps its own audit table (`pam_audit`) with the kinds `connector_registered`, `rotation_claimed`, `write_rejected`, `report_rejected`, `lease_activated`, `lease_revoked` and others. No route reads it yet.
- The bypassable-ciphers route of access rules and the access audit routes of the SDK are not served.

## Data

Migrations `0036_privileged_access_rotation` (connectors, target systems, assignments, configurations, jobs, attempts, audit) and `0037_privileged_access_leases` (rules, requests, decisions, leases). Tests: `test/pam-rotation.test.ts`, `test/pam-leases.test.ts`, `test/pam-enforcement.test.ts`, `test/pam-cron.test.ts`.
