# Federated organisations

Cloudwarden extension (TASKS #300 to #309), not part of the Bitwarden API. A user with an account
on one Cloudwarden instance can be a member of an organisation hosted on another instance and use
it from the official clients as if it were a local organisation: the items appear in the normal
sync, can be edited, shared into, deleted and restored, and changes arrive live.

Federation is off unless `FEDERATION_ENABLED` is `true`. Off, every federation route answers 404
and nothing in the normal request path changes.

## Terms

| Term | Meaning |
|---|---|
| Hosting instance (A) | Owns the organisation, its keys (wrapped), items, collections and policies. Every permission decision is made here. |
| Serving instance (B) | Holds the user's account. The user's clients only ever talk to B. |
| Peer | Another instance this instance is paired with. |
| Stand-in account | A row in A's `users` table that represents B's user. Its id equals the user's id on B, its public key is the user's public key on B, and it has no usable password. |
| Replica | B's copy of what the user can see of the organisation on A: the profile entry, collections, policies and item views (all EncStrings as stored on A). |

## Protocol

### Instance identity

Each instance has one Ed25519 key pair (`federation_identity`). The private key is encrypted with
AES-256-GCM under a key derived by HKDF-SHA-256 from `FEDERATION_KEY_SECRET` (or `JWT_SECRET` when
that is unset), so a database dump alone does not reveal it. The public descriptor is served at
`GET /.well-known/cloudwarden-federation`:

```json
{
  "protocol": "cloudwarden-federation",
  "version": 1,
  "instanceId": "00000000-0000-0000-0000-000000000000",
  "domain": "vault.example.com",
  "algorithm": "ed25519",
  "publicKey": "<raw key, base64url>",
  "fingerprint": "<SHA-256 of the raw key, hex, groups of four>",
  "endpoints": { "api": "/federation/v1" }
}
```

Rotating the instance key means removing the peering on both sides and pairing again; a peer that
presents a different key for a known domain is refused.

### Signed requests

Every server-to-server request is signed with RFC 9421 HTTP Message Signatures:

```
Content-Digest: sha-256=:<base64 SHA-256 of the body>:
Cloudwarden-Federated-User: <user id or ->
Cloudwarden-Federated-Device: <client device identifier or ->
Signature-Input: fed=("@method" "@target-uri" "content-type" "content-digest" "cloudwarden-federated-user" "cloudwarden-federated-device");created=<unix>;expires=<created+300>;nonce="<random>";keyid="<sender instance id>";alg="ed25519";tag="cloudwarden-federation"
Signature: fed=:<base64 Ed25519 signature of the signature base>:
```

The receiver accepts only this exact component list, checks `created` within 300 seconds of its
clock, `expires` not passed, the Content-Digest against the body, the signature against the peer's
stored key (looked up by `keyid`), and records the nonce per peer (`federation_nonces`); a second
use of a nonce is a replay and gets 401. Only active peers (approved on both sides, not suspended)
are accepted (403 otherwise), each limited to 600 requests per minute (429). The pairing request
spends its nonce before anything is written; at most 20 peers may wait for approval and pairing
requests are limited per address and per instance.

Responses are not signed. Their authenticity rests on TLS to the paired domain as the Workers
runtime validates it (certificate checks cannot be turned off from Worker code). The DNS over
HTTPS address check runs before each call, but the runtime resolves the name again when it
connects, so it narrows DNS rebinding rather than excluding it; Workers cannot reach private
networks in any case. Everything a peer returns is treated as untrusted input (see "Replica and
sync").

### Outbound requests

Peers are named by host name only. Outbound calls go to `https://<domain>` on port 443, with no
IP literals, `localhost`, `.local`, `.internal` or `.arpa` names. Before each call every A and AAAA
record of the host is resolved over DNS over HTTPS and the call is refused when any of them is
loopback, private (RFC 1918, unique local), link-local, CGNAT, multicast or otherwise reserved.
Redirects are refused, calls time out after 15 seconds and response bodies are size limited.

### Pairing

1. An instance admin on A opens Instance admin, Federation, and adds B's domain. A fetches B's
   descriptor and shows its fingerprint. The peer is `pending`.
2. The admins compare fingerprints out of band (for example by phone). A's admin types or pastes
   B's fingerprint to approve; a mismatch is refused. A then sends a signed `POST /federation/v1/pair`
   to B. B fetches A's descriptor from the claimed domain to bind the key to it, verifies the
   signature and records A as a pending peer that approved.
3. B's admin does the same for A. When both sides have approved the peer becomes `active`.

Admins can suspend a peer (effective immediately: requests in both directions are refused and
federated organisations disappear from users' vaults until it is resumed), run a health check
(signed ping) and remove it (unpair: both sides purge everything tied to the peer).

### Federated membership

1. An organisation admin on A invites `user@example.org` from Admin Console, Federated members,
   choosing the peer. A creates an invited membership (with its role, collections and groups) and
   sends a signed invitation to B. B refuses unknown addresses (the invitation fails on A) and
   stand-in accounts (no chains of instances).
2. B emails the user and lists the invitation in the web vault (Federated invitations). The user
   accepts or declines there. Accepting sends the user's id, address, name and public key to A.
3. A creates the stand-in account (id and public key as on B) and marks the membership accepted.
4. A's admin confirms the member with the standard Confirm action. The web client fetches the
   public key, shows the usual fingerprint phrase (the same phrase the user sees on B, because the
   user id and key are the same) and wraps the organisation key with that public key in the
   browser. Servers never see organisation keys.

Roles, custom permissions, collections and groups are those of a local member and are enforced on
A for every request.

### Replica and sync

B keeps per user: `federation_replica_orgs` (profile entry, collections and policies as JSON) and
`federation_replica_ciphers` (item views as JSON with a digest). It pulls from A:

- `POST /federation/v1/members/{userId}/organizations` lists the organisations (status and
  revision date). The body carries the user's current public key; see "Key changes".
- `POST .../organizations/{orgId}/index` returns the profile entry, collections, policies and,
  for every visible item, its id, revision date and a digest of its view (without the short-lived
  attachment links).
- `POST .../organizations/{orgId}/ciphers` returns full views for the ids whose digest changed.

The serving side only keeps organisations of invitations the user accepted from that peer (never
a local organisation id, never one another peer serves, never more than 50) and rebuilds every
record from an allowlist (`src/federation/sanitize.ts`): the profile entry gets the bound
organisation and user ids with SSO, Key Connector, account recovery, SCIM and Secrets Manager
flags forced off; policies are limited to the bound organisation and the client-side types
(master password, generator, personal ownership, Send, vault timeout, export); collections and
items are forced into the bound organisation, item ids must be ones it asked for and not already
held under another organisation, and sizes are capped. Change events only trigger sync pushes
(item, items, vault, organisation keys, organisations) with payloads rebuilt from validated ids.
Invitations always answer "pending" (no account discovery), at most 30 per peer per hour, with at
most 5 invitation emails per user per day. The scheduled resynchronisation gives each peer at most
20 seconds.

Organisations no longer listed are purged with their items and local folder links. A's links are
rewritten to B's own address: attachment downloads become
`/federation/attachments/{peerId}/{cipherId}/{attachmentId}` on B, which relays the file from A
as `application/octet-stream` with `Content-Disposition: attachment` and a `sandbox` CSP (never
the peer's own headers), rate limited per address.

`GET /api/sync` and the profile on B include the replica exactly like local organisations, with
the user's own folders from B (`federation_item_folders`). Suspended peers are left out.

### Change events

On A, `pushUserUpdate` checks whether the recipient is a stand-in account; if so the push becomes
a signed `POST /federation/v1/events` to its home instance with the same type and payload. B
refreshes the replica, then publishes the event to the user's devices through its notification hub
and the mobile push relay, excluding the device that made the change. A lost event is caught up by
the hourly scheduled resynchronisation on B.

### Writes

The user's clients send writes to B as usual. B forwards any request that touches a federated
organisation or one of its items (by id, by `organizationId` in the body or query, or the federated
part of a bulk request) to `.../members/{userId}/proxy/{path}` on A. A checks that the path is a
cipher, organisation or attachment download path, refuses features that are not federated, mints a
short-lived token for the stand-in account and runs the request through its normal routes, so
authorisation, revision checks (`lastKnownRevisionDate`) and events are exactly those of a local
member. B relays the response, applies the folder the user chose locally (folders never leave B),
refreshes the replica and returns.

- Bulk requests are split: federated ids go to their hosting instances, the rest is handled
  locally. Moving federated items between folders is purely local.
- Moving a personal item into a federated organisation creates it on A and removes the local copy.
  The item gets a new id. Items with attachments must be moved without attachments.
- Attachments upload through B to A (the upload is buffered to be signed, up to 25 MB) and download
  through B's relay.

### Revocation and key changes

- Removing the member on A (or withdrawing the invitation, or the user leaving) pushes an event;
  B's next pull no longer lists the organisation and purges the replica, then tells the devices
  to resync.
- Unpairing on either side purges replicas on the serving side and deletes stand-in accounts and
  their memberships on the hosting side.
- When the user's public key on B changes, the next pull carries the new key. A replaces it and
  moves the user's confirmed memberships back to accepted with no key, and an admin confirms again
  (with the new fingerprint phrase).
- Organisation key changes reach members through the normal confirm flow and the replicated
  profile entry.
- Deleting the account on the serving side removes its replica at once; the membership on the
  hosting side stays (shown with its home instance) until an admin removes it, and events for it
  are refused by the serving side.
- Deleting the organisation on the hosting side is picked up by the serving side's next pull (on
  any later event for the user, or the hourly resynchronisation).

## Not federated

These are refused with a clear message (400) for federated members:

- SSO, Require SSO, SCIM and organisation API keys.
- Account recovery (reset password enrolment and admin recovery).
- Emergency access across instances (emergency access only covers the grantor's own items).
- Secrets Manager.
- Organisation import and export, billing, licences and domain verification.
- Archiving federated items (archive state is per member on the hosting side).
- Organisations that require two-step login, use single sign-on (and with it trusted devices or
  Key Connector) or enable the Require SSO policy cannot invite or accept federated members.
- Stand-in accounts can never sign in: every grant of the token endpoint (password, refresh,
  SSO authorisation code, passkey, device approval, API key) refuses them, and their access
  tokens are only accepted when minted in-process for a verified peer request.
- Deleting the organisation from the serving side. Administer the organisation on its home
  instance; the Admin Console of a federated organisation on B is not supported.

Turning on single sign-on, Require SSO or required two-step login in an organisation that
already has federated members blocks them at once: the hosting side stops listing the
organisation to their home instances (which purge it) and refuses their forwarded requests. They
return if the setting is turned off again. Federated members cannot be owners.

The hosting organisation's client-side policies (master password requirements, password
generator, personal ownership, Send options, vault timeout, export) apply to federated members
through their clients exactly as for local members. Policies of the federated organisation are
synced to the clients (which enforce the client-side ones), but server-side policy checks on B (single organisation, personal ownership) do not see
federated organisations.

## Threat model

| Threat | Mitigation |
|---|---|
| A rogue server pretends to be a peer | Requests must be signed by a key pinned at pairing, after both admins compared fingerprints out of band; pairing binds the key to the domain through the https descriptor. |
| Replay or tampering of server-to-server calls | Signature covers method, full URL, body digest and the user and device headers; 300 second window; per-peer nonce store. |
| A peer acting for users it does not own | A only accepts a user id that is a stand-in account of the calling peer, and runs every request as that account through the normal authorisation. B only accepts events for its own users who hold something from the calling peer. |
| A peer reading organisation data | Same as a member's client: only EncStrings the member may see. Organisation keys are wrapped in the browser for the member's public key; neither server ever holds them. |
| The serving side is compromised | It can see the encrypted items the member can see and act as the member within the member's permissions, like a stolen session. Suspend or remove the peer on A to cut it off. |
| The hosting side is compromised | It controls the organisation, as for any member of a hosted organisation. It cannot reach the user's personal vault on B: the proxy path on B is never exposed, and A's events only trigger pulls and pushes. |
| SSRF through peer domains | Host names only, https on 443, DNS over HTTPS checks of every address, no redirects, timeouts and size caps. |
| Instance key theft from a database dump | The private key is encrypted under a key derived from a Worker secret. |
| Denial of service by a peer | Per-peer rate limit; outbound calls time out; admins can suspend instantly. |
| A user account takeover on A through the stand-in account | The stand-in account has no usable password, no API key and no passkeys. Tokens for it are only minted in-process for verified peer requests. Its address cannot also register on A. |

## Operator guide

1. Set `FEDERATION_ENABLED=true` (deploy variable). Optionally set `FEDERATION_KEY_SECRET` (32+
   characters) with `cf workers secrets`; otherwise `JWT_SECRET` protects the key. Changing that
   secret later makes the stored key unreadable: remove all peers first, clear
   `federation_identity`, and pair again.
2. Make sure `/.well-known/cloudwarden-federation` and `/federation/*` reach the Worker (they are in
   `runWorkerFirst` in `cloudflare.config.ts`).
3. Instance admin, Federation: add the peer's domain, compare fingerprints with the other admin,
   approve. Both sides must approve.
4. Organisation admins invite federated members from Admin Console, Federated members, and confirm
   them with the standard Confirm action once accepted.
5. Monitor peers on the same page (status, last seen, last error, health check) and the federation
   events list. Suspend a peer to cut it off at once; remove it to purge everything.

## Tests

`test/federation.test.ts` runs two instances in one workerd (separate D1 databases and domains,
connected by an in-process transport that also answers DNS over HTTPS) through pairing, invitation,
acceptance, confirmation, replica sync, forwarded writes and attachments, permission denial on the
hosting side, push propagation, key change, suspension, revocation and unpairing, plus signature,
replay and SSRF refusal. `test/federation-unit.test.ts` covers the signature format, address checks
and the encrypted identity.
