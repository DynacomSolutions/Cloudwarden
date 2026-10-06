# Federated organisations and collection sharing

Cloudwarden extension (TASKS #300 to #309, #370 to #376), not part of the Bitwarden API. A user with an account
on one Cloudwarden instance can be a member of an organisation hosted on another instance and use
it from the official clients as if it were a local organisation: the items appear in the normal
sync, can be edited, shared into, deleted and restored, and changes arrive live.

Federation does not tie two organisations together. A pairing is only a signed trust channel
between two instances (a "trusted workspace"). What users do with it is share individual
collections with a specific person on the other workspace, from the collection's own Access
dialog (see "Sharing a collection"). Underneath, that person is a federated member of the hosting
organisation who holds only the collections shared with them.

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

Pairing is deliberate on the side that starts it. The side that receives it trusts the caller for
INCOMING traffic only, until its own admin approves it.

1. An instance admin on A opens Instance admin, Trusted workspaces (or adds the workspace from a
   collection's Access dialog, see "Sharing a collection"), and adds B's domain. A fetches B's
   descriptor and shows its fingerprint. The peer is `pending`.
2. A's admin compares the fingerprint with B's administrator out of band (by phone, or by scanning
   B's QR code, see "QR codes for pairing") and types, pastes or scans it to approve; a mismatch
   is refused, and the server re-checks it against the key it fetched. A then sends a signed
   `POST /federation/v1/pair` to B. B refuses a blocked domain, instance or fingerprint, fetches
   A's descriptor from the claimed domain over https to bind the key to the domain, verifies the
   signature, pins the key and records A (`incoming`).
3. Unless B's admin turned on "Require admin approval for incoming workspaces", and unless B's admin
   removed that domain before (see "Removal and blocks"), B marks A active at once
   (`acceptedAutomatically`, audit event `PeerAutoAccepted` 9121). That is **inbound only**:
   A's signed requests are accepted, so A's organisations can invite B's users (who must accept),
   but nothing is sent to A, and A is not a sharing target for anyone on B, until an instance
   admin on B approves A with the fingerprint (`approved_by` set). With the setting on, or after
   a removal, A is `pending` and B's admin approves as before.

What inbound-only trust gives A: nothing about B's users beyond what each user grants. A can send
invitations that a user must accept on B, and only after that, and after the hosting admin's
confirmation, does any data move. B relies on the https binding of A's domain (WebPKI and DNS)
instead of an out-of-band comparison; an attacker who controls a domain can therefore pair as that
domain, but can only send invitations, and cannot become a target: outbound sharing, invitations
from B's organisations and the list of workspaces offered to organisation admins
(`outboundOk`: active and, when trusted automatically, approved by an admin) all exclude it.
Collection managers on B see it as "Incoming only: approve to share with this workspace", and
what they share meanwhile is queued (see "Share first, ask after"). The Trusted workspaces page
shows "Incoming only" (or "Review" when approval is required) with an Approve button, or
"Approved by <admin>".

Invitations from a workspace nobody approved: the answer to the peer is the same and immediate
whether or not the address has an account (the lookup, inserts and mail run after the response);
no email is sent (the invitation appears in the app, labelled "from an unverified workspace");
the organisation name has control characters removed and is capped at 100 characters, the inviter
address must look like an address; at most 10 invitations may be pending per user and 200 per
peer (enforced inside the insert, so concurrent requests cannot overshoot); and such a peer cannot
claim an organisation id that another peer holds, while an approved peer's invitation replaces an
unanswered one from an unapproved peer.

Removal and blocks: removing a workspace remembers the domain, so its next incoming request waits
for an admin instead of being trusted automatically (approving it clears that). "Remove" can also
block, first and in one batch with the block event. Block rules (`POST .../admin/blocked`, listed
on the page) are a domain, a suffix pattern `*.example.com` (the name and everything under it;
there is no public suffix list, so name the registrable domain), `instance:<id>` or
`fp:<fingerprint>`. They are checked in `/federation/v1/pair`, on every signed route and when an
admin adds a peer; adding a rule removes the peers it matches.

Caps on the receiving side: pairing requests per address (10 a minute) and per instance (30 a
minute); at most 25 peers trusted automatically; at most 20 incoming requests waiting for an admin
(dropped after 7 days); peers an admin added are not counted in either. Both are enforced inside
the insert. Turning "Require admin approval for incoming workspaces" on lists the workspaces that
were trusted automatically as "Review": they stay incoming only (nothing changes for people who
already accepted) until an admin approves or removes them.

Admins can suspend a peer (effective immediately: requests in both directions are refused and
federated organisations disappear from users' vaults until it is resumed), run a health check
(signed ping) and remove it (unpair: both sides purge everything tied to the peer).

### QR codes for pairing

Typing a 64 digit fingerprint is the weak step of pairing, so every place that asks for a peer domain and fingerprint also takes a QR code. It is a convenience for the out-of-band comparison and nothing more.

**Format.** One line of text, versioned, short enough for a low-density code (about 100 characters, QR error correction level M):

```
cloudwarden-workspace:v1?domain=<host>&fp=<fingerprint>
```

- `domain`: the instance's host name in lower case, the same syntax the server accepts for a peer domain (dotted host name, no scheme, port, path or IP literal).
- `fp`: the SHA-256 fingerprint of the instance's public key as 64 hexadecimal digits without separators (the same value the Federation pages show grouped in fours).
- Exactly these two parameters, each once, and nothing else. Readers refuse any other scheme, any version other than `v1`, a malformed or unknown parameter, an invalid domain, or a fingerprint that is not exactly 64 hex digits. A new version means a new `vN` token, so old readers fail closed.

**Showing it.** Instance admin, Trusted workspaces, and the "Add a workspace" step of a collection's Access dialog have a "Show this workspace's QR" panel. It draws the code for this instance (from the public descriptor at `/.well-known/cloudwarden-federation`) with the domain and the grouped fingerprint beneath, so the other administrator can scan it or read it. The code is generated in the browser with the QR generator the web client already ships.

**Scanning.** Wherever a peer domain or fingerprint is entered (adding a workspace, approving one, and the dialog's add step) a "Scan QR" control reads the code from the camera (rear camera preferred, the native `BarcodeDetector` when the browser has one, otherwise the bundled jsQR decoder), from a picked or pasted image, or from pasted URI text for desktops without a camera. The camera needs `Permissions-Policy: camera=(self)`, which the web vault's static headers set; nothing else about the CSP changes (the camera stream is not a fetched resource and the decoder runs on the page's own script origin).

What a scan does:

1. The text is validated strictly as above; anything else is refused with a message.
2. When approving a known peer, the scanned domain must equal that peer's domain, otherwise the scan is refused and nothing is filled in.
3. The domain and fingerprint fields are filled. In the dialog the server lookup runs first and the fingerprint is only filled when the domain the server reached equals the scanned one.
4. Nothing is approved. The server still compares the fingerprint with the key it fetched itself from the peer's domain (mismatch is refused), and the user still presses Approve or Add.

### Sharing a collection

The web client's collection dialog (Access tab, edit mode) has an "External workspace" section
(`web/apps/web/src/app/cloudwarden/federation/collection-external-access.component.ts`). It is a
Cloudwarden addition; nothing of it comes from `bitwarden_license/`.

1. Open a shared collection, choose Access, and in "External workspace" pick the workspace: an
   already trusted one from the list, or "Add a workspace" with its URL.
2. For a new workspace, "Look up" asks this server to fetch the remote descriptor
   (`POST .../external-access/workspaces/lookup`). The fetched fingerprint is shown; the user types
   or pastes the fingerprint the other administrator gave them out of band, and it must match
   (checked in the browser and again on the server, as pairing does).
3. Who can make the workspace trusted:
   - An **instance admin** creates and approves the peer in one step. The signed pairing request goes
     to the remote instance, whose own administrator must still approve it on their Instance admin,
     Trusted workspaces list only when that instance requires approval of incoming workspaces
     (see "Pairing"); by default the other side trusts it at once.
   - **Anyone else** who manages the collection only creates a pending request
     (`federation_peers.requested_by`, no signed request is sent, nothing is trusted). Such
     requests have their own caps (5 open instance wide, 2 per user, not counted against the 20
     pending peers of admins and inbound pairing) and are dropped after 7 days. A non-admin sees
     only active workspaces and their own requests; any other known domain is reported only as
     "waiting for an instance administrator", with no state or fingerprint. The dialog
     says "waiting for your instance administrator". An instance admin approves it on Instance
     admin, Trusted workspaces (the list shows who asked), typing or scanning the fingerprint
     again. Trust is never activated by a non-admin, because a pairing lets another server act for
     its users inside this instance. Instance admins are told of a new request by an email (when
     mail is configured) and by a count next to Trusted workspaces in the Instance admin
     navigation (`pendingRequests` of `GET .../status`).
   - **Share first, ask after.** While the workspace awaits an instance admin the dialog still
     takes addresses and a permission. "Share" then queues them (`federation_queued_shares`,
     migration 0028) and sends nothing to the other instance. Queued people show in the Access list
     as "Waiting for admin approval"; any manager of the collection can change their permission or
     remove them (`PUT/DELETE .../external-access/queued/{id}`, the path must match the
     item's organisation and collection). The pairing request on Trusted workspaces lists what is
     queued behind it: organisation, number of collections, number of people and who asked. Caps:
     50 queued people per request and 20 per requester, and the usual per-user share limit.
     When the admin approves (and the other side is active, which is immediate unless it requires
     approval), every queued item is checked again as of that moment: the requester must still
     manage the collection and still be allowed to invite (manage users, or the organisation lets
     collection managers invite), and the organisation must still be able to serve federated
     members. Items that pass become ordinary invitations sent as the requester; items that no
     longer qualify are kept as "Not sent" with the reason and an audit event. A failure that may
     pass (the peer is unreachable, a rate limit) keeps the item as retry, tried again when an admin
     next opens Trusted workspaces, up to 5 times. The send runs after the response, and its audit
     events carry the requester but no client address. A queued item that a different manager
     edits becomes theirs (`requested_by`, audit event 9129): it is sent as them, after checking
     their right to invite. Queue caps are part of the insert. A workspace trusted for incoming
     traffic only (see "Pairing") queues exactly like one awaiting approval, and shares are sent
     once an admin approves it. Items older than 7 days expire whichever peer they wait behind. When the request is declined
     (removed) or expires after 7 days, the items are cancelled and shown as "Declined by your
     instance administrator" or "Expired"; finished entries are purged after 30 days or removed by a
     manager. The requester is told by mail (when configured) of approval or decline, and sees
     the status in the dialog. Audit events 9125 to 9128 (queued, sent, dropped, cancelled).
4. When the workspace is active, enter one or more email addresses of accounts on it and choose the
   permission (Can view, Can view except passwords, Can edit, Can edit except passwords, Can
   manage; the same mapping as local access). Creating NEW external invitations needs the manage
   users permission, unless an owner or admin turned on "Collection managers may invite external
   people" (default off; External people page, `GET/PUT .../organizations/{orgId}/settings`,
   `organizations.federation_managers_invite`). Granting, changing and removing access for people
   who already belong to the organisation through the workspace stays with collection managers.
   "Share" sends one federated invitation per new
   address, scoped to exactly this collection: role User, no groups, no access to all collections.
   An address that is already a federated member of the organisation through that workspace only
   gets this collection added or its permission changed; no second invitation or mail is sent. An
   address with an account on this instance, or a member through another workspace, is refused
   with a message for that address; the others are still processed.
5. The invited person sees the invitation on their own instance (Shared with you from other
   workspaces, and by mail), with an explanation of what accepting shares and, if their instance
   has not approved the workspace yet, what is missing. Accepting makes the grantee "Accepted,
   awaiting confirm" in the dialog.
6. An organisation admin (anyone with the manage users permission) confirms from the same list:
   "Confirm" opens the standard confirm dialog with the fingerprint phrase and wraps the
   organisation key in the browser, exactly as for a local member. Auto-confirm is not offered:
   the existing auto-confirm machinery is for local members who enrolled their own key, and
   confirming a stand-in account must stay a deliberate step with the phrase checked.
7. The list shows each external person with a workspace badge, the status (Invited, Accepted
   awaiting confirm, Active), the permission (editable) and Remove. Removing drops the grant on
   this collection. The federated membership is removed too (and the home instance purges its
   replica, the same mechanisms as removing a federated member) only when the sharing flow created
   it (`federation_members.created_via_share`), the person is still Invited or Accepted, and they
   hold nothing else (role User, no other collection, no group, no access to all); the check and the
   delete run in the same batch as the grant removal. Anyone already confirmed, or invited on the
   members page, keeps the membership and a manage users admin removes it from External people.
   Otherwise only the grant goes and their instance resyncs. Removing the workspace itself (unpairing) still purges both sides.

Auto-confirm (the automatic user confirmation policy) never applies to federated members: they are
filtered out of `pending-auto-confirm` and refused by `auto-confirm` and `bulk-auto-confirm`, so
their key is only ever wrapped after a person checked the fingerprint phrase. A federated member
holding only collection grants (role User, no access to all, no groups) gets only themselves from
`users/mini-details`, not the member directory.

Authorisation matches local access edits: the caller must be able to manage the collection
(Manage access to it, or the edit any collection permission). Creating a new invitation
needs the manage users permission unless the organisation setting above is on (the member only
gets keys when an admin confirms them either way). Rate limits: lookups 20 per minute, workspace
requests 5 per hour (30 for instance admins) and shares, changes and removals 60 per hour combined,
per user, on top of the existing per-peer limits
(30 invitations per peer per hour, 5 invitation emails per user per day).

API (`/api/cloudwarden/federation/organizations/{orgId}/collections/{id}/external-access`, see
`docs/api/openapi.yaml`): `GET` (workspaces and grantees), `POST` (share), `PUT /{memberId}`,
`DELETE /{memberId}`, `POST /workspaces/lookup`, `POST /workspaces`. `GET .../admin/peers` adds
`requestedByEmail` and `sharing` (per organisation: collections and people counts; collection
names are encrypted, so they are shown only in the organisation's own Admin Console).

Web pages: Instance admin, "Trusted workspaces" (the trust channels, with what is shared through
each); Admin Console, "External people" (overview with the collections each person holds, linking
to the vault); the invited person's "Shared with you from other workspaces".

What can be shared: Bitwarden personal vaults cannot be shared, only items in an organisation
collection. To share a personal item, use "Move to organisation" on the item and pick a
collection, then share that collection here. Cloudwarden does not add personal-item sharing.

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
| A rogue server pretends to be a peer | Requests must be signed by a key pinned at pairing. The side that starts pairing compares fingerprints out of band (typed or scanned); the receiving side relies on the https binding of the caller's domain (WebPKI and DNS) instead, unless its admin requires approval. Either way the key is bound to the domain through the https descriptor. |
| An attacker who controls a domain pairs with this instance | Possible by default (automatic incoming trust), and bounded: the peer is inbound only (never a sharing or invitation target until an admin approves it with the fingerprint) and can only send invitations that users must accept, in the app only, labelled unverified, with sanitised text, rate limited per peer and capped per user and peer; at most 25 automatic peers, 20 waiting requests, and per address and global pairing limits. Admins can suspend, remove, block by domain, suffix, instance or fingerprint, or require approval for incoming workspaces. |
| Replay or tampering of server-to-server calls | Signature covers method, full URL, body digest and the user and device headers; 300 second window; per-peer nonce store. |
| A peer acting for users it does not own | A only accepts a user id that is a stand-in account of the calling peer, and runs every request as that account through the normal authorisation. B only accepts events for its own users who hold something from the calling peer. |
| A peer reading organisation data | Same as a member's client: only EncStrings the member may see. Organisation keys are wrapped in the browser for the member's public key; neither server ever holds them. |
| The serving side is compromised | It can see the encrypted items the member can see and act as the member within the member's permissions, like a stolen session. Suspend or remove the peer on A to cut it off. |
| The hosting side is compromised | It controls the organisation, as for any member of a hosted organisation. It cannot reach the user's personal vault on B: the proxy path on B is never exposed, and A's events only trigger pulls and pushes. |
| SSRF through peer domains | Host names only, https on 443, DNS over HTTPS checks of every address, no redirects, timeouts and size caps. |
| Instance key theft from a database dump | The private key is encrypted under a key derived from a Worker secret. |
| Denial of service by a peer | Per-peer rate limit; outbound calls time out; admins can suspend instantly. |
| A non-admin activates trust through the Access dialog | Only `approvePeerLocally` activates trust and its callers check the instance admin role; the dialog's request path creates an inert pending row (`requested_by`) and sends nothing to the other instance. Fingerprint typed must equal the one the server fetched, and the key is re-checked at approval. Requests are rate limited and capped (20 pending peers) |
| A collection manager over-shares through the dialog | New invitations need manage users unless owners and admins opted in (default off). An invitation carries exactly one collection, role User, no groups and no access to all; it grants nothing until an admin confirms the member with the fingerprint phrase. Existing federated members only get this collection changed. Removal drops the grant, and the membership when nothing else is held |
| A user account takeover on A through the stand-in account | The stand-in account has no usable password, no API key and no passkeys. Tokens for it are only minted in-process for verified peer requests. Its address cannot also register on A. |

## Operator guide

1. Set `FEDERATION_ENABLED=true` (deploy variable). Optionally set `FEDERATION_KEY_SECRET` (32+
   characters) with `cf workers secrets`; otherwise `JWT_SECRET` protects the key. Changing that
   secret later makes the stored key unreadable: remove all peers first, clear
   `federation_identity`, and pair again.
2. Make sure `/.well-known/cloudwarden-federation` and `/federation/*` reach the Worker (they are in
   `runWorkerFirst` in `cloudflare.config.ts`).
3. Instance admin, Trusted workspaces: add the peer's domain, compare fingerprints with the other admin,
   approve. Both sides must approve.
4. Organisation users who manage a collection share it from its Access dialog, and organisation
   admins confirm accepted people there or on Admin Console, External people (which can still
   invite people without a collection).
5. Monitor peers on the same page (status, last seen, last error, health check) and the federation
   events list. Suspend a peer to cut it off at once; remove it to purge everything.

## Tests

`test/federation.test.ts` runs two instances in one workerd (separate D1 databases and domains,
connected by an in-process transport that also answers DNS over HTTPS) through pairing, invitation,
acceptance, confirmation, replica sync, forwarded writes and attachments, permission denial on the
hosting side, push propagation, key change, suspension, revocation and unpairing, plus signature,
replay and SSRF refusal. `test/federation-unit.test.ts` covers the signature format, address checks
and the encrypted identity.
