# Mobile push notifications

Cloudwarden syncs live over its own WebSocket hub (SignalR) while an app is open. Phones close that
connection when the app is in the background. The official mobile apps are woken by Apple and Google
push services, and a self-hosted server cannot talk to those directly because the credentials belong to
the app publisher. Bitwarden runs a relay for this: your server registers each phone's push token with the
relay and asks it to deliver a small "something changed" message, and the app then syncs. TASKS #262.

Push is optional. Without credentials everything else works and mobile apps still sync when opened or on
their normal refresh.

## What you need (owner action)

1. Open the Bitwarden self-host registration page (https://bitwarden.com/host) and request an installation
   id and key with a contact email. Use the US or EU cloud region you will relay through. Keep the key
   secret.
2. Sign in to the web vault as an instance admin and open Instance admin > Mobile push. Enter the
   installation ID and key, choose the region (US, EU or custom) and Save. Use Test connection to check
   the credentials against the relay. Nothing needs redeploying.
3. In the mobile app, the server URL is your Cloudwarden address as usual. Log in; the app sends its push
   token to `PUT /api/devices/identifier/{id}/token` and the server registers it with the relay. When you
   save new credentials the server registers existing phones again in the background.

### Settings API

`GET`, `PUT` and `DELETE /api/cloudwarden/admin/push-settings` and `POST .../push-settings/test` (admin
only; the test is limited to 5 per minute per admin and returns only `ok` or an error class:
`not_configured`, `rejected`, `unreachable`, `bad_response`). The installation key is write only: it is
sealed at rest with the same key as other server-held secrets (`DATA_ENCRYPTION_KEY`, falling back to a key
derived from `JWT_SECRET`, see `docs/integrations.md`) and responses carry only `keySet` (and `keyUnreadable` when a stored key can no
longer be opened, for example after the encryption key changed, in which case it must be entered again).
Leave the key blank on save to keep the stored one, except when the region or addresses change: the key
must then be entered again so a stored key is never sent to a new destination. Saves are limited to 5 per
minute per admin. Region `us` uses `push.bitwarden.com` and
`identity.bitwarden.com`, `eu` uses `push.bitwarden.eu` and `identity.bitwarden.eu`, and `custom` takes two
public https URLs on the default port, with no trailing dot and not under `.local`, `.internal`,
`.localhost`, `.lan` or `.home.arpa`. Relay calls never follow redirects (a 3xx counts as a failure) and
the connection test times out after 5 seconds. Names that resolve to private addresses are not blocked by
the application: Workers outbound requests cannot reach private networks, which is the mitigation against
DNS rebinding. Saves, removals and tests are recorded as admin events (9009 to 9011).

### Optional: Worker secrets (override)

Operators who prefer configuration as code can set Worker secrets instead. When both
`PUSH_INSTALLATION_ID` and `PUSH_INSTALLATION_KEY` are set they take precedence over the settings page,
which then shows a notice and its values are ignored.

```sh
pnpm exec cf workers secrets update PUSH_INSTALLATION_ID
pnpm exec cf workers secrets update PUSH_INSTALLATION_KEY
# EU region only:
pnpm exec cf workers secrets update PUSH_RELAY_URI       # https://push.bitwarden.eu
pnpm exec cf workers secrets update PUSH_IDENTITY_URI    # https://identity.bitwarden.eu
```

The defaults are `https://push.bitwarden.com` and `https://identity.bitwarden.com`. Settings changes are
cached for up to ten seconds per Worker instance, so another instance may use the old values for that long.
Re-registration after a change pages through all mobile devices, runs one pass at a time and handles up to
800 devices per run (a paid plan subrequest budget); beyond that `push.reregister_truncated` is logged and
the remaining phones register again the next time the app sends its token.

## How it works

- `src/notifications/relay.ts` gets a relay access token from the identity address with the
  `client_credentials` grant (`client_id=installation.<id>`, `scope=api.push`) and caches it until shortly
  before it expires, renewing once on a 401.
- Device registration: `POST {relay}/push/register` with the device id, push token, user id, device type,
  device identifier, confirmed organisation ids and installation id. Android, iOS and Android (Amazon)
  devices register; clearing the token or removing the device calls `DELETE {relay}/push/{deviceId}`.
  Organisation membership changes re-register the user's mobile devices so organisation ids stay current.
- Delivery: every event that reaches the hub also goes to `POST {relay}/push/send` with the same type and
  payload, targeted by user id or, for `pushOrgUpdate`, by organisation id. The device that made the change
  is passed as the identifier to skip. All `PushType` values go through the same functions
  (`pushUserUpdate`, `pushLogOut`, `pushOrgUpdate`), so nothing is sent to sockets without also being offered
  to the relay.
- Failures are logged by event name and error class only and never fail the request that caused the push.
  With the credentials missing every relay call returns at once.

## Diagnostics

`GET /api/cloudwarden/admin/diagnostics` has a `push` object: `configured`, `source` (`env` or `settings`), `envOverride`, `state` (`configured`,
`not configured` or `incomplete` when only one of id and key is set), the relay and identity hosts, and the
outcome of the last relay call seen by that Worker instance (`lastResult`, best effort because Workers
instances are short lived). The key is never returned.

## Limits and honesty

The request shapes follow the relay behaviour described in public Bitwarden documentation and client code,
not a recorded session. They have not been exercised against the live relay because that needs real
installation credentials; tests use a stand-in relay. If the relay rejects a call, `push.register_rejected`
or `push.send_rejected` appears in the logs with the HTTP status, which is the first thing to check.

## Browser web push

Browsers get live sync without the notification hub through Web Push (TASKS #342). It needs no
credentials from Bitwarden and no setup: it is on by default.

- The VAPID key pair (P-256) is generated on the first `GET /api/config` and kept in instance settings;
  the private key is sealed under `DATA_ENCRYPTION_KEY` (or the `JWT_SECRET` derived key) and never
  returned. `/api/config` then reports `push: { pushTechnology: 1, vapidPublicKey }`, which the web vault
  uses to subscribe through its service worker.
- The vault stores the subscription with `POST` (or `PUT`) `/api/devices/identifier/{id}/web-push-auth`
  (`endpoint`, `p256dh`, `auth`) on its own device row. Only https endpoints of known push services are
  accepted: Firebase Cloud Messaging, Mozilla autopush, Apple web push and Windows WNS, with no custom
  port or credentials. The key sizes are checked (65 byte uncompressed P-256 key, 16 byte secret).
- Delivery happens where `pushUserUpdate` fans out (and for `pushLogOut`), in parallel with sockets and
  the mobile relay. The message is one `aes128gcm` record (RFC 8291) with a VAPID JWT (RFC 8292, ES256,
  12 hour expiry), sent with `redirect: manual`. The endpoint is checked against the allow-list again on
  every send. A 404 or 410 from the push service removes the subscription; other errors are logged by
  status only. The device that made the change is skipped.
- Instance admins can turn it off: `GET` and `PUT /api/cloudwarden/admin/web-push` (`{ enabled }`). Off
  removes the key from `/api/config` (clients fall back to the hub) and stops delivery, keeping the key
  and subscriptions for later. The Angular settings page has no switch yet.
- `PUT devices/identifier/{id}/clear-token` clears the mobile push token (and the relay registration).
