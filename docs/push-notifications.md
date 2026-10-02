# Mobile push notifications

Cloudwarden syncs live over its own WebSocket hub (SignalR) while an app is open. Phones close that
connection when the app is in the background. The official mobile apps are woken by Apple and Google
push services, and a self-hosted server cannot talk to those directly because the credentials belong to
the app publisher. Bitwarden runs a relay for this: your server registers each phone's push token with the
relay and asks it to deliver a small "something changed" message, and the app then syncs. TASKS #262.

Push is optional. Without credentials everything else works and mobile apps still sync when opened or on
their normal refresh.

## What you need (owner action)

1. Open the Bitwarden self-host registration page (bitwarden.com/host) and request an installation id and
   key with a contact email. Use the US or EU cloud region you will relay through. Keep the key secret.
2. Set the Worker secrets (never commit them):

   ```sh
   pnpm exec cf workers secrets update PUSH_INSTALLATION_ID
   pnpm exec cf workers secrets update PUSH_INSTALLATION_KEY
   # EU region only:
   pnpm exec cf workers secrets update PUSH_RELAY_URI       # https://push.bitwarden.eu
   pnpm exec cf workers secrets update PUSH_IDENTITY_URI    # https://identity.bitwarden.eu
   ```

   The defaults are `https://push.bitwarden.com` and `https://identity.bitwarden.com`.
3. In the mobile app, the server URL is your Cloudwarden address as usual. Log in; the app sends its push
   token to `PUT /api/devices/identifier/{id}/token` and the server registers it with the relay.

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

`GET /api/cloudwarden/admin/diagnostics` has a `push` object: `configured`, `state` (`configured`,
`not configured` or `incomplete` when only one of id and key is set), the relay and identity hosts, and the
outcome of the last relay call seen by that Worker instance (`lastResult`, best effort because Workers
instances are short lived). The key is never returned.

## Limits and honesty

The request shapes follow the relay behaviour described in public Bitwarden documentation and client code,
not a recorded session. They have not been exercised against the live relay because that needs real
installation credentials; tests use a stand-in relay. If the relay rejects a call, `push.register_rejected`
or `push.send_rejected` appears in the logs with the HTTP status, which is the first thing to check.
