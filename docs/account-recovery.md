# Account recovery and device approvals

TASKS #240 (account recovery, also called admin password reset) and #241 (device approvals, admin
approval auth requests). Built from the wire contract of the GPL-3.0 web client
(`web/`, tag `web-v2026.9.1`) and `docs/api/openapi.yaml`; no server code from elsewhere.

## Keys

Every organisation has an RSA key pair. The public key is stored in clear; the private key is
stored encrypted with the organisation symmetric key, which only confirmed members hold (wrapped
with their own public key). The server never sees a plain key.

| Value | Who makes it | Encrypted with | Stored in |
|---|---|---|---|
| `resetPasswordKey` | the member's client, at enrolment | organisation public key | `users_organizations.reset_password_key` |
| organisation private key | the owner's client, at creation | organisation symmetric key | `organizations.private_key` |
| device approval key | the approving admin's client | requesting device public key | `auth_requests.key` |

`GET /api/organizations/{id}/keys` returns the public key to any person with a pending, accepted
or confirmed membership (an invitee needs it to auto-enrol while joining), and the encrypted
private key only to confirmed members. Revoked members and strangers get 404.

## Policy

Policy type 8 (`ResetPassword`) turns the feature on for an organisation. Its data carries
`autoEnrollEnabled`:

- off: members enrol themselves from the vault (organisation options, "Enrol in account
  recovery"), which needs the master password;
- on: the client enrols while accepting the invitation (`resetPasswordKey` in the accept body,
  which is then required) and members cannot withdraw.

Disabling the policy stops all recovery and approval actions; enrolments are kept so turning it
back on restores them. `useResetPassword` is always true in organisation and profile responses.

## Enrolment

`PUT /api/organizations/{orgId}/users/{userId}/reset-password-enrollment` with
`{ resetPasswordKey, masterPasswordHash }`. `userId` is the caller's own user id (not the
membership id): nobody changes another person's enrolment. Enrolling needs an enabled policy,
organisation keys and the master password (accounts without one, created by SSO with trusted
devices, are enrolled by their client after login). An empty or null key withdraws, unless
auto-enrolment is on. Events 1506 and 1507.

## Recovery by an administrator

The caller needs the `manageResetPassword` permission (owners and admins always have it) and must
outrank the target: owners recover anyone, admins anyone except owners, custom members only users
and managers. Nobody recovers their own account through the organisation. The target must be
enrolled and accepted, confirmed or revoked.

1. `GET /api/organizations/{orgId}/users/{id}/reset-password-details` (or the bulk
   `POST .../users/account-recovery-details` with `{ ids }`, which drops members the caller may
   not recover) returns the KDF settings, salt, `resetPasswordKey` and the encrypted organisation
   private key.
2. The admin's client decrypts the private key with the organisation key, decrypts the user key,
   and derives new credentials for the new master password.
3. `PUT /api/organizations/{orgId}/users/{id}/recover-account` with
   `{ resetMasterPassword, resetTwoFactor, authenticationData, unlockData }` (the legacy
   `PUT .../reset-password` with `{ newMasterPasswordHash, key }` is also served). The salt in
   the nested data must be the member's email.

The server then, in one batch: replaces the password hash and the wrapped user key, clears the
password hint, sets `force_password_reset`, deletes two-step providers when asked, rotates the
security stamp (every session of the member ends, and a LogOut push is sent), records event 1508
and or 1519, and emails the member.

## Forced password change

While `force_password_reset` is set the token response carries `ForcePasswordReset: true` and the
profile `forcePasswordReset: true`. The official clients then require a new master password and
call `PUT /api/accounts/update-temp-password` with `{ authenticationData, unlockData,
masterPasswordHint }` (or the flat `{ newMasterPasswordHash, key, masterPasswordHint }`). It is
refused when no reset is pending. It clears the flag, rotates the stamp and records event 1008.
A normal password change also clears the flag.

## Key rotation

Recovery keys wrap the user key, so a rotation must re-wrap them.
`POST /api/accounts/key-management/rotate-user-account-keys` must carry
`accountUnlockData.organizationAccountRecoveryUnlockData` with exactly one entry per enrolled
organisation, or it is refused. The legacy `POST /api/accounts/key` carries no recovery data, so
it withdraws every enrolment instead of leaving a key that would unlock the old user key (an
admin reset with it would lock the member out).

## Device approvals (admin approval auth requests)

Auth request types: 0 authenticate and unlock, 1 unlock (both answered by the user's own devices,
15 minutes) and 2 admin approval (answered by an organisation, seven days).

Requesting (generic, for any client that holds an access token but not the user key, such as a
device signed in with SSO under trusted device encryption):

- `POST /api/auth-requests/admin-request`, authenticated, body as for other auth requests with
  `type: 2` and the caller's own email. Needs at least one accepted or confirmed membership,
  enrolled in account recovery, in an organisation with the policy enabled; otherwise 400. One
  request is created; every such organisation can answer it. Event 1010 per organisation and an
  email to every member who may approve.
- The anonymous `POST /api/auth-requests` refuses type 2.
- The device polls `GET /api/auth-requests/{id}` (authenticated, own requests only) and hears
  `AuthRequestResponse` (type 16) on its user hub. The answer carries `key`, the user key
  encrypted to the request's public key.
- Type 2 requests are never listed in `/api/auth-requests/pending`, cannot be answered with
  `PUT /api/auth-requests/{id}` and can never be redeemed at the token endpoint.

Answering (same authorisation as recovery: `manageResetPassword`, enabled policy, a target the
caller outranks, never the caller's own request):

- `GET /api/organizations/{orgId}/auth-requests`: pending, unexpired requests of enrolled active
  members, without keys, with `organizationUserId` so the client can fetch recovery details.
- `POST /api/organizations/{orgId}/auth-requests/{requestId}` with
  `{ requestApproved, encryptedUserKey }`.
- `POST /api/organizations/{orgId}/auth-requests/deny` with `{ ids }`.
- `POST /api/organizations/{orgId}/auth-requests` with `[{ id, approved, encryptedUserKey }]`;
  returns a per-id error list.

Events 1513 (approved) and 1514 (denied). Answers are single use: a second answer gets 404.

The Admin Console page (Settings, Device approvals) is Cloudwarden's own
(`web/apps/web/src/app/cloudwarden/device-approvals/`), because the upstream page is not open
source. It is shown to everyone who manages account recovery, not only to organisations using SSO
with trusted devices. Approving shows the request's fingerprint phrase (compare it with the one on
the requesting device), then rewraps the key in the browser.

## Notes for SSO and trusted device encryption

The admin approval contract above does not depend on SSO. The SSO workstream only needs to:

- issue access tokens to devices without the user key and set the organisation's member
  decryption type, so the official clients offer "Request admin approval";
- look up `GET /api/organizations/{identifier}/auto-enroll-status` by SSO identifier as well
  (it currently takes the organisation id);
- leave `users.password_hash` empty for accounts without a master password, which makes
  enrolment skip the password check (`hasMasterPassword` in `src/orgs/recovery.ts`).
