# Account emails

All mail goes through `src/email` (TASKS #141): the Cloudflare Email Service `EMAIL` binding and
`MAIL_FROM`. Without a transport nothing is sent and each feature that needs mail answers clearly or
skips quietly, as noted below. Notices are best effort and never fail the request. Templates are in
`src/email/templates.ts`; mail bodies are never logged. TASKS #260 and #261.

| Email | Trigger | Without mail |
|---|---|---|
| Password hint | `POST /api/accounts/password-hint` | 400 "cannot send email". With mail the answer is the same for every address and the hint (or a "no hint set" note) is mailed after the response, so there is no enumeration |
| Verify email | `POST /api/accounts/verify-email` (signed link, 5 days), `POST /api/accounts/verify-email-token` | 400 |
| Verification code | `POST /api/accounts/request-otp`, `verify-otp` | 400 |
| New device code | Password login from an unknown device when the account has `verifyDevices` on (default), mail works, the account has other devices and no two-step login. The token endpoint answers 400 "new device verification required"; the client sends `newDeviceOtp` | Login proceeds without a code |
| New device notice | Login from an unknown device, not the first, not after a code | none |
| Two-step login changed | Enabling or disabling authenticator, email or security key | none |
| Recovery code used | `two-factor/recover` and the recovery code login | none |
| Email change | Code to the new address (existing); after the change both addresses are told | none |
| Welcome | After registration | none |
| Delete by email | `POST /api/accounts/delete-recover`, `delete-recover-token` | 400 |
| Emergency access | Invite and request (existing); accepted, confirmed, approved, rejected, and approval by elapsed wait time (hourly sweep, `src/emergency-sweep.ts`) | none |
| Organisation | Invite (existing); accepted (to owners and admins), confirmed (to the member) | none |

`POST /api/accounts/verify-devices` turns new device verification on or off and needs the master password
or an emailed code. One time codes (`src/auth/otp.ts`) are six digits, stored hashed with their purpose,
valid for 10 minutes, five wrong guesses burn them, and a match is consumed atomically. The setting and
code columns come from migration `0011`.
