# Running without email

A Cloudwarden server that cannot send mail is fully usable and secure. This is the normal setup on the
Cloudflare Workers Free plan, which has no Email Sending, and it works the same on any account that has
not onboarded a sending domain (TASKS #350 to #354). Mail counts as off when the `EMAIL` binding or
`MAIL_FROM` is missing; `GET /api/config` then reports `cloudwarden.email.configured: false` and the
Instance admin overview shows "Email: not configured" with the affected features.

The rule behind every choice: missing mail may remove a feature or replace the proof with a stronger one.
It never lets someone claim an admin account or another person's account. See `docs/threat-model.md`
(Email-less installations).

Nothing in the email-less paths adds CPU work beyond a few SHA-256 digests and D1 queries; password
hashing is untouched.

## Deploying without mail

1. Deploy with `MAIL_DISABLED=true` in the environment (repository variable for the workflow, or in your
   shell for a manual deploy). This leaves the `EMAIL` binding out of the Worker, so no Email Sending
   entitlement is needed. Without it the binding is declared, and an account that lacks Email Sending can refuse the deploy.
2. Set the usual secrets (`docs/deploy.md`) plus the one time setup secret:

   ```sh
   openssl rand -base64 48        # at least 32 characters, and it must be random
   pnpm exec cf workers secrets update ADMIN_SETUP_TOKEN
   pnpm exec cf workers secrets update ADMIN_EMAILS     # the address that will be admin
   ```

   `ADMIN_SETUP_TOKEN` must be random: a guessable phrase of 32 characters is still guessable. Generate it
   with the command above and do not choose it yourself. Values with fewer than 16 distinct characters are
   refused.

   Also set the variable `ADMIN_ENABLED=true` to use the Instance admin pages.

## Creating the first admin

1. Open `https://<your domain>/#/instance-setup` (the registration page also names it in its refusal).
2. Enter the admin address from `ADMIN_EMAILS` and the setup secret. The server checks it in constant time,
   limits attempts (5 per address per 10 minutes, plus the per-client limiter), and answers every failure the
   same way.
3. The standard "set a master password" page follows. Creating the account spends the secret in the same
   database batch (`admin_setup_uses`, keyed by the secret's SHA-256).

The secret works once. It is refused after any `ADMIN_EMAILS` account exists, after it was used (even if that
account is later deleted), and whenever mail is configured. To bootstrap again after deleting the admin, set a
new `ADMIN_SETUP_TOKEN`. Once the admin exists, delete the secret:
`pnpm exec cf workers secrets delete ADMIN_SETUP_TOKEN`. An admin address cannot register through any other
route, with or without open signups, when mail is off.

## Adding other users

* Instance admins: Instance admin, Invitations. Entering an address creates the invitation and shows a link
  with a one-time code (valid 7 days, only its hash is stored). Copy it and hand it over. "New link" issues a
  fresh code and retires the old one. The invited person opens the link (`/#/instance-setup`), which prefills
  address and code, then sets a master password. The invitation is consumed by the registration.
* An invited address cannot register through the ordinary page without the code, unless open signups
  (`SIGNUPS_ALLOWED=true`) or the domain whitelist already admit that address: then anyone can register it, as
  a mail-off server cannot tell who owns an address.
* Open signups (`SIGNUPS_ALLOWED=true`) work as before. The domain whitelist (`SIGNUPS_DOMAINS_WHITELIST`)
  governs public sign-up only and works as before, but cannot prove address ownership on a mail-off server:
  use invite links instead.
* Organisation invite links admit their own allowed domains to register, with or without mail and whatever
  `SIGNUPS_ALLOWED` or the whitelist say. Nobody has to add a domain to `SIGNUPS_DOMAINS_WHITELIST` for a link
  to work. The link admits only its own organisation's domains, but the token it yields creates a full instance account and
  does not force joining the organisation. On a mail-off server the token dies with the link (a refreshed or
  deleted link refuses the registration), and an address with a pending instance invitation still needs its
  invite code.
* Risk, as it stands: any user can create an organisation and publish a link for any domains, and on a
  mail-off server anyone holding that link can register any address in those domains, unproven. No setting
  restricts who may create organisations or links yet.
* Organisation admins: use the organisation invite link (Members, Invite link), which already shows a link to
  copy. Inviting a member by email is refused with that pointer.
* A mail-off server cannot prove address ownership anywhere. Domain-restricted organisation invite links and
  federated invitations (bound to an address) therefore only match the address a person typed, not one they
  proved. Do not rely on them to keep out someone who knows or guesses the address. An email change without
  mail stores the new address as unverified (it never reaches the Instance admin check), and an address with a
  pending instance invitation cannot be changed to.
* Accounts count as email verified while mail is off (the profile and the access token say so, and joining an
  organisation by invite link does not ask for it). The Instance admin check still needs a verified address and
  never infers it.

## Every place that sends mail

| Feature | With mail | Without mail |
|---|---|---|
| First admin registration | Emailed registration link proves the address | `ADMIN_SETUP_TOKEN` at `/#/instance-setup`, single use, refused once an admin exists |
| Instance invitation | Emailed link | Link with a one-time code shown in Instance admin to copy |
| Registration of an invited address | Emailed link | Needs the invite code |
| Organisation member invitation (and resend) | Emailed link | 400 "cannot send email", use the organisation invite link. SCIM, directory sync and the public API still store the member but cannot deliver a link |
| Organisation invite link | Works | Works, nothing is mailed |
| Emergency access invitation (and resend) | Emailed link | 400 "cannot send email" |
| Emergency access notices (accepted, requested, approved, rejected) | Mailed | Skipped. The state is visible in the vault and pushed live |
| New device verification code | Required for password logins from an unknown device | Skipped. Nothing can deliver it. Turn on a second factor |
| New device notice, welcome, security notices | Mailed | Skipped |
| Magic link login | There is none in the API contract | Not offered. `cloudwarden.email.features` lists it as refused |
| Email two-step login | Offered | Cannot be turned on (400). Hidden in the web client; at login it is not offered next to other providers, and when it is the only provider the error says to use the recovery code |
| Email protected Send | Code mailed to the recipient | Creating one is refused (400); an existing one answers 400 when a code is requested |
| Organisation deletion by email | Emailed link after the master password | 400. Owners delete with the master password and the typed name; instance admins can delete from Instance admin |
| Account deletion by email | Emailed link | 400. Deleting needs the master password |
| Password hint by email | Mailed | 400 "cannot send email" |
| Verify email, verification codes | Mailed | 400. Not needed: accounts count as verified |
| Email address change | Code to the new address, plus master password | Master password to ask and again to confirm, no code. Refused for an `ADMIN_EMAILS` address |
| Federated invitation notice | Mailed | Skipped; the invitation shows under Federated organisations |
| Account recovery and device approval notices | Mailed | Skipped |
| Secrets Manager access request | Mailed to admins | 400 |

`GET /api/config` returns `cloudwarden.email = { configured, features: [{ id, label, state }] }` with state
`available`, `link`, `refused`, `skipped` or `manual`. The web client reads it to hide email two-step login and to
skip the emailed code of the change email form. The Instance admin overview shows the same list.

## What you give up

* No password hint or delete by email: a user who forgot the master password can only use a two-step
  recovery code, an emergency contact, or ask an admin to remove the account.
* New device verification adds no protection. Encourage two-step login (authenticator, security key).
* Notices never arrive. Emergency access requests are visible only when the grantor looks.
* Org admins cannot invite one address into an organisation. They use the organisation invite link with the
  member's domain allowed.

Turning mail on later needs only the `EMAIL` binding and `MAIL_FROM` (remove `MAIL_DISABLED`). Pending
invite codes stop being needed and the setup secret is ignored.
