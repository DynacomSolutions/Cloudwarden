# Notice

This directory contains a modified copy of the Bitwarden client applications source code,
taken from https://github.com/bitwarden/clients at tag `web-v2026.9.1`. Only the web vault
(`apps/web`), the shared libraries it builds from (`libs/`) and the root build configuration are
included. The browser, desktop and CLI apps are not.

## Licence

The upstream code is Copyright Bitwarden Inc. and licensed under the GNU General Public License
v3.0 (`LICENSE_GPL.txt`, `LICENSE.txt`). Cloudwarden's modifications in this directory are
released under the same licence.

Only GPL-3.0 code is vendored. Nothing from the upstream `bitwarden_license/` directory (code
under the Bitwarden License v1.0) is included, the web vault is built with the open source
(`oss`) variant that does not import it, and `scripts/check-web-licence.mjs` fails CI if any such
path appears. Features that upstream ships only under the Bitwarden License, such as Secrets
Manager, the Provider Portal, SSO and SCIM administration and other enterprise features, are
therefore not part of this build. Cloudwarden's own single sign-on and claimed domain settings
(`apps/web/src/app/cloudwarden/sso/`) are written from scratch against Cloudwarden's API contract
(`docs/sso.md`); no code or structure was taken from Bitwarden's licensed SSO screens. The device approvals page is likewise Cloudwarden's own. Cloudwarden's own Secrets Manager pages
(`apps/web/src/app/cloudwarden/secrets-manager/`) are written from scratch against Cloudwarden's
API contract (`docs/secrets-manager.md`); no code, structure or assets were taken from
Bitwarden's Secrets Manager web app. Likewise the SCIM settings and event integrations pages
(`apps/web/src/app/cloudwarden/org-integrations/`) are Cloudwarden's own, written against
`docs/integrations.md` without reference to Bitwarden's licensed screens.

The proprietary commercial SDK (`@bitwarden/commercial-sdk-internal`, Bitwarden Software
Development Kit License Agreement) is not a dependency and is removed from `package.json`, the
lockfile and the Dockerfile; `scripts/check-web-licence.mjs` also rejects any dependency whose
lockfile licence is a Bitwarden licence. The open source `@bitwarden/sdk-internal` (GPL-3.0) is
used.

## Fonts

Two web fonts are bundled under the SIL Open Font License 1.1, each with its licence text beside
the font files:

- Montserrat (Copyright 2011 The Montserrat Project Authors):
  `libs/components/src/cloudwarden/fonts/` (`OFL.txt`).
- Inter (Copyright (c) 2016 The Inter Project Authors): `libs/components/src/webfonts/` (`OFL.txt`).

## Trademarks

Bitwarden is a trademark of Bitwarden Inc. Cloudwarden is an independent project and is not
affiliated with, endorsed by or sponsored by Bitwarden Inc. The user-visible product name, logos
and icons have been replaced with Cloudwarden's own, as the upstream licence grants no rights in
Bitwarden's marks. The register page marketing images (press and review logos), the Bitwarden
wordmark graphics, and the unused upstream marketing videos have been removed. A few Secrets
Manager landing images and the extension setup videos upstream ships are still referenced by
screens that exist in the build and are kept.

The name Cloudwarden is a deliberate, non-confusing name of its own. Wording in the README, this
notice and the application strings refers to Bitwarden only to name the protocol and clients
Cloudwarden is compatible with, in a statement that it is not affiliated.

## Modifications

Summary of changes made by Cloudwarden (see `git log -- web/` for the full history):

- Workspaces reduced to `apps/web` and `libs/**`; `package-lock.json` regenerated for that set.
  The development TLS key shipped upstream for the dev server is removed.
- Bitwarden License build targets removed from `angular.json`, `tsconfig*.json`,
  `apps/web/project.json`, `apps/web/package.json` and the Tailwind content paths.
- Rebranding: product name, page titles, logos, favicons, web manifest, welcome graphic and the
  shield glyph replaced (names of real Bitwarden products the user installs separately, such as
  the browser extension, apps and Authenticator, are kept; `web/scripts/rebrand-locales.py`);
  the upstream extension videos are not shown; the
  "More from Bitwarden" product switcher entries, premium upsell, Provider Portal entry points
  and marketing links are hidden; the Secrets Manager entry opens Cloudwarden's own pages. The footer reads "Cloudwarden, based on
  Bitwarden clients (GPL-3.0)".
- Theme: colours, typography and radii mapped onto the component library tokens
  (`libs/components/src/cloudwarden/theme.css`).
- Organisations: self-hosted instances show a simple create form (name, billing email, Free
  plan) instead of the licence upload.
- Create organisation: the server lets only instance owners and admins create organisations
  (`canCreateOrganizations` in `GET /api/cloudwarden/me`). The New organisation entries (org
  switcher, vault filter, Settings "Add plan", Secrets Manager landing pages) are hidden for
  everyone else, and the `create-organization` and `settings/add-plan` routes redirect to the vault
  (`cloudwarden/organizations/can-create-organizations.guard.ts`).
- Instance admin: an admin area (`apps/web/src/app/cloudwarden/`) that talks to Cloudwarden's
  admin API.
- Secrets Manager: projects, secrets, machine accounts, access tokens and access policies at
  `/sm/:organizationId` (`apps/web/src/app/cloudwarden/secrets-manager/`), shown in the product
  switcher for members with Secrets Manager access; the Secrets Manager logo is replaced with a
  Cloudwarden one.
- Organisation integrations: SCIM provisioning settings (`settings/scim`) and event integrations
  (`integrations`: signed webhooks, Splunk, Datadog, Microsoft Sentinel) routed to Cloudwarden's
  own pages (`apps/web/src/app/cloudwarden/org-integrations/`).
- Single sign-on: organisation settings for OpenID Connect and SAML 2.0, member decryption
  options (master password, trusted devices, Key Connector) with a configuration test, and
  claimed domains with DNS TXT verification (`apps/web/src/app/cloudwarden/sso/`), routed at
  `settings/sso` and `settings/domain-verification`.
- Federated organisations (`apps/web/src/app/cloudwarden/federation/`, docs/federation.md):
  Instance admin, Federation (peers, fingerprint approval, health, suspend, remove, events);
  Admin Console, Federated members (invite a user of a paired server, confirm with the standard
  fingerprint dialog, remove); and Federated organisations under Settings for the invited user.
  The user and organisation navigation entries appear only when the server has federation on.
  Pairing QR codes: a workspace QR panel and a Scan QR control (camera, image or pasted text; jsQR,
  Apache-2.0, added as a direct dependency of the web client; QR drawing reuses the bundled qrious).
- Device approvals: an Admin Console page at `settings/device-approvals`
  (`apps/web/src/app/cloudwarden/device-approvals/`), written from scratch against Cloudwarden's
  API contract (`docs/account-recovery.md`), shown to members who manage account recovery.

- Email-less installations (`apps/web/src/app/cloudwarden/emailless/`, docs/emailless.md): a
  setup and invite page at `/instance-setup` (the operator enters the setup secret, an invited
  person the code of an invite link, then the standard finish sign up page runs), an email state
  service that reads `/api/config`, invitation links to copy and an "Email: not configured" panel
  in Instance admin. Small marked edits hide email two-step login and skip the emailed code of the
  change email form when the server cannot send mail.

Files Cloudwarden adds live in directories named `cloudwarden/` where practical.
