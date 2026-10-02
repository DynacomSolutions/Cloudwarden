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
therefore not part of this build. Cloudwarden's own Secrets Manager pages
(`apps/web/src/app/cloudwarden/secrets-manager/`) are written from scratch against Cloudwarden's
API contract (`docs/secrets-manager.md`); no code, structure or assets were taken from
Bitwarden's Secrets Manager web app. Likewise the SCIM settings and event integrations pages
(`apps/web/src/app/cloudwarden/org-integrations/`) are Cloudwarden's own, written against
`docs/integrations.md` without reference to Bitwarden's licensed screens.

## Trademarks

Bitwarden is a trademark of Bitwarden Inc. Cloudwarden is an independent project and is not
affiliated with, endorsed by or sponsored by Bitwarden Inc. The user-visible product name, logos
and icons have been replaced with Cloudwarden's own, as the upstream licence grants no rights in
Bitwarden's marks.

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
- Instance admin: an admin area (`apps/web/src/app/cloudwarden/`) that talks to Cloudwarden's
  admin API.
- Secrets Manager: projects, secrets, machine accounts, access tokens and access policies at
  `/sm/:organizationId` (`apps/web/src/app/cloudwarden/secrets-manager/`), shown in the product
  switcher for members with Secrets Manager access; the Secrets Manager logo is replaced with a
  Cloudwarden one.
- Organisation integrations: SCIM provisioning settings (`settings/scim`) and event integrations
  (`integrations`: signed webhooks, Splunk, Datadog, Microsoft Sentinel) routed to Cloudwarden's
  own pages (`apps/web/src/app/cloudwarden/org-integrations/`).

Files Cloudwarden adds live in directories named `cloudwarden/` where practical.
