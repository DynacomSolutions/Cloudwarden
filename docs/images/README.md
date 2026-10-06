# README image assets

- `hero.webp` is Cloudwarden-themed artwork generated for this README.
- `architecture.svg` is a repository-native diagram of the client, Worker, D1, R2 and NotificationHub roles. It describes encrypted vault fields and notification fan-out without making audit or security-guarantee claims.
- `vault-overview.png`, `vault-item.png` and `login.png` are real screenshots captured from the locally available web-vault build (`2026.9.1`, upstream `web-v2026.9.1`, source commit `bb2b70338a7467949c5cb818bff387c4eab9c1ab`). The vault overview and item screenshots are 1440 × 960; the sign-in screenshot is 1440 × 913. The client was served through an isolated TLS proxy and connected to a local Worker seeded with fictional `example.com` entries. The sign-in view uses a fictional `example.com` address, and passwords are masked in the item view.

The screenshot build is recorded for provenance and may differ from the web client currently tracked in this checkout.
