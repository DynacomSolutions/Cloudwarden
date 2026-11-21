# Event log

Cloudwarden writes an event for each security-relevant action. Admin Console, `GET /api/events`,
`GET /api/organizations/{orgId}/events` and `GET /public/events` read the same `events` table.
The event type codes are the integer codes of the Public API `EventType` enumeration.

## How events are recorded

- A server-side event is written in the same D1 batch as the change it records. If the change
  fails, no event exists.
- Each event keeps the acting user (`actingUserId`), the affected rows (`organizationUserId`,
  `cipherId`, `collectionId`, `groupId`, `policyId`, `secretId`, `projectId`, `sendId`), the
  `deviceType` from the `Device-Type` header (or the sign-in form) and the client address.
- `systemUser` names an actor that is not a member: 1 SCIM, 3 Public API.
- **Account events** (codes 1000 to 1099) and **Send events** (2500 to 2511) get one row for the
  account and one more row for each organisation of which the user is a confirmed member. The
  organisation row has `organizationId` and `organizationUserId`, so administrators see the
  activity of members. The account feed (`GET /api/events`) lists the account row only.
- **Client events** are reported by the official clients through `POST /events/collect`. The
  server accepts only the codes that clients raise, and only for items the caller can read or
  organisations the caller belongs to. Account-level codes (1007, 2400 to 2402) need neither.

## Codes recorded by the server

| Codes | Event | Raised by |
|---|---|---|
| 1000 | Logged in | Password, passkey, SSO code and personal API key sign-in. Not a token refresh. |
| 1001 | Changed password | `POST /api/accounts/password` |
| 1002 | Updated two-step login | A provider is turned on or its settings change (also a security key added or removed) |
| 1003 | Disabled two-step login | A provider is turned off |
| 1004 | Recovered two-step login | Recovery code spent, on `two-factor/recover` or at sign-in |
| 1005 | Failed sign-in | Wrong master password for an existing account |
| 1006 | Failed two-step sign-in | Wrong code, or wrong recovery code, at sign-in |
| 1008 | Updated temporary password | `PUT /api/accounts/update-temp-password` |
| 1009, 1010 | Key Connector migration, device approval request | SSO and device approval routes |
| 1011 | TDE offboarding password set | `PUT /api/accounts/update-tde-offboarding-password` |
| 1100 to 1106, 1115, 1116 | Item created, updated, deleted, shared, collections changed, trashed, restored | Organisation item routes |
| 1103, 1104 | Attachment added, removed | Attachment routes, organisation items only |
| 1300 to 1302, 1400 to 1402 | Collection and group changes | Collection and group routes |
| 1500 to 1514, 1519 | Member invited, confirmed, updated, removed and so on | Member, account recovery and device approval routes |
| 1515 | Member account deleted | Delete of a claimed account |
| 1516 | Member left | `POST /api/organizations/{id}/leave` |
| 1517 | Member confirmed automatically | Automatic user confirmation routes |
| 1518 | Member revoked themselves | `PUT /api/organizations/{id}/users/revoke-self` |
| 1520 | Revoked, two-step login not met | Turning on the two-step login policy, one event per revoked member |
| 1524, 1526 | Joined through an invite link, confirmed through it | Invite link accept and confirm routes |
| 1600 | Organisation updated | Organisation settings |
| 1601 | Vault purged | `POST /api/ciphers/purge?organizationId=` |
| 1603 | Vault accessed | An administrator opens the whole vault (`ciphers/organization-details`) |
| 1604 to 1607 | SSO and Key Connector turned on or off | SSO settings |
| 1609 to 1617 | Collection management | One summary event (1609) and one event per setting that changed |
| 1620, 1621 | Automatic confirmation turned on or off | The `AutomaticUserConfirmation` policy |
| 1624 to 1626, 1628 to 1630 | Invite link created, domains edited, deleted, refreshed, self-confirmation on or off | Invite link routes |
| 1700 | Policy updated | Policy routes and the Public API |
| 2000 to 2003 | Domain added, removed, verified, not verified | Claimed domain routes |
| 2100 to 2105, 2200 to 2203, 2300 to 2305 | Secrets Manager | Secrets Manager routes. Reads (2100, 2200) are recorded for machine accounts only. |
| 2500 to 2511 | Send created, edited, deleted, accessed | Send routes. Created events name the protection (none, email, password). A recipient opening a Send has no acting user. |
| 9001 and above | Cloudwarden audit codes | Admin and federation routes |

## Codes recorded from clients

`POST /events/collect` stores 1007 (vault exported), 1107 to 1114 and 1117 to 1132 (item viewed,
copied, autofilled and field visibility toggled), 1522 (notification banner), 1602 (organisation
vault exported), 1627 (invite link copied) and 2400 to 2402 (phishing blocker). Any other code
sent by a client is dropped.

## Codes Cloudwarden never records

| Codes | Event | Reason |
|---|---|---|
| 1509 | Reset SSO link | An administrator cannot reset the SSO link of a member. Members unlink themselves (1505). |
| 1521 | Revoked, single organisation not met | Turning on the single organisation policy revokes nobody here. |
| 1523 | Staged | No staging of members exists. |
| 1525 | Admin changed email | An administrator cannot change a member email. |
| 1608 | Sponsorships synced | No sponsored plans on a self-hosted server. |
| 1618, 1619 | Item organisation accepted, declined | No personal item transfer prompt. |
| 1622, 1623 | Automatic confirmation turned on or off by the portal | No provider portal. |
| 1800 to 1803, 1900 to 1903 | Provider events | No providers. |
