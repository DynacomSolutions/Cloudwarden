# Sends, Archive and per-member state

Behaviour the official clients rely on (TASKS #250 to #254).

## Sends

| `authType` | Recipient proves access with | Needs |
|---|---|---|
| 2 (none) | nothing | |
| 1 (password) | the client-hashed password (`password_hash_b64`) | |
| 0 (email) | a six digit code mailed to an address on the Send's list | `EMAIL` binding and `MAIL_FROM` |

- Creating or editing a Send with `authType` 0 is refused with 400 when no mail transport is bound.
- `emails` is the comma separated list the clients send. It is stored lowercase, deduplicated, at most 100 addresses.
- Editing with `authType` 1 and no new password keeps the stored password. `authType` 2 clears the password and the list. `PUT /api/sends/:id/remove-password` clears the password; `PUT /api/sends/:id/remove-auth` clears the password and the list.
- The deletion date has no upper bound (clients offer a custom date); a past date is refused on create.

### Email code flow (`send_access` grant)

1. No credentials: `400 invalid_request`, `send_access_error_type: email_required`.
2. `email` only: if the address is on the list a code is mailed; the answer is always `400 invalid_request`, `email_and_otp_required`, so the list cannot be probed.
3. `email` and `otp`: a correct code returns the usual send access token; a wrong or expired one repeats `email_and_otp_required`.

A code lives 10 minutes, allows 5 guesses, works once, and is stored only as a hash. Asking again within 30 seconds does not mail a second code. Requests for addresses on the list are also limited per Send. The token is bound to the Send's current authentication and revision, so editing the Send revokes tokens already issued.

Legacy clients (`POST /api/sends/access/:accessId` and `POST /api/sends/:accessId/access/file/:fileId`) pass `email`, then `email` with `otp`, in the JSON body; each file download needs its own code.

## Archive

`PUT /api/ciphers/archive` and `/unarchive` take `{ "ids": [...] }` and return a list of ciphers; `PUT /api/ciphers/:id/archive` and `/unarchive` return one cipher. `archivedDate` is part of every cipher response and of sync. Personal items store it on the item; organisation items store it per member, so archiving never hides an item from other members. Editing an item never changes its archive state. Items created or imported with an `archivedDate` keep it.

## Per-member state of organisation items

Favourite, archive date and folder belong to each member. Favourite and archive live in `cipher_user_state`, folders in `folders_ciphers` (one row per member and item). Sharing a personal item into an organisation moves the owner's favourite and archive date into that table.
