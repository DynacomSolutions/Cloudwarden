// Payload size caps for vault writes (TASKS #408), in one place. Lengths count characters of the
// encrypted string as sent. Where Bitwarden documents a limit it is used as is; the others are
// generous bounds of our own, so one member cannot bloat D1 or every member's sync.

/** Encrypted name, key and folder name (Bitwarden: 1000). */
export const MAX_ENC_NAME = 1000
/** Encrypted cipher notes (Bitwarden: 10000). */
export const MAX_CIPHER_NOTES = 10_000
/** Encrypted Send notes (Bitwarden: 1000). */
export const MAX_SEND_NOTES = 1000
/** Encrypted Send text (our bound). */
export const MAX_SEND_TEXT = 10_000
/** Serialised type payload, custom fields or password history of one cipher or Send (our bound). */
export const MAX_PAYLOAD_JSON = 100_000
/** Whole import request body (our bound; D1 rows hold about 2 MB each). */
export const MAX_IMPORT_BODY = 25_000_000
