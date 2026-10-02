// Cloudwarden: Secrets Manager access token helpers (web/NOTICE.md, docs/secrets-manager.md).
//
// Written from the wire contract in docs/secrets-manager.md ("Machine login"), the same contract
// e2e/sm-client.mjs implements. An access token as shown to the user is
// `0.<accessTokenId>.<clientSecret>:<seed b64>`; the 16 byte seed never reaches the server. The
// token's 64 byte key is HMAC-SHA256 keyed `bitwarden-accesstoken` over the seed, then
// HKDF-Expand (SHA-256) with info `sm-access-token`.

export const ACCESS_TOKEN_SEED_BYTES = 16;

const utf8 = (s: string) => new TextEncoder().encode(s);

export const toB64 = (bytes: Uint8Array) => {
  let s = "";
  for (const b of bytes) {
    s += String.fromCharCode(b);
  }
  return btoa(s);
};

export const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

const defaultSubtle = () => globalThis.crypto.subtle;

async function hmacSha256(subtle: SubtleCrypto, key: Uint8Array, data: Uint8Array) {
  const k = await subtle.importKey(
    "raw",
    new Uint8Array(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await subtle.sign("HMAC", k, new Uint8Array(data)));
}

/** HKDF-Expand (RFC 5869 step 2) with SHA-256. */
export async function hkdfExpandSha256(
  prk: Uint8Array,
  info: string,
  length: number,
  subtle: SubtleCrypto = defaultSubtle(),
) {
  const out = new Uint8Array(length);
  let prev = new Uint8Array(0);
  let filled = 0;
  for (let i = 1; filled < length; i++) {
    const infoBytes = utf8(info);
    const block = new Uint8Array(prev.length + infoBytes.length + 1);
    block.set(prev, 0);
    block.set(infoBytes, prev.length);
    block[block.length - 1] = i;
    prev = await hmacSha256(subtle, prk, block);
    const take = Math.min(prev.length, length - filled);
    out.set(prev.subarray(0, take), filled);
    filled += take;
  }
  return out;
}

/** The 64 byte key (32 encryption + 32 MAC) an access token's seed stands for. */
export async function deriveAccessTokenKey(
  seed: Uint8Array,
  subtle: SubtleCrypto = defaultSubtle(),
) {
  if (seed.length !== ACCESS_TOKEN_SEED_BYTES) {
    throw new Error("Access token seed must be 16 bytes.");
  }
  const prk = await hmacSha256(subtle, utf8("bitwarden-accesstoken"), seed);
  return hkdfExpandSha256(prk, "sm-access-token", 64, subtle);
}

export const newAccessTokenSeed = () =>
  globalThis.crypto.getRandomValues(new Uint8Array(ACCESS_TOKEN_SEED_BYTES));

/** The string shown to the user once: `0.<id>.<clientSecret>:<seed b64>`. */
export function formatAccessToken(id: string, clientSecret: string, seed: Uint8Array) {
  return `0.${id}.${clientSecret}:${toB64(seed)}`;
}

export function parseAccessToken(token: string) {
  const [first, seed, ...rest] = token.split(":");
  if (!seed || rest.length) {
    throw new Error("Access token has no key.");
  }
  const [version, id, clientSecret, ...extra] = first.split(".");
  if (version !== "0" || !id || !clientSecret || extra.length) {
    throw new Error("Malformed access token.");
  }
  const raw = fromB64(seed);
  if (raw.length !== ACCESS_TOKEN_SEED_BYTES) {
    throw new Error("Access token key must be 16 bytes.");
  }
  return { id, clientSecret, seed: raw };
}

/** Encrypts `plain` (UTF-8) into a type 2 EncString string under a raw 64 byte key. */
export type EncryptFn = (plain: string, key: Uint8Array) => Promise<string>;

export interface AccessTokenRequest {
  name: string;
  encryptedPayload: string;
  key: string;
  expireAt: string | null;
}

/**
 * Body for `POST /api/service-accounts/{id}/access-tokens`:
 * - `name`: the token name under the organisation key;
 * - `encryptedPayload`: `{"encryptionKey":"<org key b64>"}` under the key derived from `seed`,
 *   which a machine client decrypts after login to get the organisation key;
 * - `key`: the seed under the organisation key (opaque to the server).
 */
export async function buildAccessTokenRequest(opts: {
  name: string;
  orgKey: Uint8Array;
  seed: Uint8Array;
  expireAt: Date | null;
  encrypt: EncryptFn;
  subtle?: SubtleCrypto;
}): Promise<AccessTokenRequest> {
  if (opts.orgKey.length !== 64) {
    throw new Error("Organisation key must be 64 bytes.");
  }
  const tokenKey = await deriveAccessTokenKey(opts.seed, opts.subtle);
  return {
    name: await opts.encrypt(opts.name, opts.orgKey),
    encryptedPayload: await opts.encrypt(
      JSON.stringify({ encryptionKey: toB64(opts.orgKey) }),
      tokenKey,
    ),
    key: await opts.encrypt(toB64(opts.seed), opts.orgKey),
    expireAt: opts.expireAt ? opts.expireAt.toISOString() : null,
  };
}

/** Expiry choices offered when creating a token, in days (null = never). */
export const TOKEN_EXPIRY_DAYS: readonly (number | null)[] = [null, 7, 30, 60, 90];

export function expiryDate(days: number | null, now = Date.now()) {
  return days == null ? null : new Date(now + days * 24 * 60 * 60 * 1000);
}
