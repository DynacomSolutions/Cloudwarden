import { execFileSync } from "node:child_process";
import { createCipheriv, createDecipheriv, createHmac, randomBytes, webcrypto } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";

import {
  buildAccessTokenRequest,
  deriveAccessTokenKey,
  expiryDate,
  formatAccessToken,
  fromB64,
  parseAccessToken,
  toB64,
} from "./sm-crypto";

const subtle = webcrypto.subtle as unknown as SubtleCrypto;

// Published vector from the GPL-3.0 `bitwarden-core` crate (auth/access_token.rs), also used by
// scripts/sm-client.test.mjs for e2e/sm-client.mjs.
const VECTOR_ID = "ec2c1d46-6a4b-4751-a310-af9601317f2d"; // identifiers-allow-line
const VECTOR = `0.${VECTOR_ID}.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==`;
const VECTOR_KEY =
  "H9/oIRLtL9nGCQOVDjSMoEbJsjWXSOCb3qeyDt6ckzS3FhyboEDWyTP/CQfbIszNmAVg2ExFganG1FVFGXO/Jg=="; // gitleaks:allow

/** Type 2 EncString (AES-256-CBC + HMAC-SHA256), as the client's EncryptService produces. */
async function encType2(plain: string, key: Uint8Array) {
  const iv = randomBytes(16);
  const c = createCipheriv("aes-256-cbc", Buffer.from(key.subarray(0, 32)), iv);
  const ct = Buffer.concat([c.update(Buffer.from(plain, "utf8")), c.final()]);
  const mac = createHmac("sha256", Buffer.from(key.subarray(32)))
    .update(Buffer.concat([iv, ct]))
    .digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
}

function decType2(s: string, key: Uint8Array) {
  const [iv, ct, mac] = s
    .slice(2)
    .split("|")
    .map((x) => Buffer.from(x, "base64"));
  const want = createHmac("sha256", Buffer.from(key.subarray(32)))
    .update(Buffer.concat([iv, ct]))
    .digest();
  if (!want.equals(mac)) {
    throw new Error("bad MAC");
  }
  const d = createDecipheriv("aes-256-cbc", Buffer.from(key.subarray(0, 32)), iv);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}

describe("access token key derivation", () => {
  it("matches the published SDK vector", async () => {
    const t = parseAccessToken(VECTOR);
    expect(t.id).toBe(VECTOR_ID);
    expect(t.clientSecret).toBe("C2IgxjjLF7qSshsbwe8JGcbM075YXw");
    expect(toB64(await deriveAccessTokenKey(t.seed, subtle))).toBe(VECTOR_KEY);
  });

  it("formats and parses tokens symmetrically", () => {
    const seed = new Uint8Array(randomBytes(16));
    const s = formatAccessToken("00000000-0000-0000-0000-000000000000", "secret", seed);
    expect(s).toBe(`0.00000000-0000-0000-0000-000000000000.secret:${toB64(seed)}`);
    expect(parseAccessToken(s).seed).toEqual(seed);
  });

  it("rejects malformed tokens and seeds", async () => {
    expect(() => parseAccessToken(VECTOR.replace(/^0/, "1"))).toThrow(/Malformed/);
    expect(() => parseAccessToken(VECTOR.split(":")[0])).toThrow(/no key/);
    expect(() => parseAccessToken(`${VECTOR.split(":")[0]}:AAAA`)).toThrow(/16 bytes/);
    await expect(deriveAccessTokenKey(new Uint8Array(8), subtle)).rejects.toThrow(/16 bytes/);
  });

  it("round-trips base64", () => {
    const b = new Uint8Array(randomBytes(33));
    expect(fromB64(toB64(b))).toEqual(b);
  });
});

describe("buildAccessTokenRequest", () => {
  it("wraps the organisation key under the token key and the seed under the org key", async () => {
    const orgKey = new Uint8Array(randomBytes(64));
    const seed = new Uint8Array(randomBytes(16));
    const expireAt = new Date(Date.UTC(2030, 0, 1));
    const req = await buildAccessTokenRequest({
      name: "ci token",
      orgKey,
      seed,
      expireAt,
      encrypt: encType2,
      subtle,
    });
    expect(decType2(req.name, orgKey)).toBe("ci token");
    expect(decType2(req.key, orgKey)).toBe(toB64(seed));
    const tokenKey = await deriveAccessTokenKey(seed, subtle);
    expect(JSON.parse(decType2(req.encryptedPayload, tokenKey))).toEqual({
      encryptionKey: toB64(orgKey),
    });
    expect(() => decType2(req.encryptedPayload, orgKey)).toThrow(/MAC/);
    expect(req.expireAt).toBe(expireAt.toISOString());
  });

  it("rejects an organisation key of the wrong size", async () => {
    await expect(
      buildAccessTokenRequest({
        name: "x",
        orgKey: new Uint8Array(32),
        seed: new Uint8Array(16),
        expireAt: null,
        encrypt: encType2,
        subtle,
      }),
    ).rejects.toThrow(/64 bytes/);
  });

  it("computes expiry dates", () => {
    expect(expiryDate(null)).toBeNull();
    expect(expiryDate(30, 0)?.getTime()).toBe(30 * 24 * 60 * 60 * 1000);
  });

  // The machine client used by `pnpm e2e` (e2e/sm-client.mjs, from the GPL SDK contract) must be
  // able to parse a token built here and decrypt its payload to the organisation key.
  const repoRoot = join(__dirname, "../../../../../../..");
  const smClient = join(repoRoot, "e2e/sm-client.mjs");
  (existsSync(smClient) ? it : it.skip)(
    "produces tokens e2e/sm-client.mjs parses and decrypts",
    async () => {
      const orgKey = new Uint8Array(randomBytes(64));
      const seed = new Uint8Array(randomBytes(16));
      const req = await buildAccessTokenRequest({
        name: "ui token",
        orgKey,
        seed,
        expireAt: null,
        encrypt: encType2,
        subtle,
      });
      const token = formatAccessToken("00000000-0000-4000-8000-000000000000", "abc123", seed);
      const script = `
        import { parseAccessToken } from ${JSON.stringify(smClient)};
        import { decType2 } from ${JSON.stringify(join(repoRoot, "e2e/crypto.mjs"))};
        const [token, payload] = process.argv.slice(1);
        const t = parseAccessToken(token);
        const body = JSON.parse((await decType2(payload, t.key)).toString());
        console.log(JSON.stringify({ id: t.id, clientSecret: t.clientSecret, key: body.encryptionKey }));
      `;
      const out = execFileSync(
        process.execPath,
        ["--input-type=module", "-e", script, token, req.encryptedPayload],
        { encoding: "utf8" },
      );
      expect(JSON.parse(out)).toEqual({
        id: "00000000-0000-4000-8000-000000000000",
        clientSecret: "abc123",
        key: toB64(orgKey),
      });
    },
  );
});
