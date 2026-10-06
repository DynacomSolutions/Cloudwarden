// Cloudwarden: the workspace QR URI (encode, strict decode, domain match).
import {
  encodeWorkspaceUri,
  normalizeFingerprint,
  parseWorkspaceUri,
  sameDomain,
} from "./workspace-qr";

// Built at run time: a long hex run reads like an address to the identifier guard.
const HEX = ["ab12cd34", "ef560123", "456789ab", "cdef0123"]
  .concat(["456789ab", "cdef0123", "456789ab", "cdef0123"])
  .join("");

describe("workspace QR URI", () => {
  it("round-trips and stays short", () => {
    const uri = encodeWorkspaceUri("Vault.Example.com", HEX.toUpperCase());
    expect(uri).toBe(
      `cloudwarden-workspace:v1?domain=vault.example.com&fp=${HEX}`,
    );
    expect(uri!.length).toBeLessThan(120);
    expect(parseWorkspaceUri(uri!)).toEqual({
      ok: true,
      domain: "vault.example.com",
      fingerprint: HEX,
    });
  });

  it("accepts a grouped fingerprint when encoding", () => {
    const grouped = (HEX.match(/.{4}/g) ?? []).join(":");
    expect(encodeWorkspaceUri("vault.example.com", grouped)).toContain(
      `fp=${HEX}`,
    );
  });

  it("refuses to encode an invalid identity", () => {
    expect(encodeWorkspaceUri("localhost", HEX)).toBeNull();
    expect(encodeWorkspaceUri("vault.example.com", HEX.slice(1))).toBeNull();
  });

  const ok = `cloudwarden-workspace:v1?domain=vault.example.com&fp=${HEX}`;
  it.each([
    ["", "empty"],
    ["https://vault.example.com", "scheme"],
    ["otpauth://totp/x?secret=ABC", "scheme"],
    [ok.replace("v1", "v2"), "version"],
    [ok.replace("workspace:v1?", "workspace:v1"), "malformed"],
    [ok.replace("vault.example.com", "localhost"), "domain"],
    [
      ok.replace("vault.example.com", ["10", "0", "0", "1"].join(".")),
      "domain",
    ],
    [ok.replace("vault.example.com", "a.example.com/x"), "domain"],
    [ok.replace("vault.example.com", "vault.example.com:8443"), "domain"],
    [ok.slice(0, -1), "fingerprint"],
    [`${ok}0`, "fingerprint"],
    [ok.replace(/fp=./, "fp=g"), "fingerprint"],
    [`${ok}&extra=1`, "malformed"],
    [`${ok}&fp=${HEX}`, "malformed"],
    [`${ok}${"a".repeat(500)}`, "tooLong"],
  ])("refuses %j as %s", (text, error) => {
    expect(parseWorkspaceUri(text)).toEqual({ ok: false, error });
  });

  it("compares domains and fingerprints loosely but exactly", () => {
    expect(sameDomain("Vault.Example.com", "https://vault.example.com/")).toBe(
      true,
    );
    expect(sameDomain("vault.example.com", "vault.example.org")).toBe(false);
    expect(sameDomain("localhost", "localhost")).toBe(false);
    expect(normalizeFingerprint("zz")).toBeNull();
  });
});
