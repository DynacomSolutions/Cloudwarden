// Cloudwarden: the workspace QR format (docs/federation.md, "QR codes for pairing"; web/NOTICE.md).
// A QR carries this instance's domain and key fingerprint so an administrator can scan it instead of
// typing. It is only a convenience for the out-of-band comparison: the server still compares the
// fingerprint with the key it fetches itself, and the user still approves explicitly.

/** `cloudwarden-workspace:v1?domain=<host>&fp=<64 hex digits, no separators>` */
export const WORKSPACE_URI_SCHEME = "cloudwarden-workspace";
export const WORKSPACE_URI_VERSION = "v1";
const FINGERPRINT_HEX_LENGTH = 64;
const MAX_URI_LENGTH = 400;

export type WorkspaceUriError =
  | "empty"
  | "tooLong"
  | "scheme"
  | "version"
  | "domain"
  | "fingerprint"
  | "malformed";

export type WorkspaceUriResult =
  | { ok: true; domain: string; fingerprint: string }
  | { ok: false; error: WorkspaceUriError };

/** Same rule as the server's peer domain check: a host name with a dot, no port, no IP literal. */
export function normalizeDomain(input: string): string | null {
  const raw = input
    .trim()
    .toLowerCase()
    .replace(/^https:\/\//, "")
    .replace(/\/+$/, "");
  if (
    !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/.test(
      raw,
    )
  ) {
    return null;
  }
  return raw;
}

export const sameDomain = (a: string, b: string): boolean => {
  const x = normalizeDomain(a);
  return x !== null && x === normalizeDomain(b);
};

/** Fingerprint as 64 lower-case hex digits, or null when it is not one. */
export function normalizeFingerprint(input: string): string | null {
  const hex = input.replace(/[\s:-]/g, "").toLowerCase();
  return new RegExp(`^[0-9a-f]{${FINGERPRINT_HEX_LENGTH}}$`).test(hex)
    ? hex
    : null;
}

export function encodeWorkspaceUri(
  domain: string,
  fingerprint: string,
): string | null {
  const d = normalizeDomain(domain);
  const fp = normalizeFingerprint(fingerprint);
  if (!d || !fp) {
    return null;
  }
  return `${WORKSPACE_URI_SCHEME}:${WORKSPACE_URI_VERSION}?domain=${d}&fp=${fp}`;
}

/** Strict parser: anything that is not exactly this format is refused. */
export function parseWorkspaceUri(text: string): WorkspaceUriResult {
  const value = (text ?? "").trim();
  if (value === "") {
    return { ok: false, error: "empty" };
  }
  if (value.length > MAX_URI_LENGTH) {
    return { ok: false, error: "tooLong" };
  }
  const colon = value.indexOf(":");
  if (
    colon < 0 ||
    value.slice(0, colon).toLowerCase() !== WORKSPACE_URI_SCHEME
  ) {
    return { ok: false, error: "scheme" };
  }
  const rest = value.slice(colon + 1);
  const q = rest.indexOf("?");
  if (q < 0) {
    return { ok: false, error: "malformed" };
  }
  if (rest.slice(0, q).toLowerCase() !== WORKSPACE_URI_VERSION) {
    return { ok: false, error: "version" };
  }
  const params = new Map<string, string>();
  for (const pair of rest.slice(q + 1).split("&")) {
    const eq = pair.indexOf("=");
    if (eq < 1) {
      return { ok: false, error: "malformed" };
    }
    const k = pair.slice(0, eq);
    if (params.has(k) || (k !== "domain" && k !== "fp")) {
      return { ok: false, error: "malformed" };
    }
    params.set(k, pair.slice(eq + 1));
  }
  const domain = normalizeDomain(params.get("domain") ?? "");
  if (!domain) {
    return { ok: false, error: "domain" };
  }
  const fingerprint = normalizeFingerprint(params.get("fp") ?? "");
  if (!fingerprint) {
    return { ok: false, error: "fingerprint" };
  }
  return { ok: true, domain, fingerprint };
}

/** i18n key of the message for a refused scan. */
export const workspaceUriErrorKey = (e: WorkspaceUriError): string =>
  `cwQrErr_${e}`;
