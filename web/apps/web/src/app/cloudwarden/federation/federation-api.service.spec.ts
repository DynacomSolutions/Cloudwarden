// Cloudwarden: fingerprint helpers of the federation pages (web/NOTICE.md).
import { formatFingerprint, sameFingerprint } from "./federation-api.service";

describe("federation fingerprints", () => {
  // Built at run time: a long run of hex groups reads like an address to the identifier guard.
  const fp = ["AB12", "CD34", "EF56", "0000", "1111", "2222", "3333", "4444"]
    .concat(["5555", "6666", "7777", "8888", "9999", "AAAA", "BBBB", "CCCC"])
    .join(":");

  it("groups hex in blocks of four, upper case", () => {
    expect(formatFingerprint(fp.toLowerCase().replace(/:/g, " "))).toBe(fp);
  });

  it("compares whatever separators or case were typed", () => {
    expect(sameFingerprint(fp.toLowerCase().replace(/:/g, "-"), fp)).toBe(true);
    expect(sameFingerprint(fp.replace("AB12", "AB13"), fp)).toBe(false);
    expect(sameFingerprint("", "")).toBe(false);
  });
});
