import { nameMatches } from "./confirm-name-dialog.component";

describe("nameMatches", () => {
  it("requires the exact name", () => {
    expect(nameMatches("Example Org", "Example Org")).toBe(true);
    expect(nameMatches("  Example Org ", "Example Org")).toBe(true);
    expect(nameMatches("example org", "Example Org")).toBe(false);
    expect(nameMatches("Example", "Example Org")).toBe(false);
    expect(nameMatches("", "Example Org")).toBe(false);
    expect(nameMatches(null, "Example Org")).toBe(false);
  });

  it("never matches an empty expected name", () => {
    expect(nameMatches("", "")).toBe(false);
    expect(nameMatches(" ", " ")).toBe(false);
  });
});
