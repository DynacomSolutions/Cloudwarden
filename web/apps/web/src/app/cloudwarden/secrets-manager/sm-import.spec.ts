import { Utils } from "@bitwarden/common/platform/misc/utils";

import { SM_IMPORT_MAX_ITEMS, checkImport } from "./sm-import";

const P1 = Utils.newGuid();
const S1 = Utils.newGuid();
const S2 = Utils.newGuid();
const GEN = Utils.newGuid();
const gen = () => GEN;

const file = (over: Record<string, unknown> = {}) =>
  JSON.stringify({
    projects: [{ id: P1, name: "deploy" }],
    secrets: [{ id: S1, key: "DB", value: "pw", note: "n", projectIds: [P1] }],
    ...over,
  });

describe("checkImport", () => {
  it("accepts a valid file and counts what it holds", () => {
    const r = checkImport(file(), gen);
    expect(r.errors).toEqual([]);
    expect(r).toMatchObject({ projects: 1, secrets: 1, loose: 0 });
    expect(r.file?.secrets[0]).toEqual({
      id: S1,
      key: "DB",
      value: "pw",
      note: "n",
      projectIds: [P1],
    });
  });

  it("counts secrets without a project as loose", () => {
    const r = checkImport(
      file({ secrets: [{ id: S1, key: "A", value: "v" }] }),
      gen,
    );
    expect(r.errors).toEqual([]);
    expect(r.loose).toBe(1);
  });

  it("gives ids to entries that have none", () => {
    const r = checkImport(JSON.stringify({ secrets: [{ key: "A", value: "v" }] }), gen);
    expect(r.file?.secrets[0].id).toBe(gen());
  });

  it.each([
    ["not json", "{", /not valid JSON/],
    ["an array", "[]", /JSON object/],
    ["empty", "{}", /no projects or secrets/],
    ["lists", JSON.stringify({ projects: {}, secrets: [] }), /must be lists/],
  ])("rejects %s", (_n, text, re) => {
    const r = checkImport(text as string, gen);
    expect(r.file).toBeNull();
    expect(r.errors.join(" ")).toMatch(re as RegExp);
  });

  it("reports every problem with its position", () => {
    const r = checkImport(
      file({
        projects: [
          { id: P1, name: "" },
          { id: P1, name: "dup" },
          { id: "x", name: "bad id" },
        ],
        secrets: [
          { id: S1, key: "", value: "v" },
          { id: S1, key: "k", value: "" },
          { id: Utils.newGuid(), key: "k", value: "v", projectIds: ["nope"] },
          { id: S2, key: "k", value: "v", projectIds: [P1, P1] },
        ],
      }),
      gen,
    );
    expect(r.file).toBeNull();
    const all = r.errors.join("\n");
    expect(all).toContain("Project 1: the name is missing");
    expect(all).toContain("Project 2: the id is used twice");
    expect(all).toContain("Project 3: the id is not a valid id");
    expect(all).toContain("Secret 1: the name is missing");
    expect(all).toContain("Secret 2: the value is missing");
    expect(all).toContain("Secret 2: the id is used twice");
    expect(all).toContain("Secret 3: it must refer to at most one project");
    expect(all).toContain("Secret 4: it must refer to at most one project");
  });

  it("limits sizes and counts", () => {
    expect(checkImport(file({ secrets: [{ id: S1, key: "k", value: "x".repeat(25001) }] }), gen).errors[0]).toMatch(
      /value is missing or longer/,
    );
    const many = Array.from({ length: SM_IMPORT_MAX_ITEMS + 1 }, () => ({ key: "k", value: "v" }));
    expect(checkImport(JSON.stringify({ secrets: many }), gen).errors[0]).toMatch(/At most/);
  });
});
