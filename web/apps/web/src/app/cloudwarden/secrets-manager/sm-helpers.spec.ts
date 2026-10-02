import { availableGrantees } from "./sm-people-access.component";
import { SmSelection } from "./sm-selection";

describe("SmSelection", () => {
  it("toggles single rows and all rows", () => {
    const s = new SmSelection();
    const rows = [{ id: "a" }, { id: "b" }];
    s.toggle("a");
    expect(s.ids()).toEqual(["a"]);
    expect(s.allOf(rows)).toBe(false);
    s.toggleAll(rows);
    expect(s.count()).toBe(2);
    s.toggleAll(rows);
    expect(s.count()).toBe(0);
  });

  it("drops ids that are no longer listed", () => {
    const s = new SmSelection();
    s.toggle("a");
    s.toggle("b");
    s.retain(["b"]);
    expect(s.ids()).toEqual(["b"]);
  });
});

describe("availableGrantees", () => {
  it("offers members and groups not already granted", () => {
    const out = availableGrantees(
      [
        { kind: "user", id: "u1", name: "Ann" },
        { kind: "user", id: "u2", name: "Bob" },
        { kind: "group", id: "u1", name: "Same id, other kind" },
        { kind: "serviceAccount", id: "m1", name: "machine" },
      ],
      [{ kind: "user", id: "u1", name: "Ann", read: true, write: false }],
    );
    expect(out.map((g) => `${g.kind}:${g.id}`)).toEqual(["user:u2", "group:u1"]);
  });
});
