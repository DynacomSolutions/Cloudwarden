import { withDismissBlocked } from "./dismiss-guard";

describe("withDismissBlocked", () => {
  it("blocks dismissal while the work is pending and restores it afterwards", async () => {
    const dialog = { disableClose: false as boolean | undefined };
    let finish!: () => void;
    const pending = withDismissBlocked(
      dialog,
      () => new Promise<void>((resolve) => (finish = resolve)),
    );
    expect(dialog.disableClose).toBe(true);
    finish();
    await pending;
    expect(dialog.disableClose).toBe(false);
  });

  it("restores the previous setting when the work fails", async () => {
    const dialog = { disableClose: undefined as boolean | undefined };
    await expect(
      withDismissBlocked(dialog, async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(dialog.disableClose).toBeUndefined();
  });

  it("returns the result of the work", async () => {
    const dialog = { disableClose: false as boolean | undefined };
    await expect(withDismissBlocked(dialog, async () => 42)).resolves.toBe(42);
  });
});
