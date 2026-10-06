/** The part of a dialog reference the guard needs: the flag that blocks Escape, backdrop and X. */
export interface DismissableDialog {
  disableClose: boolean | undefined;
}

/**
 * Runs `work` with the dialog's dismissal blocked, restoring the previous setting afterwards.
 *
 * A dialog that is closed while its request is still in flight never reports the result, so the
 * page behind it is not refreshed even though the server went on to apply the change (TASKS #385:
 * an invite that takes a few seconds because the mail is sent first, dismissed with Escape).
 */
export async function withDismissBlocked<T>(
  dialog: DismissableDialog,
  work: () => Promise<T>,
): Promise<T> {
  const previous = dialog.disableClose;
  dialog.disableClose = true;
  try {
    return await work();
  } finally {
    dialog.disableClose = previous;
  }
}
