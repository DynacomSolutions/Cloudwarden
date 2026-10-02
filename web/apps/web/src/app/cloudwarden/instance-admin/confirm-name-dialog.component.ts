// Cloudwarden: destructive action confirmation that requires typing the target's name
// (web/NOTICE.md).
import { ChangeDetectionStrategy, Component, inject } from "@angular/core";
import { FormBuilder } from "@angular/forms";
import { firstValueFrom } from "rxjs";

import { DIALOG_DATA, DialogRef, DialogService } from "@bitwarden/components";

import { SharedModule } from "../../shared";

export interface ConfirmNameDialogData {
  title: string;
  description: string;
  /** The exact text the admin must type. */
  name: string;
}

/** True only when the typed text equals the expected name exactly (surrounding spaces ignored). */
export const nameMatches = (typed: string | null | undefined, expected: string) =>
  (typed ?? "").trim() === expected.trim() && expected.trim() !== "";

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule],
  template: `
    <bit-dialog dialogSize="small" [title]="data.title">
      <div bitDialogContent>
        <p bitTypography="body1">{{ data.description }}</p>
        <bit-form-field>
          <bit-label>{{ "cwTypeNameToConfirm" | i18n: data.name }}</bit-label>
          <input bitInput type="text" [formControl]="typed" data-testid="cw-confirm-name" />
        </bit-form-field>
      </div>
      <ng-container bitDialogFooter>
        <button
          type="button"
          bitButton
          buttonType="danger"
          [disabled]="!matches()"
          (click)="dialogRef.close(true)"
        >
          {{ "delete" | i18n }}
        </button>
        <button type="button" bitButton buttonType="secondary" (click)="dialogRef.close(false)">
          {{ "cancel" | i18n }}
        </button>
      </ng-container>
    </bit-dialog>
  `,
})
export class ConfirmNameDialogComponent {
  protected readonly data = inject<ConfirmNameDialogData>(DIALOG_DATA);
  protected readonly dialogRef = inject<DialogRef<boolean>>(DialogRef);
  protected readonly typed = inject(FormBuilder).control("");

  protected matches() {
    return nameMatches(this.typed.value, this.data.name);
  }

  static async confirm(dialogService: DialogService, data: ConfirmNameDialogData) {
    const ref = dialogService.open<boolean, ConfirmNameDialogData>(ConfirmNameDialogComponent, {
      data,
    });
    return (await firstValueFrom(ref.closed)) === true;
  }
}
