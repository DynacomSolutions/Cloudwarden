// Cloudwarden: small shared dialogs and helpers for the Secrets Manager pages (web/NOTICE.md).
import { ChangeDetectionStrategy, Component, inject } from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";
import { firstValueFrom } from "rxjs";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DIALOG_DATA, DialogRef, DialogService, ToastService } from "@bitwarden/components";

import { SharedModule } from "../../shared";

import { SmBulkResult } from "./sm-api.service";

/** A readable message from an ApiService error (ErrorResponse) or any thrown value. */
export function errorMessage(e: unknown): string {
  const any = e as { getSingleMessage?: () => string; message?: string } | null;
  return any?.getSingleMessage?.() || any?.message || String(e);
}

export function toastError(toast: ToastService, e: unknown) {
  toast.showToast({ variant: "error", message: errorMessage(e) });
}

export function toastSuccess(toast: ToastService, message: string) {
  toast.showToast({ variant: "success", message });
}

/** Confirms a destructive action on `count` items. */
export function confirmDelete(
  dialogs: DialogService,
  i18n: I18nService,
  what: string,
  count: number,
) {
  return dialogs.openSimpleDialog({
    title: i18n.t("cwSmDeleteTitle", what),
    content: i18n.t("cwSmDeleteDesc", String(count)),
    type: "danger",
    acceptButtonText: { key: "delete" },
  });
}

/** Toasts the outcome of a bulk delete and returns how many failed. */
export function reportBulk(toast: ToastService, i18n: I18nService, rows: SmBulkResult[]) {
  const failed = rows.filter((r) => r.error).length;
  if (failed) {
    toast.showToast({
      variant: "error",
      message: i18n.t("cwSmBulkPartial", String(rows.length - failed), String(failed)),
    });
  } else {
    toastSuccess(toast, i18n.t("cwSmDeleted", String(rows.length)));
  }
  return failed;
}

export interface NameDialogData {
  title: string;
  label: string;
  value?: string;
}

/** Asks for one name (project or machine account); resolves to the trimmed name or null. */
@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule],
  template: `
    <form [formGroup]="form" (ngSubmit)="submit()">
      <bit-dialog dialogSize="small" [title]="data.title">
        <div bitDialogContent>
          <bit-form-field>
            <bit-label>{{ data.label }}</bit-label>
            <input bitInput type="text" formControlName="name" data-testid="cw-sm-name" />
          </bit-form-field>
        </div>
        <ng-container bitDialogFooter>
          <button type="submit" bitButton buttonType="primary" [disabled]="form.invalid">
            {{ "save" | i18n }}
          </button>
          <button type="button" bitButton buttonType="secondary" (click)="ref.close(null)">
            {{ "cancel" | i18n }}
          </button>
        </ng-container>
      </bit-dialog>
    </form>
  `,
})
export class SmNameDialogComponent {
  protected readonly data = inject<NameDialogData>(DIALOG_DATA);
  protected readonly ref = inject<DialogRef<string | null>>(DialogRef);
  protected readonly form = inject(FormBuilder).group({
    name: [this.data.value ?? "", [Validators.required, Validators.maxLength(500)]],
  });

  protected submit() {
    const name = (this.form.value.name ?? "").trim();
    if (name) {
      this.ref.close(name);
    }
  }

  static async open(dialogs: DialogService, data: NameDialogData) {
    const ref = dialogs.open<string | null, NameDialogData>(SmNameDialogComponent, { data });
    return (await firstValueFrom(ref.closed)) ?? null;
  }
}
