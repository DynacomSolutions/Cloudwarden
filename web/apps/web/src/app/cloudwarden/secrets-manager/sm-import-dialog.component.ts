// Cloudwarden: import Secrets Manager projects and secrets from an export file (web/NOTICE.md).
import { ChangeDetectionStrategy, Component, inject, signal } from "@angular/core";
import { firstValueFrom } from "rxjs";

import { Utils } from "@bitwarden/common/platform/misc/utils";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DIALOG_DATA, DialogRef, DialogService, ToastService } from "@bitwarden/components";

import { SharedModule } from "../../shared";

import { SmApiService } from "./sm-api.service";
import { SmImportCheck, checkImport } from "./sm-import";
import { toastError } from "./sm-dialogs";

export interface ImportDialogData {
  organizationId: string;
  /** Owners and admins may import secrets that belong to no project. */
  admin: boolean;
}

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule],
  template: `
    <bit-dialog [title]="'cwSmImportTitle' | i18n">
      <div bitDialogContent>
        <p bitTypography="body1">{{ "cwSmImportDesc" | i18n }}</p>
        <input
          type="file"
          accept=".json,application/json"
          (change)="pick($event)"
          data-testid="cw-sm-import-file"
        />
        @if (check(); as c) {
          @if (c.errors.length > 0) {
            <bit-callout type="danger" data-testid="cw-sm-import-errors">
              <ul class="tw-m-0 tw-pl-4">
                @for (e of c.errors; track e) {
                  <li>{{ e }}</li>
                }
              </ul>
            </bit-callout>
          } @else {
            <bit-callout type="info" data-testid="cw-sm-import-summary">
              {{ "cwSmImportSummary" | i18n: "" + c.projects : "" + c.secrets }}
            </bit-callout>
          }
          @if (blockedLoose()) {
            <bit-callout type="danger" data-testid="cw-sm-import-loose">
              {{ "cwSmImportLoose" | i18n: "" + c.loose }}
            </bit-callout>
          }
        }
      </div>
      <ng-container bitDialogFooter>
        <button
          type="button"
          bitButton
          buttonType="primary"
          [disabled]="!ready() || importing()"
          (click)="run()"
          data-testid="cw-sm-import-run"
        >
          {{ "cwSmImport" | i18n }}
        </button>
        <button type="button" bitButton buttonType="secondary" (click)="ref.close(false)">
          {{ "cancel" | i18n }}
        </button>
      </ng-container>
    </bit-dialog>
  `,
})
export class SmImportDialogComponent {
  protected readonly data = inject<ImportDialogData>(DIALOG_DATA);
  protected readonly ref = inject<DialogRef<boolean>>(DialogRef);
  private readonly api = inject(SmApiService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);

  protected readonly check = signal<SmImportCheck | null>(null);
  protected readonly importing = signal(false);

  protected blockedLoose() {
    const c = this.check();
    return !!c && !this.data.admin && c.loose > 0;
  }

  protected ready() {
    return !!this.check()?.file && !this.blockedLoose();
  }

  protected async pick(event: Event) {
    const file = (event.target as HTMLInputElement).files?.[0];
    if (!file) {
      this.check.set(null);
      return;
    }
    this.check.set(checkImport(await file.text(), Utils.newGuid));
  }

  /** Test seam: validates text as if it came from a chosen file. */
  loadText(text: string) {
    this.check.set(checkImport(text, Utils.newGuid));
  }

  protected async run() {
    const file = this.check()?.file;
    if (!file || !this.ready()) {
      return;
    }
    this.importing.set(true);
    try {
      await this.api.importAll(this.data.organizationId, file);
      this.toast.showToast({
        variant: "success",
        message: this.i18n.t("cwSmImportDone", String(file.projects.length), String(file.secrets.length)),
      });
      this.ref.close(true);
    } catch (e) {
      toastError(this.toast, e);
    } finally {
      this.importing.set(false);
    }
  }

  static async open(dialogs: DialogService, data: ImportDialogData) {
    const ref = dialogs.open<boolean, ImportDialogData>(SmImportDialogComponent, { data });
    return (await firstValueFrom(ref.closed)) === true;
  }
}
