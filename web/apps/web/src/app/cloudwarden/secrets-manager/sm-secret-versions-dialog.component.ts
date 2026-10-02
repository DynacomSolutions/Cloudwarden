// Cloudwarden: version history of one Secrets Manager secret (web/NOTICE.md).
import { DatePipe } from "@angular/common";
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { firstValueFrom } from "rxjs";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { DIALOG_DATA, DialogRef, DialogService, ToastService } from "@bitwarden/components";

import { SharedModule } from "../../shared";

import { SmApiService, SmSecretVersion } from "./sm-api.service";
import { toastError, toastSuccess } from "./sm-dialogs";

export interface VersionsDialogData {
  organizationId: string;
  secretId: string;
  /** Restoring and deleting need write access to the secret. */
  canWrite: boolean;
}

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, DatePipe],
  template: `
    <bit-dialog dialogSize="large" [title]="'cwSmVersionHistory' | i18n" [loading]="loading()">
      <div bitDialogContent>
        @if (versions().length === 0 && !loading()) {
          <p bitTypography="body1" data-testid="cw-sm-no-versions">{{ "cwSmNoVersions" | i18n }}</p>
        } @else {
          <bit-table>
            <ng-container header>
              <tr>
                <th bitCell>{{ "date" | i18n }}</th>
                <th bitCell>{{ "cwSmChangedBy" | i18n }}</th>
                <th bitCell>{{ "value" | i18n }}</th>
                <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
              </tr>
            </ng-container>
            <ng-template body>
              @for (v of versions(); track v.id) {
                <tr bitRow data-testid="cw-sm-version">
                  <td bitCell>{{ v.versionDate | date: "medium" }}</td>
                  <td bitCell>{{ v.editor ?? ("cwSmUnknownEditor" | i18n) }}</td>
                  <td bitCell class="tw-font-mono tw-break-all">
                    @if (shown().has(v.id)) {
                      {{ v.value }}
                    } @else {
                      ••••••••
                    }
                  </td>
                  <td bitCell class="tw-text-right">
                    <button
                      type="button"
                      bitIconButton="bwi-eye"
                      [label]="'toggleVisibility' | i18n"
                      (click)="toggle(v.id)"
                      data-testid="cw-sm-version-reveal"
                    ></button>
                    <button
                      type="button"
                      bitIconButton="bwi-clone"
                      [label]="'copyValue' | i18n"
                      (click)="copy(v)"
                    ></button>
                    @if (data.canWrite) {
                      <button
                        type="button"
                        bitIconButton="bwi-undo"
                        [label]="'cwSmRestoreVersion' | i18n"
                        (click)="restore(v)"
                        data-testid="cw-sm-version-restore"
                      ></button>
                      <button
                        type="button"
                        bitIconButton="bwi-trash"
                        buttonType="danger"
                        [label]="'delete' | i18n"
                        (click)="remove(v)"
                        data-testid="cw-sm-version-delete"
                      ></button>
                    }
                  </td>
                </tr>
              }
            </ng-template>
          </bit-table>
        }
      </div>
      <ng-container bitDialogFooter>
        <button type="button" bitButton buttonType="secondary" (click)="ref.close(changed)">
          {{ "close" | i18n }}
        </button>
      </ng-container>
    </bit-dialog>
  `,
})
export class SmSecretVersionsDialogComponent implements OnInit {
  protected readonly data = inject<VersionsDialogData>(DIALOG_DATA);
  protected readonly ref = inject<DialogRef<boolean>>(DialogRef);
  private readonly api = inject(SmApiService);
  private readonly dialogs = inject(DialogService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly platform = inject(PlatformUtilsService);

  protected readonly loading = signal(true);
  protected readonly versions = signal<SmSecretVersion[]>([]);
  protected readonly shown = signal<Set<string>>(new Set());
  /** True once the secret itself changed (a restore), so the caller reloads. */
  protected changed = false;

  async ngOnInit() {
    await this.load();
  }

  private async load() {
    try {
      this.versions.set(await this.api.listSecretVersions(this.data.organizationId, this.data.secretId));
    } catch (e) {
      toastError(this.toast, e);
    } finally {
      this.loading.set(false);
    }
  }

  protected toggle(id: string) {
    const next = new Set(this.shown());
    if (!next.delete(id)) {
      next.add(id);
    }
    this.shown.set(next);
  }

  protected copy(v: SmSecretVersion) {
    this.platform.copyToClipboard(v.value);
    toastSuccess(this.toast, this.i18n.t("valueCopied", this.i18n.t("value")));
  }

  protected async restore(v: SmSecretVersion) {
    const ok = await this.dialogs.openSimpleDialog({
      title: this.i18n.t("cwSmRestoreVersion"),
      content: this.i18n.t("cwSmRestoreDesc"),
      type: "warning",
      acceptButtonText: { key: "cwSmRestoreVersion" },
    });
    if (!ok) {
      return;
    }
    try {
      await this.api.restoreSecretVersion(this.data.secretId, v.id);
      this.changed = true;
      toastSuccess(this.toast, this.i18n.t("cwSmVersionRestored"));
      await this.load();
    } catch (e) {
      toastError(this.toast, e);
    }
  }

  protected async remove(v: SmSecretVersion) {
    const ok = await this.dialogs.openSimpleDialog({
      title: this.i18n.t("cwSmDeleteVersionTitle"),
      content: this.i18n.t("cwSmDeleteVersionDesc"),
      type: "danger",
      acceptButtonText: { key: "delete" },
    });
    if (!ok) {
      return;
    }
    try {
      await this.api.deleteSecretVersions([v.id]);
      await this.load();
    } catch (e) {
      toastError(this.toast, e);
    }
  }

  static async open(dialogs: DialogService, data: VersionsDialogData) {
    const ref = dialogs.open<boolean, VersionsDialogData>(SmSecretVersionsDialogComponent, {
      data,
    });
    return (await firstValueFrom(ref.closed)) === true;
  }
}
