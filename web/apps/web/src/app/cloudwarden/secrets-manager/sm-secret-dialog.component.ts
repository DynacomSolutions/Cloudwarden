// Cloudwarden: create, view and edit one Secrets Manager secret (web/NOTICE.md).
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";
import { firstValueFrom } from "rxjs";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import {
  CopyClickDirective,
  DIALOG_DATA,
  DialogRef,
  DialogService,
  ToastService,
} from "@bitwarden/components";

import { SharedModule } from "../../shared";

import { SmApiService, SmProject } from "./sm-api.service";
import { toastError, toastSuccess } from "./sm-dialogs";
import { SmSecretVersionsDialogComponent } from "./sm-secret-versions-dialog.component";

export interface SecretDialogData {
  organizationId: string;
  /** Absent for a new secret. */
  secretId?: string;
  /** Preselected project for a new secret. */
  projectId?: string | null;
  projects: SmProject[];
  /** Admins may keep a secret outside every project. */
  allowNoProject: boolean;
}

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, CopyClickDirective],
  template: `
    <form [formGroup]="form" (ngSubmit)="save()">
      <bit-dialog [title]="title()" [loading]="loading()">
        <div bitDialogContent>
          <bit-form-field>
            <bit-label>{{ "name" | i18n }}</bit-label>
            <input bitInput type="text" formControlName="key" data-testid="cw-sm-secret-key" />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "value" | i18n }}</bit-label>
            @if (revealed()) {
              <textarea
                bitInput
                rows="3"
                formControlName="value"
                class="tw-font-mono"
                data-testid="cw-sm-secret-value"
              ></textarea>
            } @else {
              <input
                bitInput
                type="password"
                formControlName="value"
                class="tw-font-mono"
                data-testid="cw-sm-secret-value"
              />
            }
            <button
              type="button"
              bitSuffix
              [bitIconButton]="revealed() ? 'bwi-eye-slash' : 'bwi-eye'"
              [label]="'toggleVisibility' | i18n"
              (click)="revealed.set(!revealed())"
              data-testid="cw-sm-reveal"
            ></button>
            <button
              type="button"
              bitIconButton="bwi-clone"
              bitSuffix
              showToast
              [valueLabel]="'value' | i18n"
              [appCopyClick]="form.value.value ?? ''"
              [label]="'copyValue' | i18n"
            ></button>
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "notes" | i18n }}</bit-label>
            <textarea bitInput rows="3" formControlName="note"></textarea>
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "project" | i18n }}</bit-label>
            <bit-select formControlName="projectId" data-testid="cw-sm-secret-project">
              @if (data.allowNoProject) {
                <bit-option [value]="null" [label]="'cwSmNoProject' | i18n"></bit-option>
              }
              @for (p of writableProjects; track p.id) {
                <bit-option [value]="p.id" [label]="p.name"></bit-option>
              }
            </bit-select>
          </bit-form-field>
          @if (!canWrite()) {
            <bit-callout type="info">{{ "cwSmReadOnly" | i18n }}</bit-callout>
          }
        </div>
        <ng-container bitDialogFooter>
          @if (data.secretId) {
            <button
              type="button"
              bitButton
              buttonType="secondary"
              (click)="history()"
              data-testid="cw-sm-secret-history"
            >
              {{ "cwSmVersionHistory" | i18n }}
            </button>
          }
          @if (canWrite()) {
            <button
              type="submit"
              bitButton
              buttonType="primary"
              [disabled]="form.invalid || saving()"
              data-testid="cw-sm-secret-save"
            >
              {{ "save" | i18n }}
            </button>
          }
          <button type="button" bitButton buttonType="secondary" (click)="ref.close(changedByRestore)">
            {{ (canWrite() ? "cancel" : "close") | i18n }}
          </button>
        </ng-container>
      </bit-dialog>
    </form>
  `,
})
export class SmSecretDialogComponent implements OnInit {
  protected readonly data = inject<SecretDialogData>(DIALOG_DATA);
  protected readonly ref = inject<DialogRef<boolean>>(DialogRef);
  private readonly api = inject(SmApiService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly dialogs = inject(DialogService);
  protected changedByRestore = false;

  protected readonly loading = signal(!!this.data.secretId);
  protected readonly saving = signal(false);
  protected readonly revealed = signal(!this.data.secretId);
  protected readonly canWrite = signal(true);
  protected readonly title = signal(
    this.i18n.t(this.data.secretId ? "cwSmSecretDetails" : "newSecret"),
  );
  protected readonly writableProjects = this.data.projects.filter((p) => p.write);

  protected readonly form = inject(FormBuilder).group({
    key: ["", [Validators.required, Validators.maxLength(500)]],
    value: ["", [Validators.required, Validators.maxLength(25000)]],
    note: ["", [Validators.maxLength(7000)]],
    projectId: [
      this.data.projectId ??
        (this.data.allowNoProject ? null : this.writableProjects[0]?.id) ??
        null,
      this.data.allowNoProject ? [] : [Validators.required],
    ],
  });

  async ngOnInit() {
    if (!this.data.secretId) {
      return;
    }
    try {
      const s = await this.api.getSecret(this.data.organizationId, this.data.secretId);
      this.form.setValue({
        key: s.key,
        value: s.value,
        note: s.note,
        projectId: s.projectId,
      });
      // A project the caller cannot write still has to show as the current choice.
      if (s.projectId && !this.writableProjects.some((p) => p.id === s.projectId)) {
        this.writableProjects.push({
          id: s.projectId,
          name: s.projectName ?? s.projectId,
          creationDate: "",
          revisionDate: "",
          read: true,
          write: false,
        });
      }
      this.canWrite.set(s.write);
      if (!s.write) {
        this.form.disable();
      }
    } catch (e) {
      toastError(this.toast, e);
      this.ref.close(false);
    } finally {
      this.loading.set(false);
    }
  }

  protected async history() {
    const restored = await SmSecretVersionsDialogComponent.open(this.dialogs, {
      organizationId: this.data.organizationId,
      secretId: this.data.secretId as string,
      canWrite: this.canWrite(),
    });
    if (restored) {
      // The secret changed under this dialog: reload it and tell the list to refresh.
      this.changedByRestore = true;
      await this.ngOnInit();
    }
  }

  protected async save() {
    if (this.form.invalid || !this.canWrite()) {
      return;
    }
    const v = this.form.getRawValue();
    const body = {
      key: (v.key ?? "").trim(),
      value: v.value ?? "",
      note: v.note ?? "",
      projectId: v.projectId ?? null,
    };
    this.saving.set(true);
    try {
      if (this.data.secretId) {
        await this.api.updateSecret(this.data.organizationId, this.data.secretId, body);
      } else {
        await this.api.createSecret(this.data.organizationId, body);
      }
      toastSuccess(this.toast, this.i18n.t("cwSmSecretSaved"));
      this.ref.close(true);
    } catch (e) {
      toastError(this.toast, e);
    } finally {
      this.saving.set(false);
    }
  }

  static async open(dialogs: DialogService, data: SecretDialogData) {
    const ref = dialogs.open<boolean, SecretDialogData>(SmSecretDialogComponent, { data });
    return (await firstValueFrom(ref.closed)) === true;
  }
}
