// Cloudwarden: Secrets Manager secrets list, for the organisation or one project (web/NOTICE.md).
import { DatePipe } from "@angular/common";
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  inject,
  input,
  signal,
  viewChild,
} from "@angular/core";
import { ActivatedRoute, RouterModule } from "@angular/router";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { FileDownloadService } from "@bitwarden/common/platform/abstractions/file-download/file-download.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import { SmApiService, SmProject, SmSecretListItem } from "./sm-api.service";
import { confirmDelete, reportBulk, toastError, toastSuccess } from "./sm-dialogs";
import { SmImportDialogComponent } from "./sm-import-dialog.component";
import { SmSecretDialogComponent } from "./sm-secret-dialog.component";
import { SmSelection } from "./sm-selection";

@Component({
  selector: "cw-sm-secrets-list",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, DatePipe, RouterModule],
  template: `
    <div class="tw-mb-3 tw-flex tw-items-center tw-gap-3">
      <button
        type="button"
        bitButton
        buttonType="primary"
        (click)="create()"
        data-testid="cw-sm-new-secret"
      >
        <i class="bwi bwi-plus" aria-hidden="true"></i>
        {{ "newSecret" | i18n }}
      </button>
      @if (selection.count() > 0) {
        <span>{{ "cwSmSelected" | i18n: selection.count() }}</span>
        <button type="button" bitButton buttonType="danger" (click)="removeSelected()">
          {{ "delete" | i18n }}
        </button>
      }
    </div>
    @if (loading()) {
      <i class="bwi bwi-spinner bwi-spin" aria-hidden="true"></i>
    } @else if (secrets().length === 0) {
      <div
        class="tw-flex tw-flex-col tw-items-center tw-gap-3 tw-py-12 tw-text-center"
        data-testid="cw-sm-empty"
      >
        <i class="bwi bwi-key bwi-3x tw-text-fg-brand" aria-hidden="true"></i>
        <h2 bitTypography="h3">{{ "cwSmNoSecrets" | i18n }}</h2>
        <p bitTypography="body1">{{ "cwSmNoSecretsDesc" | i18n }}</p>
      </div>
    } @else {
      <bit-table>
        <ng-container header>
          <tr>
            <th bitCell class="tw-w-8">
              <input
                type="checkbox"
                bitCheckbox
                [checked]="selection.allOf(secrets())"
                (change)="selection.toggleAll(secrets())"
                [attr.aria-label]="'all' | i18n"
              />
            </th>
            <th bitCell>{{ "name" | i18n }}</th>
            @if (!projectId()) {
              <th bitCell>{{ "project" | i18n }}</th>
            }
            <th bitCell>{{ "lastEdited" | i18n }}</th>
            <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
          </tr>
        </ng-container>
        <ng-template body>
          @for (s of secrets(); track s.id) {
            <tr bitRow>
              <td bitCell>
                <input
                  type="checkbox"
                  bitCheckbox
                  [checked]="selection.has(s.id)"
                  (change)="selection.toggle(s.id)"
                  [attr.aria-label]="s.key"
                />
              </td>
              <td bitCell>
                <button type="button" bitLink (click)="open(s)">
                  {{ s.key }}
                </button>
              </td>
              @if (!projectId()) {
                <td bitCell>
                  @if (s.projectId) {
                    <a bitLink [routerLink]="['/sm', organizationId(), 'projects', s.projectId]">
                      {{ s.projectName }}
                    </a>
                  } @else {
                    <span class="tw-text-muted">{{ "cwSmNoProject" | i18n }}</span>
                  }
                </td>
              }
              <td bitCell>{{ s.revisionDate | date: "medium" }}</td>
              <td bitCell class="tw-text-right">
                <button
                  type="button"
                  bitIconButton="bwi-ellipsis-v"
                  [bitMenuTriggerFor]="menu"
                  [label]="'options' | i18n"
                ></button>
                <bit-menu #menu>
                  <button type="button" bitMenuItem (click)="open(s)">
                    {{ (s.write ? "edit" : "view") | i18n }}
                  </button>
                  <button type="button" bitMenuItem (click)="copyValue(s)">
                    {{ "copyValue" | i18n }}
                  </button>
                  @if (s.write) {
                    <button type="button" bitMenuItem (click)="remove([s.id])">
                      <span class="tw-text-danger">{{ "delete" | i18n }}</span>
                    </button>
                  }
                </bit-menu>
              </td>
            </tr>
          }
        </ng-template>
      </bit-table>
    }
  `,
})
export class SmSecretsListComponent implements OnInit {
  readonly organizationId = input.required<string>();
  readonly projectId = input<string | null>(null);

  private readonly api = inject(SmApiService);
  private readonly dialogs = inject(DialogService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly platform = inject(PlatformUtilsService);

  protected readonly secrets = signal<SmSecretListItem[]>([]);
  protected readonly loading = signal(true);
  protected readonly selection = new SmSelection();
  private projects: SmProject[] = [];
  private admin = false;

  async ngOnInit() {
    await this.load();
  }

  async load() {
    try {
      const orgId = this.organizationId();
      const [secrets, projects, admin] = await Promise.all([
        this.api.listSecrets(orgId, this.projectId() ?? undefined),
        this.api.listProjects(orgId),
        this.api.isOrgAdmin(orgId),
      ]);
      this.secrets.set(secrets);
      this.projects = projects;
      this.admin = admin;
      this.selection.retain(secrets.map((s) => s.id));
    } catch (e) {
      toastError(this.toast, e);
    } finally {
      this.loading.set(false);
    }
  }

  protected async create() {
    if (!this.admin && !this.projects.some((p) => p.write)) {
      toastError(this.toast, new Error(this.i18n.t("cwSmNeedProject")));
      return;
    }
    const saved = await SmSecretDialogComponent.open(this.dialogs, {
      organizationId: this.organizationId(),
      projectId: this.projectId(),
      projects: this.projects,
      allowNoProject: this.admin,
    });
    if (saved) {
      await this.load();
    }
  }

  protected async open(s: SmSecretListItem) {
    const saved = await SmSecretDialogComponent.open(this.dialogs, {
      organizationId: this.organizationId(),
      secretId: s.id,
      projects: this.projects,
      allowNoProject: this.admin,
    });
    if (saved) {
      await this.load();
    }
  }

  protected async copyValue(s: SmSecretListItem) {
    try {
      const full = await this.api.getSecret(this.organizationId(), s.id);
      this.platform.copyToClipboard(full.value);
      toastSuccess(this.toast, this.i18n.t("valueCopied", this.i18n.t("value")));
    } catch (e) {
      toastError(this.toast, e);
    }
  }

  protected removeSelected() {
    return this.remove(this.selection.ids());
  }

  protected async remove(ids: string[]) {
    if (!(await confirmDelete(this.dialogs, this.i18n, this.i18n.t("secrets"), ids.length))) {
      return;
    }
    try {
      reportBulk(this.toast, this.i18n, await this.api.deleteSecrets(ids));
      this.selection.clear();
    } catch (e) {
      toastError(this.toast, e);
    }
    await this.load();
  }
}

@Component({
  selector: "cw-sm-secrets-page",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, SmSecretsListComponent],
  template: `
    <app-header>
      <button
        type="button"
        bitButton
        buttonType="secondary"
        (click)="importFile()"
        data-testid="cw-sm-import"
      >
        {{ "cwSmImport" | i18n }}
      </button>
      <button
        type="button"
        bitButton
        buttonType="secondary"
        (click)="exportFile()"
        data-testid="cw-sm-export"
      >
        {{ "cwSmExport" | i18n }}
      </button>
    </app-header>
    <bit-container>
      <cw-sm-secrets-list #secretsList [organizationId]="organizationId"></cw-sm-secrets-list>
    </bit-container>
  `,
})
export class SmSecretsPageComponent {
  protected readonly organizationId =
    inject(ActivatedRoute).parent?.snapshot.paramMap.get("organizationId") ?? "";
  private readonly api = inject(SmApiService);
  private readonly dialogs = inject(DialogService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly download = inject(FileDownloadService);
  private readonly list = viewChild(SmSecretsListComponent);

  protected async importFile() {
    const admin = await this.api.isOrgAdmin(this.organizationId);
    if (await SmImportDialogComponent.open(this.dialogs, { organizationId: this.organizationId, admin })) {
      await this.list()?.load();
    }
  }

  /** Writes the decrypted projects and secrets the caller can read as a JSON file. */
  protected async exportFile() {
    try {
      const file = await this.api.exportAll(this.organizationId);
      const stamp = new Date().toISOString().slice(0, 10);
      this.download.download({
        fileName: `secrets-manager-export-${stamp}.json`,
        blobData: JSON.stringify(file, null, 2),
        blobOptions: { type: "application/json" },
      });
      toastSuccess(this.toast, this.i18n.t("cwSmExportDone", String(file.secrets.length)));
    } catch (e) {
      toastError(this.toast, e);
    }
  }
}
