// Cloudwarden: Secrets Manager projects list (web/NOTICE.md).
import { DatePipe } from "@angular/common";
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { ActivatedRoute, RouterModule } from "@angular/router";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import { SmApiService, SmProject } from "./sm-api.service";
import {
  SmNameDialogComponent,
  confirmDelete,
  reportBulk,
  toastError,
  toastSuccess,
} from "./sm-dialogs";
import { SmSelection } from "./sm-selection";

@Component({
  selector: "cw-sm-projects",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, DatePipe, RouterModule],
  template: `
    <app-header>
      <button
        type="button"
        bitButton
        buttonType="primary"
        (click)="create()"
        data-testid="cw-sm-new-project"
      >
        <i class="bwi bwi-plus" aria-hidden="true"></i>
        {{ "newProject" | i18n }}
      </button>
    </app-header>
    <bit-container>
      @if (loading()) {
        <i class="bwi bwi-spinner bwi-spin" aria-hidden="true"></i>
      } @else if (projects().length === 0) {
        <div
          class="tw-flex tw-flex-col tw-items-center tw-gap-3 tw-py-12 tw-text-center"
          data-testid="cw-sm-empty"
        >
          <i class="bwi bwi-collection bwi-3x tw-text-fg-brand" aria-hidden="true"></i>
          <h2 bitTypography="h3">{{ "cwSmNoProjects" | i18n }}</h2>
          <p bitTypography="body1">{{ "cwSmNoProjectsDesc" | i18n }}</p>
          <button type="button" bitButton buttonType="secondary" (click)="create()">
            {{ "newProject" | i18n }}
          </button>
        </div>
      } @else {
        @if (selection.count() > 0) {
          <div class="tw-mb-3 tw-flex tw-items-center tw-gap-3">
            <span>{{ "cwSmSelected" | i18n: selection.count() }}</span>
            <button type="button" bitButton buttonType="danger" (click)="removeSelected()">
              {{ "delete" | i18n }}
            </button>
          </div>
        }
        <bit-table>
          <ng-container header>
            <tr>
              <th bitCell class="tw-w-8">
                <input
                  type="checkbox"
                  bitCheckbox
                  [checked]="selection.allOf(projects())"
                  (change)="selection.toggleAll(projects())"
                  [attr.aria-label]="'all' | i18n"
                />
              </th>
              <th bitCell>{{ "name" | i18n }}</th>
              <th bitCell>{{ "lastEdited" | i18n }}</th>
              <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
            </tr>
          </ng-container>
          <ng-template body>
            @for (p of projects(); track p.id) {
              <tr bitRow>
                <td bitCell>
                  <input
                    type="checkbox"
                    bitCheckbox
                    [checked]="selection.has(p.id)"
                    (change)="selection.toggle(p.id)"
                    [attr.aria-label]="p.name"
                  />
                </td>
                <td bitCell>
                  <a bitLink [routerLink]="[p.id]">{{ p.name }}</a>
                </td>
                <td bitCell>{{ p.revisionDate | date: "medium" }}</td>
                <td bitCell class="tw-text-right">
                  <button
                    type="button"
                    bitIconButton="bwi-ellipsis-v"
                    [bitMenuTriggerFor]="menu"
                    [label]="'options' | i18n"
                  ></button>
                  <bit-menu #menu>
                    <a bitMenuItem [routerLink]="[p.id]">{{ "view" | i18n }}</a>
                    @if (p.write) {
                      <button type="button" bitMenuItem (click)="rename(p)">
                        {{ "cwSmRename" | i18n }}
                      </button>
                      <button type="button" bitMenuItem (click)="remove([p.id])">
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
    </bit-container>
  `,
})
export class SmProjectsComponent implements OnInit {
  private readonly api = inject(SmApiService);
  private readonly dialogs = inject(DialogService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly orgId =
    inject(ActivatedRoute).parent?.snapshot.paramMap.get("organizationId") ?? "";

  protected readonly projects = signal<SmProject[]>([]);
  protected readonly loading = signal(true);
  protected readonly selection = new SmSelection();

  async ngOnInit() {
    await this.load();
  }

  protected async load() {
    try {
      this.projects.set(await this.api.listProjects(this.orgId));
      this.selection.retain(this.projects().map((p) => p.id));
    } catch (e) {
      toastError(this.toast, e);
    } finally {
      this.loading.set(false);
    }
  }

  protected async create() {
    const name = await SmNameDialogComponent.open(this.dialogs, {
      title: this.i18n.t("newProject"),
      label: this.i18n.t("projectName"),
    });
    if (!name) {
      return;
    }
    try {
      await this.api.createProject(this.orgId, name);
      toastSuccess(this.toast, this.i18n.t("cwSmProjectSaved"));
    } catch (e) {
      toastError(this.toast, e);
    }
    await this.load();
  }

  protected async rename(p: SmProject) {
    const name = await SmNameDialogComponent.open(this.dialogs, {
      title: this.i18n.t("cwSmRename"),
      label: this.i18n.t("projectName"),
      value: p.name,
    });
    if (!name || name === p.name) {
      return;
    }
    try {
      await this.api.renameProject(this.orgId, p.id, name);
      toastSuccess(this.toast, this.i18n.t("cwSmProjectSaved"));
    } catch (e) {
      toastError(this.toast, e);
    }
    await this.load();
  }

  protected removeSelected() {
    return this.remove(this.selection.ids());
  }

  protected async remove(ids: string[]) {
    if (!(await confirmDelete(this.dialogs, this.i18n, this.i18n.t("projects"), ids.length))) {
      return;
    }
    try {
      reportBulk(this.toast, this.i18n, await this.api.deleteProjects(ids));
      this.selection.clear();
    } catch (e) {
      toastError(this.toast, e);
    }
    await this.load();
  }
}
