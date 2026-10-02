// Cloudwarden: one Secrets Manager project with its secrets, people and machine accounts
// (web/NOTICE.md).
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { ActivatedRoute, Router, RouterModule } from "@angular/router";

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
import { SmPeopleAccessComponent } from "./sm-people-access.component";
import { SmSecretsListComponent } from "./sm-secrets.component";

@Component({
  selector: "cw-sm-project",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    SharedModule,
    HeaderModule,
    RouterModule,
    SmSecretsListComponent,
    SmPeopleAccessComponent,
  ],
  template: `
    <app-header [title]="project()?.name ?? ''">
      @if (project()?.write) {
        <button type="button" bitButton buttonType="secondary" (click)="rename()">
          {{ "cwSmRename" | i18n }}
        </button>
        <button type="button" bitButton buttonType="danger" (click)="remove()">
          {{ "delete" | i18n }}
        </button>
      }
    </app-header>
    <bit-container>
      <a bitLink [routerLink]="['/sm', orgId, 'projects']" class="tw-mb-3 tw-inline-block">
        <i class="bwi bwi-angle-left" aria-hidden="true"></i>
        {{ "projects" | i18n }}
      </a>
      @if (project(); as p) {
        <bit-tab-group>
          <bit-tab [label]="'secrets' | i18n">
            <cw-sm-secrets-list [organizationId]="orgId" [projectId]="p.id"></cw-sm-secrets-list>
          </bit-tab>
          <bit-tab [label]="'people' | i18n">
            <cw-sm-people-access
              [organizationId]="orgId"
              target="projects"
              [targetId]="p.id"
              [canEdit]="p.write"
            ></cw-sm-people-access>
          </bit-tab>
          <bit-tab [label]="'machineAccounts' | i18n">
            @if (machineAccounts().length === 0) {
              <p bitTypography="body1">{{ "cwSmNoMachineAccess" | i18n }}</p>
            } @else {
              <bit-table>
                <ng-container header>
                  <tr>
                    <th bitCell>{{ "name" | i18n }}</th>
                    <th bitCell>{{ "permission" | i18n }}</th>
                  </tr>
                </ng-container>
                <ng-template body>
                  @for (m of machineAccounts(); track m.id) {
                    <tr bitRow>
                      <td bitCell>
                        <a bitLink [routerLink]="['/sm', orgId, 'machine-accounts', m.id]">
                          {{ m.name }}
                        </a>
                      </td>
                      <td bitCell>
                        {{ (m.write ? "canReadWrite" : "canRead") | i18n }}
                      </td>
                    </tr>
                  }
                </ng-template>
              </bit-table>
            }
            <p bitTypography="body2" class="tw-mt-3 tw-text-muted">
              {{ "cwSmMachineAccessHint" | i18n }}
            </p>
          </bit-tab>
        </bit-tab-group>
      }
    </bit-container>
  `,
})
export class SmProjectComponent implements OnInit {
  private readonly api = inject(SmApiService);
  private readonly dialogs = inject(DialogService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  protected readonly orgId = this.route.parent?.snapshot.paramMap.get("organizationId") ?? "";
  private readonly projectId = this.route.snapshot.paramMap.get("projectId") ?? "";

  protected readonly project = signal<SmProject | null>(null);
  protected readonly machineAccounts = signal<
    { id: string; name: string; read: boolean; write: boolean }[]
  >([]);

  async ngOnInit() {
    try {
      this.project.set(await this.api.getProject(this.orgId, this.projectId));
      this.machineAccounts.set(
        await this.api.getProjectMachineAccounts(this.orgId, this.projectId),
      );
    } catch (e) {
      toastError(this.toast, e);
      await this.router.navigate(["/sm", this.orgId, "projects"]);
    }
  }

  protected async rename() {
    const p = this.project();
    if (!p) {
      return;
    }
    const name = await SmNameDialogComponent.open(this.dialogs, {
      title: this.i18n.t("cwSmRename"),
      label: this.i18n.t("projectName"),
      value: p.name,
    });
    if (!name || name === p.name) {
      return;
    }
    try {
      this.project.set(await this.api.renameProject(this.orgId, p.id, name));
      toastSuccess(this.toast, this.i18n.t("cwSmProjectSaved"));
    } catch (e) {
      toastError(this.toast, e);
    }
  }

  protected async remove() {
    if (!(await confirmDelete(this.dialogs, this.i18n, this.i18n.t("project"), 1))) {
      return;
    }
    try {
      if (
        reportBulk(this.toast, this.i18n, await this.api.deleteProjects([this.projectId])) === 0
      ) {
        await this.router.navigate(["/sm", this.orgId, "projects"]);
      }
    } catch (e) {
      toastError(this.toast, e);
    }
  }
}
