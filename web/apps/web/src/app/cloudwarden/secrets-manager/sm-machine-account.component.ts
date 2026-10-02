// Cloudwarden: one machine account with its project access, people and access tokens
// (web/NOTICE.md).
import { DatePipe } from "@angular/common";
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  inject,
  signal,
} from "@angular/core";
import { FormsModule } from "@angular/forms";
import { ActivatedRoute, Router, RouterModule } from "@angular/router";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import {
  SmAccessToken,
  SmApiService,
  SmMachineAccount,
  SmProject,
  SmProjectGrant,
} from "./sm-api.service";
import {
  SmNameDialogComponent,
  confirmDelete,
  reportBulk,
  toastError,
  toastSuccess,
} from "./sm-dialogs";
import { SmEventsComponent } from "./sm-events.component";
import { SmPeopleAccessComponent } from "./sm-people-access.component";
import { SmTokenDialogComponent } from "./sm-token-dialog.component";

@Component({
  selector: "cw-sm-machine-account",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    SharedModule,
    HeaderModule,
    RouterModule,
    DatePipe,
    FormsModule,
    SmPeopleAccessComponent,
    SmEventsComponent,
  ],
  template: `
    <app-header [title]="account()?.name ?? ''">
      <button type="button" bitButton buttonType="secondary" (click)="rename()">
        {{ "cwSmRename" | i18n }}
      </button>
      <button type="button" bitButton buttonType="danger" (click)="remove()">
        {{ "delete" | i18n }}
      </button>
    </app-header>
    <bit-container>
      <a bitLink [routerLink]="['/sm', orgId, 'machine-accounts']" class="tw-mb-3 tw-inline-block">
        <i class="bwi bwi-angle-left" aria-hidden="true"></i>
        {{ "machineAccounts" | i18n }}
      </a>
      @if (account(); as a) {
        <bit-tab-group>
          <bit-tab [label]="'projects' | i18n">
            <p bitTypography="body2" class="tw-text-muted">
              {{ "cwSmGrantsDesc" | i18n }}
            </p>
            <div class="tw-mb-4 tw-flex tw-flex-wrap tw-items-end tw-gap-3">
              <bit-form-field class="tw-mb-0 tw-min-w-64 tw-grow">
                <bit-label>{{ "cwSmAddProject" | i18n }}</bit-label>
                <bit-select [(ngModel)]="pick" data-testid="cw-sm-grant-pick">
                  @for (p of availableProjects(); track p.id) {
                    <bit-option [value]="p.id" [label]="p.name"></bit-option>
                  }
                </bit-select>
              </bit-form-field>
              <bit-form-field class="tw-mb-0 tw-w-48">
                <bit-label>{{ "permission" | i18n }}</bit-label>
                <bit-select [(ngModel)]="pickPermission">
                  <bit-option value="read" [label]="'canRead' | i18n"></bit-option>
                  <bit-option value="write" [label]="'canReadWrite' | i18n"></bit-option>
                </bit-select>
              </bit-form-field>
              <button
                type="button"
                bitButton
                buttonType="secondary"
                [disabled]="!pick"
                (click)="addGrant()"
                data-testid="cw-sm-grant-add"
              >
                {{ "add" | i18n }}
              </button>
            </div>
            @if (grants().length === 0) {
              <p bitTypography="body1" data-testid="cw-sm-empty">
                {{ "cwSmNoGrants" | i18n }}
              </p>
            } @else {
              <bit-table>
                <ng-container header>
                  <tr>
                    <th bitCell>{{ "project" | i18n }}</th>
                    <th bitCell>{{ "permission" | i18n }}</th>
                    <th bitCell class="tw-text-right">
                      {{ "options" | i18n }}
                    </th>
                  </tr>
                </ng-container>
                <ng-template body>
                  @for (g of grants(); track g.projectId) {
                    <tr bitRow>
                      <td bitCell>
                        <a bitLink [routerLink]="['/sm', orgId, 'projects', g.projectId]">
                          {{ g.projectName }}
                        </a>
                      </td>
                      <td bitCell>
                        <select
                          class="tw-rounded tw-border tw-border-secondary-500 tw-bg-background tw-p-1"
                          [disabled]="!g.editable"
                          [ngModel]="g.write ? 'write' : 'read'"
                          (ngModelChange)="setGrant(g, $event)"
                          [attr.aria-label]="'permission' | i18n"
                        >
                          <option value="read">{{ "canRead" | i18n }}</option>
                          <option value="write">
                            {{ "canReadWrite" | i18n }}
                          </option>
                        </select>
                      </td>
                      <td bitCell class="tw-text-right">
                        @if (g.editable) {
                          <button
                            type="button"
                            bitIconButton="bwi-close"
                            [label]="'remove' | i18n"
                            (click)="removeGrant(g)"
                          ></button>
                        }
                      </td>
                    </tr>
                  }
                </ng-template>
              </bit-table>
            }
            <div class="tw-mt-4">
              <button
                type="button"
                bitButton
                buttonType="primary"
                [disabled]="!grantsDirty()"
                (click)="saveGrants()"
                data-testid="cw-sm-grant-save"
              >
                {{ "save" | i18n }}
              </button>
            </div>
          </bit-tab>
          <bit-tab [label]="'people' | i18n">
            <cw-sm-people-access
              [organizationId]="orgId"
              target="service-accounts"
              [targetId]="a.id"
            ></cw-sm-people-access>
          </bit-tab>
          <bit-tab [label]="'accessTokens' | i18n">
            <div class="tw-mb-3 tw-flex tw-items-center tw-gap-3">
              <button
                type="button"
                bitButton
                buttonType="primary"
                (click)="createToken()"
                data-testid="cw-sm-new-token"
              >
                <i class="bwi bwi-plus" aria-hidden="true"></i>
                {{ "cwSmNewAccessToken" | i18n }}
              </button>
            </div>
            @if (tokens().length === 0) {
              <p bitTypography="body1" data-testid="cw-sm-empty">
                {{ "cwSmNoTokens" | i18n }}
              </p>
            } @else {
              <bit-table>
                <ng-container header>
                  <tr>
                    <th bitCell>{{ "name" | i18n }}</th>
                    <th bitCell>{{ "expires" | i18n }}</th>
                    <th bitCell>{{ "cwCreated" | i18n }}</th>
                    <th bitCell class="tw-text-right">
                      {{ "options" | i18n }}
                    </th>
                  </tr>
                </ng-container>
                <ng-template body>
                  @for (t of tokens(); track t.id) {
                    <tr bitRow>
                      <td bitCell>{{ t.name }}</td>
                      <td bitCell>
                        {{ t.expireAt ? (t.expireAt | date: "medium") : ("never" | i18n) }}
                      </td>
                      <td bitCell>{{ t.creationDate | date: "medium" }}</td>
                      <td bitCell class="tw-text-right">
                        <button type="button" bitButton buttonType="danger" (click)="revoke(t)">
                          {{ "revoke" | i18n }}
                        </button>
                      </td>
                    </tr>
                  }
                </ng-template>
              </bit-table>
            }
          </bit-tab>
          <bit-tab [label]="'cwSmEvents' | i18n">
            <cw-sm-events [machineAccountId]="a.id"></cw-sm-events>
          </bit-tab>
        </bit-tab-group>
      }
    </bit-container>
  `,
})
export class SmMachineAccountComponent implements OnInit {
  private readonly api = inject(SmApiService);
  private readonly dialogs = inject(DialogService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  protected readonly orgId = this.route.parent?.snapshot.paramMap.get("organizationId") ?? "";
  private readonly id = this.route.snapshot.paramMap.get("machineAccountId") ?? "";

  protected readonly account = signal<SmMachineAccount | null>(null);
  protected readonly tokens = signal<SmAccessToken[]>([]);
  protected readonly grants = signal<SmProjectGrant[]>([]);
  protected readonly projects = signal<SmProject[]>([]);
  protected readonly grantsDirty = signal(false);
  protected readonly availableProjects = computed(() => {
    const taken = new Set(this.grants().map((g) => g.projectId));
    return this.projects().filter((p) => p.write && !taken.has(p.id));
  });
  protected pick: string | null = null;
  protected pickPermission: "read" | "write" = "read";

  async ngOnInit() {
    try {
      this.account.set(await this.api.getMachineAccount(this.orgId, this.id));
      const [tokens, grants, projects] = await Promise.all([
        this.api.listAccessTokens(this.orgId, this.id),
        this.api.getProjectGrants(this.orgId, this.id),
        this.api.listProjects(this.orgId),
      ]);
      this.tokens.set(tokens);
      this.grants.set(grants);
      this.projects.set(projects);
    } catch (e) {
      toastError(this.toast, e);
      await this.router.navigate(["/sm", this.orgId, "machine-accounts"]);
    }
  }

  protected addGrant() {
    const p = this.availableProjects().find((x) => x.id === this.pick);
    if (!p) {
      return;
    }
    this.grants.set([
      ...this.grants(),
      {
        projectId: p.id,
        projectName: p.name,
        read: true,
        write: this.pickPermission === "write",
        editable: true,
      },
    ]);
    this.pick = null;
    this.grantsDirty.set(true);
  }

  protected setGrant(g: SmProjectGrant, value: "read" | "write") {
    this.grants.set(
      this.grants().map((x) => (x === g ? { ...x, read: true, write: value === "write" } : x)),
    );
    this.grantsDirty.set(true);
  }

  protected removeGrant(g: SmProjectGrant) {
    this.grants.set(this.grants().filter((x) => x !== g));
    this.grantsDirty.set(true);
  }

  protected async saveGrants() {
    try {
      this.grants.set(await this.api.putProjectGrants(this.orgId, this.id, this.grants()));
      this.grantsDirty.set(false);
      toastSuccess(this.toast, this.i18n.t("cwSmAccessSaved"));
    } catch (e) {
      toastError(this.toast, e);
    }
  }

  protected async createToken() {
    const created = await SmTokenDialogComponent.open(this.dialogs, {
      organizationId: this.orgId,
      machineAccountId: this.id,
    });
    if (created) {
      await this.loadTokens();
    }
  }

  private async loadTokens() {
    try {
      this.tokens.set(await this.api.listAccessTokens(this.orgId, this.id));
    } catch (e) {
      toastError(this.toast, e);
    }
  }

  protected async revoke(t: SmAccessToken) {
    const ok = await this.dialogs.openSimpleDialog({
      title: this.i18n.t("cwSmRevokeTitle"),
      content: this.i18n.t("cwSmRevokeDesc", t.name),
      type: "danger",
      acceptButtonText: { key: "revoke" },
    });
    if (!ok) {
      return;
    }
    try {
      await this.api.revokeAccessTokens(this.id, [t.id]);
      toastSuccess(this.toast, this.i18n.t("cwSmTokenRevoked"));
    } catch (e) {
      toastError(this.toast, e);
    }
    await this.loadTokens();
  }

  protected async rename() {
    const a = this.account();
    if (!a) {
      return;
    }
    const name = await SmNameDialogComponent.open(this.dialogs, {
      title: this.i18n.t("cwSmRename"),
      label: this.i18n.t("name"),
      value: a.name,
    });
    if (!name || name === a.name) {
      return;
    }
    try {
      this.account.set(await this.api.renameMachineAccount(this.orgId, a.id, name));
      toastSuccess(this.toast, this.i18n.t("cwSmMachineAccountSaved"));
    } catch (e) {
      toastError(this.toast, e);
    }
  }

  protected async remove() {
    const what = this.i18n.t("machineAccount");
    if (!(await confirmDelete(this.dialogs, this.i18n, what, 1))) {
      return;
    }
    try {
      if (
        reportBulk(this.toast, this.i18n, await this.api.deleteMachineAccounts([this.id])) === 0
      ) {
        await this.router.navigate(["/sm", this.orgId, "machine-accounts"]);
      }
    } catch (e) {
      toastError(this.toast, e);
    }
  }
}
