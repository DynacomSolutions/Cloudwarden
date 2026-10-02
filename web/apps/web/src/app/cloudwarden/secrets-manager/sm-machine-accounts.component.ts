// Cloudwarden: Secrets Manager machine accounts list (web/NOTICE.md).
import { DatePipe } from "@angular/common";
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { ActivatedRoute, RouterModule } from "@angular/router";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import { SmApiService, SmMachineAccount } from "./sm-api.service";
import {
  SmNameDialogComponent,
  confirmDelete,
  reportBulk,
  toastError,
  toastSuccess,
} from "./sm-dialogs";
import { SmSelection } from "./sm-selection";

@Component({
  selector: "cw-sm-machine-accounts",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, DatePipe, RouterModule],
  template: `
    <app-header>
      <button
        type="button"
        bitButton
        buttonType="primary"
        (click)="create()"
        data-testid="cw-sm-new-machine-account"
      >
        <i class="bwi bwi-plus" aria-hidden="true"></i>
        {{ "newMachineAccount" | i18n }}
      </button>
    </app-header>
    <bit-container>
      @if (loading()) {
        <i class="bwi bwi-spinner bwi-spin" aria-hidden="true"></i>
      } @else if (accounts().length === 0) {
        <div
          class="tw-flex tw-flex-col tw-items-center tw-gap-3 tw-py-12 tw-text-center"
          data-testid="cw-sm-empty"
        >
          <i class="bwi bwi-wrench bwi-3x tw-text-fg-brand" aria-hidden="true"></i>
          <h2 bitTypography="h3">{{ "cwSmNoMachineAccounts" | i18n }}</h2>
          <p bitTypography="body1">{{ "cwSmNoMachineAccountsDesc" | i18n }}</p>
          <button type="button" bitButton buttonType="secondary" (click)="create()">
            {{ "newMachineAccount" | i18n }}
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
                  [checked]="selection.allOf(accounts())"
                  (change)="selection.toggleAll(accounts())"
                  [attr.aria-label]="'all' | i18n"
                />
              </th>
              <th bitCell>{{ "name" | i18n }}</th>
              <th bitCell>{{ "secrets" | i18n }}</th>
              <th bitCell>{{ "lastEdited" | i18n }}</th>
              <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
            </tr>
          </ng-container>
          <ng-template body>
            @for (a of accounts(); track a.id) {
              <tr bitRow>
                <td bitCell>
                  <input
                    type="checkbox"
                    bitCheckbox
                    [checked]="selection.has(a.id)"
                    (change)="selection.toggle(a.id)"
                    [attr.aria-label]="a.name"
                  />
                </td>
                <td bitCell>
                  <a bitLink [routerLink]="[a.id]">{{ a.name }}</a>
                </td>
                <td bitCell>{{ a.accessToSecrets ?? 0 }}</td>
                <td bitCell>{{ a.revisionDate | date: "medium" }}</td>
                <td bitCell class="tw-text-right">
                  <button
                    type="button"
                    bitIconButton="bwi-ellipsis-v"
                    [bitMenuTriggerFor]="menu"
                    [label]="'options' | i18n"
                  ></button>
                  <bit-menu #menu>
                    <a bitMenuItem [routerLink]="[a.id]">{{ "view" | i18n }}</a>
                    <button type="button" bitMenuItem (click)="rename(a)">
                      {{ "cwSmRename" | i18n }}
                    </button>
                    <button type="button" bitMenuItem (click)="remove([a.id])">
                      <span class="tw-text-danger">{{ "delete" | i18n }}</span>
                    </button>
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
export class SmMachineAccountsComponent implements OnInit {
  private readonly api = inject(SmApiService);
  private readonly dialogs = inject(DialogService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly orgId =
    inject(ActivatedRoute).parent?.snapshot.paramMap.get("organizationId") ?? "";

  protected readonly accounts = signal<SmMachineAccount[]>([]);
  protected readonly loading = signal(true);
  protected readonly selection = new SmSelection();

  async ngOnInit() {
    await this.load();
  }

  protected async load() {
    try {
      this.accounts.set(await this.api.listMachineAccounts(this.orgId));
      this.selection.retain(this.accounts().map((a) => a.id));
    } catch (e) {
      toastError(this.toast, e);
    } finally {
      this.loading.set(false);
    }
  }

  protected async create() {
    const name = await SmNameDialogComponent.open(this.dialogs, {
      title: this.i18n.t("newMachineAccount"),
      label: this.i18n.t("name"),
    });
    if (!name) {
      return;
    }
    try {
      await this.api.createMachineAccount(this.orgId, name);
      toastSuccess(this.toast, this.i18n.t("cwSmMachineAccountSaved"));
    } catch (e) {
      toastError(this.toast, e);
    }
    await this.load();
  }

  protected async rename(a: SmMachineAccount) {
    const name = await SmNameDialogComponent.open(this.dialogs, {
      title: this.i18n.t("cwSmRename"),
      label: this.i18n.t("name"),
      value: a.name,
    });
    if (!name || name === a.name) {
      return;
    }
    try {
      await this.api.renameMachineAccount(this.orgId, a.id, name);
      toastSuccess(this.toast, this.i18n.t("cwSmMachineAccountSaved"));
    } catch (e) {
      toastError(this.toast, e);
    }
    await this.load();
  }

  protected removeSelected() {
    return this.remove(this.selection.ids());
  }

  protected async remove(ids: string[]) {
    const what = this.i18n.t("machineAccounts");
    if (!(await confirmDelete(this.dialogs, this.i18n, what, ids.length))) {
      return;
    }
    try {
      reportBulk(this.toast, this.i18n, await this.api.deleteMachineAccounts(ids));
      this.selection.clear();
    } catch (e) {
      toastError(this.toast, e);
    }
    await this.load();
  }
}
