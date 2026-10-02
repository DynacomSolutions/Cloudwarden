// Cloudwarden: instance organisations (web/NOTICE.md).
import { DatePipe } from "@angular/common";
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import { AdminOrganization, InstanceAdminApiService } from "./instance-admin-api.service";

@Component({
  selector: "cw-instance-admin-organizations",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, DatePipe],
  template: `
    <app-header></app-header>
    <bit-container>
      @if (error()) {
        <bit-callout type="danger">{{ error() }}</bit-callout>
      }
      <bit-table>
        <ng-container header>
          <tr>
            <th bitCell>{{ "name" | i18n }}</th>
            <th bitCell>{{ "cwCreated" | i18n }}</th>
            <th bitCell>{{ "members" | i18n }}</th>
            <th bitCell>{{ "items" | i18n }}</th>
            <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
          </tr>
        </ng-container>
        <ng-template body>
          @for (o of organizations(); track o.id) {
            <tr bitRow>
              <td bitCell>{{ o.name }}</td>
              <td bitCell>{{ o.createdAt | date: "short" }}</td>
              <td bitCell>{{ o.memberCount }}</td>
              <td bitCell>{{ o.itemCount }}</td>
              <td bitCell class="tw-text-right">
                <button type="button" bitButton buttonType="danger" (click)="remove(o)">
                  {{ "delete" | i18n }}
                </button>
              </td>
            </tr>
          }
        </ng-template>
      </bit-table>
    </bit-container>
  `,
})
export class InstanceAdminOrganizationsComponent implements OnInit {
  private readonly api = inject(InstanceAdminApiService);
  private readonly dialogService = inject(DialogService);
  private readonly toastService = inject(ToastService);
  private readonly i18n = inject(I18nService);

  protected readonly organizations = signal<AdminOrganization[]>([]);
  protected readonly error = signal<string | null>(null);

  async ngOnInit() {
    await this.load();
  }

  private async load() {
    try {
      this.organizations.set((await this.api.organizations()).data);
      this.error.set(null);
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
  }

  protected async remove(o: AdminOrganization) {
    const ok = await this.dialogService.openSimpleDialog({
      title: { key: "cwDeleteOrganization" },
      content: this.i18n.t("cwDeleteOrganizationDesc", o.name),
      type: "danger",
    });
    if (!ok) {
      return;
    }
    try {
      await this.api.deleteOrganization(o.id);
      this.toastService.showToast({ variant: "success", message: this.i18n.t("cwDone") });
    } catch (e) {
      this.toastService.showToast({ variant: "error", message: (e as Error)?.message ?? "" });
    }
    await this.load();
  }
}
