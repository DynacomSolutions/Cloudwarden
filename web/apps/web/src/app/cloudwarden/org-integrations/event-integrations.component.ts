// Cloudwarden: event integrations at /organizations/:id/integrations (web/NOTICE.md,
// docs/integrations.md): signed webhooks, Splunk, Datadog and Microsoft Sentinel. The event log
// itself, with CSV export, stays under Reporting.
import { DatePipe } from "@angular/common";
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { ActivatedRoute, RouterModule } from "@angular/router";
import { firstValueFrom } from "rxjs";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import { IntegrationDialogComponent, TYPE_LABELS } from "./integration-dialog.component";
import {
  EventIntegration,
  OrgIntegrationsApiService,
  organizationIdFrom,
} from "./org-integrations-api.service";

@Component({
  selector: "cw-event-integrations",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, DatePipe, RouterModule],
  template: `
    <app-header>
      <button type="button" bitButton buttonType="primary" (click)="add()" data-testid="cw-int-add">
        <i class="bwi bwi-plus" aria-hidden="true"></i>
        {{ "cwIntAdd" | i18n }}
      </button>
    </app-header>
    <bit-container>
      <p bitTypography="body1">{{ "cwIntDesc" | i18n }}</p>
      <p bitTypography="body2">
        <a bitLink routerLink="../reporting/events">{{ "cwIntExportLink" | i18n }}</a>
      </p>
      @if (loading()) {
        <i class="bwi bwi-spinner bwi-spin" aria-hidden="true"></i>
      } @else if (items().length === 0) {
        <p class="tw-text-muted" data-testid="cw-int-empty">{{ "cwIntNone" | i18n }}</p>
      } @else {
        <bit-table>
          <ng-container header>
            <tr>
              <th bitCell>{{ "name" | i18n }}</th>
              <th bitCell>{{ "type" | i18n }}</th>
              <th bitCell>{{ "status" | i18n }}</th>
              <th bitCell class="tw-w-12"></th>
            </tr>
          </ng-container>
          <ng-template body>
            @for (i of items(); track i.id) {
              <tr bitRow>
                <td bitCell>{{ i.name }}</td>
                <td bitCell>{{ labels[i.type] | i18n }}</td>
                <td bitCell>
                  @if (!i.enabled) {
                    <span bitBadge variant="secondary">{{ "disabled" | i18n }}</span>
                  } @else if (i.status.lastError) {
                    <span bitBadge variant="danger" [title]="i.status.lastError">
                      {{ "cwIntFailing" | i18n: i.status.failureCount }}
                    </span>
                    <div class="tw-text-sm tw-text-muted">{{ i.status.lastError }}</div>
                  } @else {
                    <span bitBadge variant="success">{{ "enabled" | i18n }}</span>
                    @if (i.status.lastSuccessDate) {
                      <div class="tw-text-sm tw-text-muted">
                        {{ "cwIntLastSent" | i18n: (i.status.lastSuccessDate | date: "medium") }}
                      </div>
                    }
                  }
                </td>
                <td bitCell class="tw-text-right">
                  <button
                    type="button"
                    bitIconButton="bwi-ellipsis-v"
                    [bitMenuTriggerFor]="menu"
                    [label]="'options' | i18n"
                  ></button>
                  <bit-menu #menu>
                    <button type="button" bitMenuItem (click)="edit(i)">{{ "edit" | i18n }}</button>
                    <button type="button" bitMenuItem (click)="test(i)">{{ "cwIntTest" | i18n }}</button>
                    @if (i.type === "webhook") {
                      <button type="button" bitMenuItem (click)="rotate(i)">
                        {{ "cwIntRotateSecret" | i18n }}
                      </button>
                    }
                    <button type="button" bitMenuItem (click)="remove(i)">
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
export class EventIntegrationsComponent implements OnInit {
  private readonly api = inject(OrgIntegrationsApiService);
  private readonly dialogs = inject(DialogService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly orgId = organizationIdFrom(inject(ActivatedRoute));

  protected readonly labels = TYPE_LABELS;
  protected readonly items = signal<EventIntegration[]>([]);
  protected readonly loading = signal(true);

  async ngOnInit() {
    await this.load();
  }

  protected async load() {
    try {
      this.items.set(await this.api.list(this.orgId));
    } catch (e: any) {
      this.toast.showToast({ variant: "error", message: e?.message ?? String(e) });
    } finally {
      this.loading.set(false);
    }
  }

  protected async add() {
    await this.openDialog();
  }

  protected async edit(i: EventIntegration) {
    await this.openDialog(i);
  }

  private async openDialog(integration?: EventIntegration) {
    const ref = IntegrationDialogComponent.open(this.dialogs, {
      organizationId: this.orgId,
      integration,
    });
    if (await firstValueFrom(ref.closed)) {
      await this.load();
    }
  }

  protected async test(i: EventIntegration) {
    const r = await this.api.test(this.orgId, i.id);
    this.toast.showToast(
      r.success
        ? { variant: "success", message: this.i18n.t("cwIntTestOk") }
        : { variant: "error", message: this.i18n.t("cwIntTestFailed", r.error ?? "") },
    );
  }

  protected async rotate(i: EventIntegration) {
    const ok = await this.dialogs.openSimpleDialog({
      title: { key: "cwIntRotateSecret" },
      content: { key: "cwIntRotateSecretDesc" },
      type: "warning",
    });
    if (!ok) {
      return;
    }
    const r = await this.api.rotateSecret(this.orgId, i.id);
    await this.dialogs.openSimpleDialog({
      title: { key: "cwIntSigningSecret" },
      content: r.signingSecret ?? "",
      type: "info",
      acceptButtonText: { key: "close" },
      cancelButtonText: null,
    });
  }

  protected async remove(i: EventIntegration) {
    const ok = await this.dialogs.openSimpleDialog({
      title: { key: "delete" },
      content: { key: "cwIntDeleteDesc", placeholders: [i.name] },
      type: "warning",
    });
    if (!ok) {
      return;
    }
    await this.api.remove(this.orgId, i.id);
    await this.load();
  }
}
