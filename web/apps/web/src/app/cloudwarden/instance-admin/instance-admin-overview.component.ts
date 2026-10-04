// Cloudwarden: instance overview and diagnostics pages (web/NOTICE.md).
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import { EmailFeature } from "../emailless/email-status.service";

import { InstanceAdminApiService } from "./instance-admin-api.service";

type Row = { label: string; value: string };

/** Flattens a JSON object into label and value rows for display. */
export function toRows(obj: Record<string, unknown>, prefix = ""): Row[] {
  const rows: Row[] = [];
  for (const [k, v] of Object.entries(obj ?? {})) {
    const label = prefix ? `${prefix} / ${k}` : k;
    if (v !== null && typeof v === "object" && !Array.isArray(v)) {
      rows.push(...toRows(v as Record<string, unknown>, label));
    } else {
      rows.push({ label, value: v === null || v === undefined ? "-" : String(v) });
    }
  }
  return rows;
}

/** Locale key naming what a feature does without email. */
export function emailStateKey(state: string): string {
  switch (state) {
    case "link":
      return "cwEmailStateLink";
    case "refused":
      return "cwEmailStateRefused";
    case "skipped":
      return "cwEmailStateSkipped";
    case "manual":
      return "cwEmailStateManual";
    default:
      return "cwEmailStateAvailable";
  }
}

@Component({
  selector: "cw-instance-admin-overview",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule],
  template: `
    <app-header></app-header>
    <bit-container>
      @if (error()) {
        <bit-callout type="danger">{{ error() }}</bit-callout>
      }
      @if (mode() === "overview" && counts().length) {
        <div class="tw-grid tw-grid-cols-2 md:tw-grid-cols-4 tw-gap-4 tw-mb-6">
          @for (c of counts(); track c.label) {
            <div class="tw-rounded-lg tw-border tw-border-solid tw-border-secondary-300 tw-p-4">
              <div bitTypography="helper" class="tw-text-muted tw-uppercase">{{ c.label }}</div>
              <div bitTypography="h2" class="tw-mb-0" data-testid="cw-count">{{ c.value }}</div>
            </div>
          }
        </div>
      }
      @if (mailOff()) {
        <bit-callout type="warning" [title]="'cwEmailNotConfigured' | i18n" data-testid="cw-email-off">
          {{ "cwEmailNotConfiguredDesc" | i18n }}
          <ul class="tw-mb-0 tw-mt-2 tw-list-disc tw-pl-5">
            @for (f of affected(); track f.id) {
              <li>{{ f.label }}: {{ stateKey(f) | i18n }}</li>
            }
          </ul>
        </bit-callout>
      }
      <bit-table>
        <ng-container header>
          <tr>
            <th bitCell>{{ "cwSetting" | i18n }}</th>
            <th bitCell>{{ "cwValue" | i18n }}</th>
          </tr>
        </ng-container>
        <ng-template body>
          @for (r of rows(); track r.label) {
            <tr bitRow>
              <td bitCell>{{ r.label }}</td>
              <td bitCell class="tw-font-mono tw-break-all">{{ r.value }}</td>
            </tr>
          }
        </ng-template>
      </bit-table>
    </bit-container>
  `,
})
export class InstanceAdminOverviewComponent implements OnInit {
  protected readonly mode = signal<"overview" | "diagnostics">(
    inject(ActivatedRoute).snapshot.data["mode"] === "diagnostics" ? "diagnostics" : "overview",
  );
  private readonly api = inject(InstanceAdminApiService);
  protected readonly counts = signal<Row[]>([]);
  protected readonly rows = signal<Row[]>([]);
  protected readonly error = signal<string | null>(null);
  protected readonly mailOff = signal(false);
  protected readonly affected = signal<EmailFeature[]>([]);

  protected stateKey(f: EmailFeature): string {
    return emailStateKey(f.state);
  }

  async ngOnInit() {
    try {
      if (this.mode() === "overview") {
        const { counts, email, ...rest } = await this.api.overview();
        const status = email as { configured?: boolean; features?: EmailFeature[] } | undefined;
        this.mailOff.set(status?.configured === false);
        this.affected.set(status?.features ?? []);
        this.counts.set(toRows(counts));
        this.rows.set(toRows(rest));
      } else {
        this.rows.set(toRows(await this.api.diagnostics()));
      }
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
  }
}
