// Cloudwarden: Instance admin > Health (web/NOTICE.md, docs/admin.md, TASKS #361).
// Shows whether the Worker is being stopped by Cloudflare limits, from Cloudflare's analytics.
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  inject,
  signal,
} from "@angular/core";
import { ActivatedRoute, Router } from "@angular/router";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import {
  Health,
  HealthData,
  HealthNotConfigured,
  HealthRange,
  InstanceAdminApiService,
} from "./instance-admin-api.service";

export const LIMITS_URL =
  "https://developers.cloudflare.com/workers/platform/limits/";
export const TOKEN_URL =
  "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/";

/** The `range` query parameter, defaulting to 24h for anything unknown. */
export function rangeFrom(param: string | null | undefined): HealthRange {
  return param === "7d" ? "7d" : "24h";
}

export type CpuState = "unknown" | "ok" | "near" | "over";

/** Compares a CPU time with the limit: over at or above it, near from 80 percent. */
export function cpuState(
  value: number | null | undefined,
  limit: number,
): CpuState {
  if (value === null || value === undefined) {
    return "unknown";
  }
  return value >= limit ? "over" : value >= limit * 0.8 ? "near" : "ok";
}

/** Bar width for an hour relative to the busiest hour; at least 2 percent when non-zero. */
export function barPercent(value: number, max: number): number {
  if (value <= 0 || max <= 0) {
    return 0;
  }
  return Math.max(2, Math.round((value / max) * 100));
}

@Component({
  selector: "cw-instance-admin-health",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule],
  template: `
    <app-header></app-header>
    <bit-container>
      <p bitTypography="body1">{{ "cwHealthDesc" | i18n }}</p>
      @if (error()) {
        <bit-callout type="danger" data-testid="cw-health-error">{{
          error()
        }}</bit-callout>
      }
      @if (setup(); as h) {
        <bit-callout
          type="info"
          [title]="'cwHealthSetupTitle' | i18n"
          data-testid="cw-health-setup"
        >
          {{ "cwHealthSetupDesc" | i18n }}
          <ul class="tw-mb-0 tw-mt-2 tw-list-disc tw-pl-5">
            @for (m of h.missing; track m) {
              <li class="tw-font-mono">{{ m }}</li>
            }
          </ul>
          <a
            bitLink
            [href]="tokenUrl"
            target="_blank"
            rel="noreferrer noopener"
          >
            {{ "cwHealthSetupLink" | i18n }}
          </a>
        </bit-callout>
      } @else if (view(); as h) {
        <div
          class="tw-mb-4 tw-flex tw-flex-wrap tw-gap-2"
          role="group"
          [attr.aria-label]="'cwHealthRange' | i18n"
        >
          @for (r of ranges; track r.value) {
            <button
              type="button"
              bitButton
              [buttonType]="range() === r.value ? 'primary' : 'secondary'"
              [attr.aria-pressed]="range() === r.value"
              (click)="setRange(r.value)"
              [attr.data-testid]="'cw-health-range-' + r.value"
            >
              {{ r.label | i18n }}
            </button>
          }
        </div>

        @if (h.limitFailures.exceededCpu > 0) {
          <bit-callout
            type="danger"
            [title]="'cwHealthCpuWarnTitle' | i18n"
            data-testid="cw-health-cpu-warning"
          >
            {{
              "cwHealthCpuWarn"
                | i18n: h.limitFailures.exceededCpu : h.cpuLimitMs
            }}
            <ul class="tw-mb-0 tw-mt-2 tw-list-disc tw-pl-5">
              <li>{{ "cwHealthCpuOptionPaid" | i18n }}</li>
              <li>{{ "cwHealthCpuOptionKdf" | i18n }}</li>
            </ul>
            <a
              bitLink
              [href]="limitsUrl"
              target="_blank"
              rel="noreferrer noopener"
            >
              {{ "cwHealthLimitsLink" | i18n }}
            </a>
          </bit-callout>
        } @else if (
          h.limitFailures.exceededMemory + h.limitFailures.exceededResources > 0
        ) {
          <bit-callout type="warning" data-testid="cw-health-resource-warning">
            {{ "cwHealthResourceWarn" | i18n }}
          </bit-callout>
        } @else if (h.totals.requests > 0) {
          <bit-callout type="success" data-testid="cw-health-ok">
            {{ "cwHealthNoLimitFailures" | i18n }}
          </bit-callout>
        }

        <div class="tw-mb-6 tw-grid tw-grid-cols-2 tw-gap-4 md:tw-grid-cols-3">
          @for (t of tiles(); track t.id) {
            <div
              class="tw-rounded-lg tw-border tw-border-solid tw-p-4"
              [class.tw-border-secondary-300]="
                t.state !== 'over' && t.state !== 'near'
              "
              [class.tw-border-danger-600]="t.state === 'over'"
              [class.tw-border-warning-600]="t.state === 'near'"
            >
              <div bitTypography="helper" class="tw-text-muted tw-uppercase">
                {{ t.label | i18n }}
              </div>
              <div
                bitTypography="h2"
                class="tw-mb-0"
                [class.tw-text-danger]="t.state === 'over'"
                [attr.data-testid]="'cw-health-' + t.id"
              >
                {{ t.value }}
              </div>
              @if (t.hint) {
                <div bitTypography="helper" class="tw-text-muted">
                  {{ t.hint }}
                </div>
              }
            </div>
          }
        </div>
        <p bitTypography="helper" class="tw-text-muted">
          {{ "cwHealthLimitNote" | i18n: h.cpuLimitMs }}
        </p>

        <div bitTypography="h3" class="tw-mt-4">
          {{ "cwHealthStatuses" | i18n }}
        </div>
        <bit-table class="tw-mb-6">
          <ng-container header>
            <tr>
              <th bitCell>{{ "cwHealthStatus" | i18n }}</th>
              <th bitCell>{{ "cwHealthRequests" | i18n }}</th>
              <th bitCell>{{ "cwHealthErrors" | i18n }}</th>
            </tr>
          </ng-container>
          <ng-template body>
            @for (s of h.statuses; track s.status) {
              <tr bitRow>
                <td bitCell class="tw-font-mono">{{ s.status }}</td>
                <td bitCell>{{ s.requests }}</td>
                <td bitCell>{{ s.errors }}</td>
              </tr>
            }
          </ng-template>
        </bit-table>

        <div bitTypography="h3">{{ "cwHealthPerHour" | i18n }}</div>
        <bit-table data-testid="cw-health-series">
          <ng-container header>
            <tr>
              <th bitCell>{{ "cwHealthHour" | i18n }}</th>
              <th bitCell class="tw-w-1/3">{{ "cwHealthRequests" | i18n }}</th>
              <th bitCell>{{ "cwHealthErrors" | i18n }}</th>
              <th bitCell>{{ "cwHealthCpuFailures" | i18n }}</th>
            </tr>
          </ng-container>
          <ng-template body>
            @for (p of h.series; track p.hour) {
              <tr bitRow>
                <td bitCell>{{ p.hour | date: "short" }}</td>
                <td bitCell>
                  <div class="tw-flex tw-items-center tw-gap-2">
                    <div
                      class="tw-h-2 tw-flex-1 tw-rounded tw-bg-secondary-100"
                    >
                      <div
                        class="tw-h-2 tw-rounded tw-bg-primary-600"
                        [style.width.%]="percent(p.requests)"
                      ></div>
                    </div>
                    <span class="tw-w-12 tw-text-right">{{ p.requests }}</span>
                  </div>
                </td>
                <td bitCell>{{ p.errors }}</td>
                <td bitCell [class.tw-text-danger]="p.exceededCpu > 0">
                  {{ p.exceededCpu }}
                </td>
              </tr>
            }
          </ng-template>
        </bit-table>
        <p bitTypography="helper" class="tw-mt-2 tw-text-muted">
          {{ "cwHealthFresh" | i18n }}
        </p>
      } @else if (!error()) {
        <i class="bwi bwi-spinner bwi-spin" aria-hidden="true"></i>
      }
    </bit-container>
  `,
})
export class InstanceAdminHealthComponent implements OnInit {
  private readonly api = inject(InstanceAdminApiService);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);

  protected readonly limitsUrl = LIMITS_URL;
  protected readonly tokenUrl = TOKEN_URL;
  protected readonly ranges = [
    { value: "24h" as HealthRange, label: "cwHealthRange24h" },
    { value: "7d" as HealthRange, label: "cwHealthRange7d" },
  ];
  protected readonly range = signal<HealthRange>(
    rangeFrom(this.route.snapshot.queryParamMap.get("range")),
  );
  protected readonly data = signal<Health | null>(null);
  protected readonly error = signal<string | null>(null);

  async ngOnInit() {
    await this.load();
  }

  protected async setRange(r: HealthRange) {
    if (r === this.range()) {
      return;
    }
    this.range.set(r);
    await this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { range: r },
      queryParamsHandling: "merge",
      replaceUrl: true,
    });
    await this.load();
  }

  private async load() {
    this.data.set(null);
    this.error.set(null);
    try {
      this.data.set(await this.api.health(this.range()));
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
  }

  protected percent(value: number): number {
    const h = this.view();
    return h
      ? barPercent(value, Math.max(0, ...h.series.map((p) => p.requests)))
      : 0;
  }

  protected readonly setup = computed(() => {
    const h = this.data();
    return h && !h.configured ? (h as HealthNotConfigured) : null;
  });
  protected readonly view = computed(() => {
    const h = this.data();
    return h?.configured ? (h as HealthData) : null;
  });

  protected tiles() {
    const h = this.view();
    return h ? healthTiles(h) : [];
  }
}

const fmt = (v: number | null | undefined) =>
  v === null || v === undefined ? "-" : `${v} ms`;

/** Summary tiles; CPU tiles are coloured against the configured limit. */
export function healthTiles(h: HealthData) {
  const limit = h.cpuLimitMs;
  const cpu = h.cpu;
  return [
    {
      id: "requests",
      label: "cwHealthRequests",
      value: String(h.totals.requests),
      state: "ok" as CpuState,
      hint: "",
    },
    {
      id: "errors",
      label: "cwHealthErrors",
      value: String(h.totals.errors),
      state: "ok" as CpuState,
      hint: "",
    },
    {
      id: "cpu-failures",
      label: "cwHealthCpuFailures",
      value: String(h.limitFailures.exceededCpu),
      state: (h.limitFailures.exceededCpu > 0 ? "over" : "ok") as CpuState,
      hint: "exceededCpu",
    },
    {
      id: "cpu-p50",
      label: "cwHealthCpuP50",
      value: fmt(cpu?.p50),
      state: cpuState(cpu?.p50, limit),
      hint: "",
    },
    {
      id: "cpu-p99",
      label: "cwHealthCpuP99",
      value: fmt(cpu?.p99),
      state: cpuState(cpu?.p99, limit),
      hint: "",
    },
    {
      id: "cpu-max",
      label: "cwHealthCpuMax",
      value: fmt(cpu?.max),
      state: cpuState(cpu?.max, limit),
      hint: "",
    },
  ];
}
