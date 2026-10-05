import { NO_ERRORS_SCHEMA } from "@angular/core";
import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { ActivatedRoute, Router, convertToParamMap } from "@angular/router";
import { mock } from "jest-mock-extended";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";

import { HeaderModule } from "../../layouts/header/header.module";

import {
  HealthData,
  InstanceAdminApiService,
} from "./instance-admin-api.service";
import {
  InstanceAdminHealthComponent,
  barPercent,
  cpuState,
  healthTiles,
  rangeFrom,
} from "./instance-admin-health.component";

const at = (day: number, hour: number) =>
  new Date(Date.UTC(2026, 9, day, hour)).toISOString();

const data: HealthData = {
  configured: true,
  range: "24h",
  from: at(4, 0),
  to: at(5, 0),
  generatedAt: at(5, 0),
  cpuLimitMs: 10,
  totals: { requests: 1000, errors: 7, subrequests: 10 },
  statuses: [{ status: "success", requests: 993, errors: 0 }],
  limitFailures: { exceededCpu: 0, exceededMemory: 0, exceededResources: 0 },
  cpu: { p50: 2.3, p99: 8.5, p999: 9, max: 12, wallMax: 100 },
  series: [
    { hour: at(4, 10), requests: 100, errors: 0, exceededCpu: 0 },
    { hour: at(4, 11), requests: 50, errors: 7, exceededCpu: 7 },
  ],
};

describe("health helpers", () => {
  it("reads the range and defaults to 24h", () => {
    expect(rangeFrom("7d")).toBe("7d");
    expect(rangeFrom("1y")).toBe("24h");
    expect(rangeFrom(null)).toBe("24h");
  });

  it("compares CPU time with the limit", () => {
    expect(cpuState(null, 10)).toBe("unknown");
    expect(cpuState(7.9, 10)).toBe("ok");
    expect(cpuState(8, 10)).toBe("near");
    expect(cpuState(10, 10)).toBe("over");
  });

  it("sizes bars against the busiest hour", () => {
    expect(barPercent(0, 100)).toBe(0);
    expect(barPercent(50, 100)).toBe(50);
    expect(barPercent(1, 1000)).toBe(2);
  });

  it("builds tiles with CPU state against the limit", () => {
    const t = Object.fromEntries(healthTiles(data).map((x) => [x.id, x]));
    expect(t["cpu-p50"].state).toBe("ok");
    expect(t["cpu-p99"].state).toBe("near");
    expect(t["cpu-max"].state).toBe("over");
    expect(t["cpu-max"].value).toBe("12 ms");
    expect(healthTiles({ ...data, cpu: null })[3].value).toBe("-");
  });
});

describe("InstanceAdminHealthComponent", () => {
  let api: ReturnType<typeof mock<InstanceAdminApiService>>;
  let router: ReturnType<typeof mock<Router>>;

  beforeEach(() => {
    api = mock<InstanceAdminApiService>();
    router = mock<Router>();
    const i18n = mock<I18nService>();
    i18n.t.mockImplementation((k: string) => k);
    TestBed.configureTestingModule({
      providers: [
        provideNoopAnimations(),
        { provide: InstanceAdminApiService, useValue: api },
        { provide: I18nService, useValue: i18n },
        { provide: Router, useValue: router },
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { queryParamMap: convertToParamMap({ range: "7d" }) },
          },
        },
      ],
    });
  });

  async function render() {
    TestBed.overrideComponent(InstanceAdminHealthComponent, {
      remove: { imports: [HeaderModule] },
      add: { schemas: [NO_ERRORS_SCHEMA] },
    });
    const f = TestBed.createComponent(InstanceAdminHealthComponent);
    f.detectChanges();
    await f.whenStable();
    f.detectChanges();
    return f;
  }
  const q = (f: { nativeElement: HTMLElement }, id: string) =>
    f.nativeElement.querySelector(`[data-testid=${id}]`);

  it("shows how to configure instead of an error when not configured", async () => {
    api.health.mockResolvedValue({
      configured: false,
      range: "7d",
      cpuLimitMs: 10,
      missing: ["CF_ANALYTICS_TOKEN"],
    });
    const f = await render();
    expect(q(f, "cw-health-setup")?.textContent).toContain(
      "CF_ANALYTICS_TOKEN",
    );
    expect(q(f, "cw-health-error")).toBeNull();
    expect(api.health).toHaveBeenCalledWith("7d");
  });

  it("warns about CPU limit failures with the options and shows the table", async () => {
    api.health.mockResolvedValue({
      ...data,
      range: "7d",
      limitFailures: { ...data.limitFailures, exceededCpu: 7 },
    });
    const f = await render();
    const warn = q(f, "cw-health-cpu-warning");
    expect(warn?.textContent).toContain("cwHealthCpuOptionPaid");
    expect(warn?.textContent).toContain("cwHealthCpuOptionKdf");
    expect(q(f, "cw-health-cpu-failures")?.textContent).toContain("7");
    expect(
      q(f, "cw-health-series")?.querySelectorAll("tr").length,
    ).toBeGreaterThanOrEqual(3);
    expect(q(f, "cw-health-ok")).toBeNull();
  });

  it("shows the all clear without limit failures and keeps the range in the URL", async () => {
    api.health.mockResolvedValue(data);
    const f = await render();
    expect(q(f, "cw-health-ok")).not.toBeNull();
    expect(q(f, "cw-health-cpu-warning")).toBeNull();
    (q(f, "cw-health-range-24h") as HTMLButtonElement).click();
    await f.whenStable();
    expect(router.navigate).toHaveBeenCalledWith(
      [],
      expect.objectContaining({ queryParams: { range: "24h" } }),
    );
    expect(api.health).toHaveBeenLastCalledWith("24h");
  });

  it("shows an upstream error", async () => {
    api.health.mockRejectedValue(
      new Error("Cloudflare rejected the analytics token"),
    );
    const f = await render();
    expect(q(f, "cw-health-error")?.textContent).toContain("rejected");
  });
});
