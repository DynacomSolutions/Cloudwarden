import { NO_ERRORS_SCHEMA } from "@angular/core";
import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { ActivatedRoute, provideRouter } from "@angular/router";
import { mock } from "jest-mock-extended";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";

import { EventIntegrationsComponent } from "./event-integrations.component";
import {
  EventIntegration,
  FIELDS,
  OrgIntegrationsApiService,
  parseEventTypes,
  splitValues,
} from "./org-integrations-api.service";
import { ScimSettingsComponent } from "./scim-settings.component";

const ORG = "00000000-0000-4000-8000-000000000000";

describe("integration helpers", () => {
  it("parses event type lists and ranges", () => {
    expect(parseEventTypes("")).toBeNull();
    expect(parseEventTypes("1500, 1100-1102 1100")).toEqual([1100, 1101, 1102, 1500]);
    expect(() => parseEventTypes("12a")).toThrow("12a");
  });

  it("separates settings from secrets and drops blank secrets", () => {
    expect(
      splitValues("splunk", { url: " https://s.example.com ", token: "", index: "", other: "x" }),
    ).toEqual({
      config: { url: "https://s.example.com", index: null, source: null, sourcetype: null },
      secrets: {},
    });
    expect(splitValues("datadog", { site: "datadoghq.eu", apiKey: "k" }).secrets).toEqual({
      apiKey: "k",
    });
  });

  it("marks every token field as secret", () => {
    const secrets = Object.values(FIELDS)
      .flat()
      .filter((f) => f.secret)
      .map((f) => f.key)
      .sort();
    expect(secrets).toEqual(["apiKey", "clientSecret", "headerValue", "token"]);
  });
});

describe("integration pages", () => {
  let api: ReturnType<typeof mock<OrgIntegrationsApiService>>;

  beforeEach(() => {
    api = mock<OrgIntegrationsApiService>();
    const i18n = mock<I18nService>();
    i18n.t.mockImplementation((k: string) => k);
    TestBed.configureTestingModule({
      providers: [
        provideNoopAnimations(),
        provideRouter([]),
        { provide: OrgIntegrationsApiService, useValue: api },
        { provide: I18nService, useValue: i18n },
        { provide: ToastService, useValue: mock<ToastService>() },
        { provide: PlatformUtilsService, useValue: mock<PlatformUtilsService>() },
        {
          provide: ActivatedRoute,
          useValue: {
            snapshot: { pathFromRoot: [{ paramMap: new Map([["organizationId", ORG]]) }] },
          },
        },
      ],
    });
  });

  function render<T>(c: new (...args: any[]) => T) {
    TestBed.overrideComponent(c, {
      remove: { imports: [HeaderModule] },
      add: { schemas: [NO_ERRORS_SCHEMA] },
    });
    TestBed.overrideProvider(DialogService, { useValue: mock<DialogService>() });
    return TestBed.createComponent(c);
  }

  it("lists integrations with their delivery status", async () => {
    const failing: EventIntegration = {
      id: "i1",
      type: "webhook",
      name: "SIEM hook",
      enabled: true,
      config: { url: "https://hooks.example.com" },
      eventTypes: null,
      status: {
        failureCount: 3,
        nextAttemptDate: null,
        lastError: "The webhook receiver answered HTTP 503.",
        lastSuccessDate: null,
      },
    };
    api.list.mockResolvedValue([failing]);
    const f = render(EventIntegrationsComponent);
    f.detectChanges();
    await f.whenStable();
    f.detectChanges();
    expect(api.list).toHaveBeenCalledWith(ORG);
    const text = f.nativeElement.textContent as string;
    expect(text).toContain("SIEM hook");
    expect(text).toContain("HTTP 503");
  });

  it("loads and saves the SCIM settings", async () => {
    const cfg = {
      enabled: false,
      provider: null,
      scimUrl: `https://vault.example.com/scim/v2/${ORG}`,
      hasApiKey: false,
      apiKeyRevisionDate: null,
    };
    api.getScimConfig.mockResolvedValue(cfg);
    api.saveScimConfig.mockResolvedValue({ ...cfg, enabled: true, provider: 1 });
    const f = render(ScimSettingsComponent);
    f.detectChanges();
    await f.whenStable();
    f.detectChanges();
    const url = f.nativeElement.querySelector("[data-testid=cw-scim-url]") as HTMLInputElement;
    expect(url.value).toBe(cfg.scimUrl);
    const c = f.componentInstance as any;
    c.form.setValue({ enabled: true, provider: 1 });
    await c.save();
    expect(api.saveScimConfig).toHaveBeenCalledWith(ORG, true, 1);
  });
});
