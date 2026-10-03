import { NO_ERRORS_SCHEMA } from "@angular/core";
import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { mock } from "jest-mock-extended";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";

import { InstanceAdminApiService, PushSettings } from "./instance-admin-api.service";
import {
  HOST_URL,
  InstanceAdminPushComponent,
  buildPushInput,
  testErrorKey,
} from "./instance-admin-push.component";

const base: PushSettings = {
  installationId: "",
  keySet: false,
  keyUnreadable: false,
  region: "us",
  relayUri: null,
  identityUri: null,
  updatedAt: null,
  status: {
    configured: false,
    state: "not configured",
    source: null,
    envOverride: false,
    relayHost: null,
    identityHost: null,
    lastResult: null,
  },
};

describe("push settings helpers", () => {
  it("leaves a blank key out so the server keeps the stored one", () => {
    expect(buildPushInput({ installationId: " id-1 ", installationKey: "  ", region: "eu" })).toEqual(
      { installationId: "id-1", region: "eu" },
    );
    expect(
      buildPushInput({ installationId: "id-1", installationKey: " k ", region: "us" }),
    ).toEqual({ installationId: "id-1", installationKey: "k", region: "us" });
  });

  it("sends custom addresses only for the custom region", () => {
    const v = {
      installationId: "i",
      region: "custom" as const,
      relayUri: " https://push.example.com ",
      identityUri: "https://id.example.com",
    };
    expect(buildPushInput(v)).toEqual({
      installationId: "i",
      region: "custom",
      relayUri: "https://push.example.com",
      identityUri: "https://id.example.com",
    });
    expect(buildPushInput({ ...v, region: "us" }).relayUri).toBeUndefined();
  });

  it("maps test error classes to messages and links to the host page", () => {
    expect(testErrorKey("rejected")).toBe("cwPushErrRejected");
    expect(testErrorKey("unreachable")).toBe("cwPushErrUnreachable");
    expect(testErrorKey("something-else")).toBe("cwPushErrBadResponse");
    expect(HOST_URL).toBe("https://bitwarden.com/host");
  });
});

describe("InstanceAdminPushComponent", () => {
  let api: ReturnType<typeof mock<InstanceAdminApiService>>;
  let dialogs: ReturnType<typeof mock<DialogService>>;

  beforeEach(() => {
    api = mock<InstanceAdminApiService>();
    dialogs = mock<DialogService>();
    const i18n = mock<I18nService>();
    i18n.t.mockImplementation((k: string) => k);
    TestBed.configureTestingModule({
      providers: [
        provideNoopAnimations(),
        { provide: InstanceAdminApiService, useValue: api },
        { provide: I18nService, useValue: i18n },
        { provide: ToastService, useValue: mock<ToastService>() },
        { provide: DialogService, useValue: dialogs },
      ],
    });
  });

  async function render() {
    TestBed.overrideComponent(InstanceAdminPushComponent, {
      remove: { imports: [HeaderModule] },
      add: {
        schemas: [NO_ERRORS_SCHEMA],
        providers: [{ provide: DialogService, useValue: dialogs }],
      },
    });
    const f = TestBed.createComponent(InstanceAdminPushComponent);
    f.detectChanges();
    await f.whenStable();
    f.detectChanges();
    return f;
  }

  it("shows the status panel and the env override notice", async () => {
    api.pushSettings.mockResolvedValue({
      ...base,
      installationId: "id-1",
      keySet: true,
      status: {
        ...base.status,
        configured: true,
        state: "configured",
        source: "env",
        envOverride: true,
        relayHost: "push.bitwarden.com",
        lastResult: { at: "2026-01-01", ok: true, status: 200 },
      },
    });
    const f = await render();
    const el = f.nativeElement as HTMLElement;
    expect(el.querySelector("[data-testid=cw-push-env-notice]")).not.toBeNull();
    expect(el.querySelector("[data-testid=cw-push-state]")?.textContent).toContain(
      "cwPushStatusConfigured",
    );
    expect(el.querySelector("[data-testid=cw-push-source]")?.textContent).toContain(
      "cwPushSourceEnv",
    );
    const key = el.querySelector("[data-testid=cw-push-key]") as HTMLInputElement;
    expect(key.type).toBe("password");
    expect(key.value).toBe("");
    expect(el.querySelector("a")?.getAttribute("href")).toBe(HOST_URL);
  });

  it("saves without sending a blank key, then clears the key field", async () => {
    api.pushSettings.mockResolvedValue({ ...base, installationId: "id-1", keySet: true });
    api.savePushSettings.mockResolvedValue({ ...base, installationId: "id-2", keySet: true });
    const f = await render();
    const c = f.componentInstance as any;
    c.form.patchValue({ installationId: "id-2", region: "eu" });
    await c.save();
    expect(api.savePushSettings).toHaveBeenCalledWith({ installationId: "id-2", region: "eu" });
    expect(c.form.value.installationKey).toBe("");
  });

  it("shows web push state and switches it", async () => {
    api.pushSettings.mockResolvedValue(base);
    api.webPush.mockResolvedValue({
      enabled: true,
      available: true,
      publicKey: "k",
      subscriptions: 3,
    });
    api.setWebPush.mockResolvedValue({
      enabled: false,
      available: true,
      publicKey: "k",
      subscriptions: 3,
    });
    const f = await render();
    const el = f.nativeElement as HTMLElement;
    expect(el.querySelector("[data-testid=cw-webpush-state]")?.textContent).toContain(
      "cwWebPushOn",
    );
    expect(el.querySelector("[data-testid=cw-webpush-count]")?.textContent).toContain("3");
    (el.querySelector("[data-testid=cw-webpush-toggle]") as HTMLButtonElement).click();
    await f.whenStable();
    f.detectChanges();
    expect(api.setWebPush).toHaveBeenCalledWith(false);
    expect(el.querySelector("[data-testid=cw-webpush-state]")?.textContent).toContain(
      "cwWebPushOff",
    );
  });

  it("disables the switch when the stored key cannot be opened", async () => {
    api.pushSettings.mockResolvedValue(base);
    api.webPush.mockResolvedValue({
      enabled: false,
      available: false,
      publicKey: null,
      subscriptions: 0,
    });
    const f = await render();
    const el = f.nativeElement as HTMLElement;
    expect(el.querySelector("[data-testid=cw-webpush-unavailable]")).not.toBeNull();
    expect(el.querySelector("[data-testid=cw-webpush-state]")?.textContent).toContain(
      "cwWebPushOff",
    );
  });

  it("tests the connection and removes after confirmation", async () => {
    const settings = { ...base, keySet: true, status: { ...base.status, configured: true } };
    api.pushSettings.mockResolvedValue(settings);
    api.testPushSettings.mockResolvedValue({ ok: false, error: "rejected" });
    api.removePushSettings.mockResolvedValue(base);
    const f = await render();
    const c = f.componentInstance as any;
    await c.test();
    expect(api.testPushSettings).toHaveBeenCalled();
    dialogs.openSimpleDialog.mockResolvedValue(true);
    await c.remove();
    expect(api.removePushSettings).toHaveBeenCalled();
    expect(c.settings().keySet).toBe(false);
  });
});
