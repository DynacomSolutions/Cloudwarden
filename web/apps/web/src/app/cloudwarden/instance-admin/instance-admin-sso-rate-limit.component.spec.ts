import { NO_ERRORS_SCHEMA } from "@angular/core";
import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { mock } from "jest-mock-extended";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";

import { InstanceAdminApiService } from "./instance-admin-api.service";
import { InstanceAdminSsoRateLimitComponent } from "./instance-admin-sso-rate-limit.component";

describe("InstanceAdminSsoRateLimitComponent", () => {
  let api: ReturnType<typeof mock<InstanceAdminApiService>>;
  let toast: ReturnType<typeof mock<ToastService>>;

  beforeEach(() => {
    api = mock<InstanceAdminApiService>();
    toast = mock<ToastService>();
    const i18n = mock<I18nService>();
    i18n.t.mockImplementation((k: string) => k);
    TestBed.configureTestingModule({
      providers: [
        provideNoopAnimations(),
        { provide: InstanceAdminApiService, useValue: api },
        { provide: I18nService, useValue: i18n },
        { provide: ToastService, useValue: toast },
      ],
    });
  });

  async function render() {
    TestBed.overrideComponent(InstanceAdminSsoRateLimitComponent, {
      remove: { imports: [HeaderModule] },
      add: { schemas: [NO_ERRORS_SCHEMA] },
    });
    const f = TestBed.createComponent(InstanceAdminSsoRateLimitComponent);
    f.detectChanges();
    await f.whenStable();
    f.detectChanges();
    return f;
  }

  it("shows the current limit in a bounded number field", async () => {
    api.ssoRateLimit.mockResolvedValue({ ssoRateLimitPerMinute: 20, custom: false });
    const f = await render();
    const input = (f.nativeElement as HTMLElement).querySelector(
      "[data-testid=cw-sso-limit]",
    ) as HTMLInputElement;
    expect(input.type).toBe("number");
    expect(input.value).toBe("20");
    expect(input.min).toBe("5");
    expect(input.max).toBe("1000");
  });

  it("saves the entered number and shows the stored value", async () => {
    api.ssoRateLimit.mockResolvedValue({ ssoRateLimitPerMinute: 20, custom: false });
    api.saveSsoRateLimit.mockResolvedValue({ ssoRateLimitPerMinute: 50, custom: true });
    const f = await render();
    const c = f.componentInstance as any;
    c.form.patchValue({ limit: 50 });
    await c.save();
    expect(api.saveSsoRateLimit).toHaveBeenCalledWith(50);
    expect(c.form.value.limit).toBe(50);
    expect(toast.showToast).toHaveBeenCalled();
  });

  it("is invalid for empty and fractional input and disables Save", async () => {
    api.ssoRateLimit.mockResolvedValue({ ssoRateLimitPerMinute: 20, custom: false });
    const f = await render();
    const c = f.componentInstance as any;
    const save = () =>
      (f.nativeElement as HTMLElement).querySelector(
        "[data-testid=cw-sso-save]",
      ) as HTMLButtonElement;
    for (const bad of [null, 20.5, 4, 1001]) {
      c.form.patchValue({ limit: bad });
      f.detectChanges();
      expect(c.form.invalid).toBe(true);
      expect(save().disabled || save().hasAttribute("aria-disabled")).toBe(true);
    }
    c.form.patchValue({ limit: 20 });
    f.detectChanges();
    expect(c.form.valid).toBe(true);
    expect(save().disabled).toBe(false);
    expect(save().hasAttribute("aria-disabled")).toBe(false);
  });

  it("resets to the default", async () => {
    api.ssoRateLimit.mockResolvedValue({ ssoRateLimitPerMinute: 50, custom: true });
    api.resetSsoRateLimit.mockResolvedValue({ ssoRateLimitPerMinute: 20, custom: false });
    const f = await render();
    const c = f.componentInstance as any;
    await c.reset();
    expect(api.resetSsoRateLimit).toHaveBeenCalled();
    expect(c.form.value.limit).toBe(20);
    expect(c.custom()).toBe(false);
  });
});
