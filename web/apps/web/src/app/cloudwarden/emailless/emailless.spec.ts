import { NO_ERRORS_SCHEMA } from "@angular/core";
import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { ActivatedRoute, Router, provideRouter } from "@angular/router";
import { mock } from "jest-mock-extended";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { InstanceAdminApiService } from "../instance-admin/instance-admin-api.service";
import { InstanceAdminInvitationsComponent } from "../instance-admin/instance-admin-invitations.component";
import { emailStateKey } from "../instance-admin/instance-admin-overview.component";

import { EmailStatusService } from "./email-status.service";
import { InstanceSetupApiService } from "./instance-setup-api.service";
import { InstanceSetupComponent, finishSignupParams } from "./instance-setup.component";

describe("EmailStatusService", () => {
  const service = (response: unknown) => {
    const api = mock<ApiService>();
    if (response instanceof Error) {
      api.send.mockRejectedValue(response);
    } else {
      api.send.mockResolvedValue(response);
    }
    TestBed.configureTestingModule({ providers: [{ provide: ApiService, useValue: api }] });
    return { svc: TestBed.inject(EmailStatusService), api };
  };

  it("reports mail off only when the server says so", async () => {
    const off = service({ cloudwarden: { email: { configured: false, features: [] } } });
    expect(await off.svc.configured()).toBe(false);
    expect(off.api.send).toHaveBeenCalledWith("GET", "/config", null, false, true);
  });

  it("keeps the upstream behaviour when the answer is missing or the call fails", async () => {
    TestBed.resetTestingModule();
    expect(await service({}).svc.configured()).toBe(true);
    TestBed.resetTestingModule();
    expect(await service(new Error("offline")).svc.configured()).toBe(true);
    TestBed.resetTestingModule();
    expect(await service({ cloudwarden: { email: { configured: true } } }).svc.configured()).toBe(
      true,
    );
  });

  it("asks once", async () => {
    TestBed.resetTestingModule();
    const { svc, api } = service({ cloudwarden: { email: { configured: false, features: [] } } });
    await svc.configured();
    await svc.status();
    expect(api.send).toHaveBeenCalledTimes(1);
  });
});

describe("helpers", () => {
  it("hands the redeemed token to the standard finish sign up page", () => {
    expect(finishSignupParams("a@example.com", "tok")).toEqual({
      queryParams: { token: "tok", email: "a@example.com" },
    });
  });

  it("names what a feature does without email", () => {
    expect(emailStateKey("link")).toBe("cwEmailStateLink");
    expect(emailStateKey("refused")).toBe("cwEmailStateRefused");
    expect(emailStateKey("skipped")).toBe("cwEmailStateSkipped");
    expect(emailStateKey("manual")).toBe("cwEmailStateManual");
    expect(emailStateKey("available")).toBe("cwEmailStateAvailable");
  });
});

describe("InstanceSetupComponent", () => {
  const setup = async (query: Record<string, string>) => {
    const api = mock<InstanceSetupApiService>();
    TestBed.overrideComponent(InstanceSetupComponent, { add: { schemas: [NO_ERRORS_SCHEMA] } });
    await TestBed.configureTestingModule({
      imports: [InstanceSetupComponent],
      providers: [
        provideRouter([]),
        provideNoopAnimations(),
        { provide: InstanceSetupApiService, useValue: api },
        { provide: I18nService, useValue: { t: (k: string) => k } },
        { provide: ActivatedRoute, useValue: { snapshot: { queryParams: query } } },
      ],
    }).compileComponents();
    const navigate = jest.spyOn(TestBed.inject(Router), "navigate").mockResolvedValue(true);
    const fixture = TestBed.createComponent(InstanceSetupComponent);
    fixture.detectChanges();
    return { api, navigate, fixture, component: fixture.componentInstance as any };
  };

  it("prefills the address and code from an invite link", async () => {
    const { component } = await setup({ email: "guest@example.com", code: "abc" });
    expect(component.form.value).toEqual({ email: "guest@example.com", code: "abc" });
  });

  it("removes the code from the URL after reading it, and leaves a bare page alone", async () => {
    const withCode = await setup({ email: "guest@example.com", code: "abc" });
    expect(withCode.navigate).toHaveBeenCalledWith(
      [],
      expect.objectContaining({ queryParams: {}, replaceUrl: true }),
    );
    TestBed.resetTestingModule();
    const bare = await setup({});
    expect(bare.navigate).not.toHaveBeenCalled();
  });

  it("redeems the code and continues to the standard registration", async () => {
    const { api, navigate, component } = await setup({});
    api.redeem.mockResolvedValue("reg-token");
    component.form.setValue({ email: "ADMIN@example.com", code: "s3cret" });
    await component.submit();
    expect(api.redeem).toHaveBeenCalledWith("admin@example.com", "s3cret");
    expect(navigate).toHaveBeenCalledWith(["/finish-signup"], {
      queryParams: { token: "reg-token", email: "admin@example.com" },
    });
  });

  it("shows the server's refusal and stays on the page", async () => {
    const { api, navigate, component } = await setup({});
    api.redeem.mockRejectedValue(new Error("The code is not valid, or it has already been used."));
    component.form.setValue({ email: "admin@example.com", code: "wrong" });
    await component.submit();
    expect(component.error()).toContain("not valid");
    expect(navigate).not.toHaveBeenCalled();
  });

  it("does not call the server for an incomplete form", async () => {
    const { api, component } = await setup({});
    component.form.setValue({ email: "not-an-address", code: "" });
    await component.submit();
    expect(api.redeem).not.toHaveBeenCalled();
  });
});

describe("InstanceSetupApiService", () => {
  it("posts unauthenticated and returns the token", async () => {
    const api = mock<ApiService>();
    api.send.mockResolvedValue({ emailVerificationToken: "t" });
    TestBed.configureTestingModule({ providers: [{ provide: ApiService, useValue: api }] });
    expect(await TestBed.inject(InstanceSetupApiService).redeem("a@example.com", "c")).toBe("t");
    expect(api.send).toHaveBeenCalledWith(
      "POST",
      "/cloudwarden/registration/redeem",
      { email: "a@example.com", code: "c" },
      false,
      true,
    );
    api.send.mockResolvedValue({});
    await expect(TestBed.inject(InstanceSetupApiService).redeem("a@example.com", "c")).rejects.toThrow();
  });
});

describe("instance invitations without email", () => {
  it("shows the link once and copies it", async () => {
    const admin = mock<InstanceAdminApiService>();
    admin.overview.mockResolvedValue({
      counts: {},
      email: { configured: false, features: [] },
    });
    admin.invitations.mockResolvedValue({ data: [] });
    admin.invite.mockResolvedValue({
      email: "guest@example.com",
      createdAt: null,
      emailStatus: "not-configured",
      link: "https://vault.example.com/#/instance-setup?email=guest-example&code=abc",
      codeExpiresAt: "2026-10-11",
    });
    const platform = mock<PlatformUtilsService>();
    TestBed.overrideComponent(InstanceAdminInvitationsComponent, {
      remove: { imports: [HeaderModule] },
      add: { schemas: [NO_ERRORS_SCHEMA] },
    });
    await TestBed.configureTestingModule({
      imports: [InstanceAdminInvitationsComponent],
      providers: [
        provideNoopAnimations(),
        { provide: InstanceAdminApiService, useValue: admin },
        { provide: PlatformUtilsService, useValue: platform },
        { provide: DialogService, useValue: mock<DialogService>() },
        { provide: ToastService, useValue: mock<ToastService>() },
        { provide: I18nService, useValue: { t: (k: string, ...a: string[]) => [k, ...a].join(" ") } },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(InstanceAdminInvitationsComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    const c = fixture.componentInstance as any;
    expect(c.mailOff()).toBe(true);
    c.form.setValue({ email: "guest@example.com" });
    await c.invite();
    fixture.detectChanges();
    expect(c.issued()).toContain("/#/instance-setup?email=");
    expect(fixture.nativeElement.querySelector("[data-testid=cw-invite-link]")).not.toBeNull();
    c.copy(c.issued());
    expect(platform.copyToClipboard).toHaveBeenCalledWith(expect.stringContaining("code=abc"));
  });
});
