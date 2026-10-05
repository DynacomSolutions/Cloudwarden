import { NO_ERRORS_SCHEMA } from "@angular/core";
import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { mock } from "jest-mock-extended";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";

import {
  AdminUser,
  InstanceAdminApiService,
} from "./instance-admin-api.service";
import { InstanceAdminUsersComponent } from "./instance-admin-users.component";

const user = (over: Partial<AdminUser>): AdminUser => ({
  id: "u1",
  email: "user@example.com",
  name: "User",
  createdAt: "2026-01-01",
  lastActive: null,
  itemCount: 0,
  twoFactorProviders: [],
  enabled: true,
  emailVerified: true,
  role: "user",
  self: false,
  ...over,
});

describe("InstanceAdminUsersComponent roles", () => {
  let api: ReturnType<typeof mock<InstanceAdminApiService>>;
  let dialogs: ReturnType<typeof mock<DialogService>>;
  let toasts: ReturnType<typeof mock<ToastService>>;

  beforeEach(() => {
    api = mock<InstanceAdminApiService>();
    dialogs = mock<DialogService>();
    toasts = mock<ToastService>();
    const i18n = mock<I18nService>();
    i18n.t.mockImplementation((k: string) => k);
    TestBed.configureTestingModule({
      providers: [
        provideNoopAnimations(),
        { provide: InstanceAdminApiService, useValue: api },
        { provide: I18nService, useValue: i18n },
        { provide: ToastService, useValue: toasts },
        { provide: DialogService, useValue: dialogs },
      ],
    });
  });

  async function render(users: AdminUser[]) {
    api.users.mockResolvedValue({
      data: users,
      page: 1,
      pageSize: 50,
      total: users.length,
      hasMore: false,
    });
    TestBed.overrideComponent(InstanceAdminUsersComponent, {
      remove: { imports: [HeaderModule] },
      add: {
        schemas: [NO_ERRORS_SCHEMA],
        providers: [
          { provide: DialogService, useValue: dialogs },
          { provide: ToastService, useValue: toasts },
        ],
      },
    });
    const f = TestBed.createComponent(InstanceAdminUsersComponent);
    f.detectChanges();
    await f.whenStable();
    f.detectChanges();
    return f;
  }

  const rows = (f: { nativeElement: HTMLElement }) =>
    Array.from(f.nativeElement.querySelectorAll("[data-testid=cw-user-row]"));

  it("shows a role badge per user and locks owner and own rows with a tooltip", async () => {
    const f = await render([
      user({ id: "o", email: "o@example.com", role: "owner" }),
      user({ id: "a", email: "a@example.com", role: "admin" }),
      user({ id: "u", email: "u@example.com", role: "user" }),
      user({ id: "s", email: "s@example.com", role: "admin", self: true }),
    ]);
    const r = rows(f);
    expect(r.length).toBe(4);
    const role = (i: number) =>
      r[i].querySelector("[data-testid=cw-user-role]") as HTMLElement;
    expect(role(0).textContent).toContain("cwRoleOwner");
    expect(role(1).textContent).toContain("cwRoleAdmin");
    expect(role(2).textContent).toContain("cwRoleUser");
    // Owner: locked, tooltip explains ADMIN_EMAILS.
    expect(
      role(0).querySelector("[data-testid=cw-role-locked]"),
    ).not.toBeNull();
    expect(role(0).querySelector("[data-testid=cw-role-trigger]")).toBeNull();
    expect(role(0).querySelector("[title=cwRoleOwnerTip]")).not.toBeNull();
    // Admin and user rows can be changed.
    expect(
      role(1).querySelector("[data-testid=cw-role-trigger]"),
    ).not.toBeNull();
    expect(
      role(2).querySelector("[data-testid=cw-role-trigger]"),
    ).not.toBeNull();
    // Own row is locked with its own tooltip.
    expect(
      role(3).querySelector("[data-testid=cw-role-locked]"),
    ).not.toBeNull();
    expect(role(3).querySelector("[title=cwRoleSelfTip]")).not.toBeNull();
  });

  it("confirms, then sets the role and reloads", async () => {
    const target = user({ id: "u", email: "u@example.com", role: "user" });
    const f = await render([target]);
    dialogs.openSimpleDialog.mockResolvedValue(true);
    api.setUserRole.mockResolvedValue(undefined);
    await (f.componentInstance as any).changeRole(target, "admin");
    expect(dialogs.openSimpleDialog).toHaveBeenCalledTimes(1);
    expect(api.setUserRole).toHaveBeenCalledWith("u", "admin");
    expect(api.users).toHaveBeenCalledTimes(2);
    expect(toasts.showToast).toHaveBeenCalledWith(
      expect.objectContaining({ variant: "success", message: "cwRoleChanged" }),
    );
  });

  it("does nothing when the confirmation is declined", async () => {
    const target = user({ role: "admin" });
    const f = await render([target]);
    dialogs.openSimpleDialog.mockResolvedValue(false);
    await (f.componentInstance as any).changeRole(target, "user");
    expect(api.setUserRole).not.toHaveBeenCalled();
  });

  it("never sends a change for an owner, your own row or an unchanged role", async () => {
    const owner = user({ id: "o", role: "owner" });
    const self = user({ id: "s", role: "admin", self: true });
    const same = user({ id: "x", role: "user" });
    const f = await render([owner, self, same]);
    dialogs.openSimpleDialog.mockResolvedValue(true);
    const c = f.componentInstance as any;
    await c.changeRole(owner, "user");
    await c.changeRole(self, "user");
    await c.changeRole(same, "user");
    expect(dialogs.openSimpleDialog).not.toHaveBeenCalled();
    expect(api.setUserRole).not.toHaveBeenCalled();
  });

  it("shows the server's refusal as an error toast", async () => {
    const target = user({ id: "u", role: "user" });
    const f = await render([target]);
    dialogs.openSimpleDialog.mockResolvedValue(true);
    api.setUserRole.mockRejectedValue(
      new Error(
        "Only a user with a verified email address can be made an admin.",
      ),
    );
    await (f.componentInstance as any).changeRole(target, "admin");
    expect(toasts.showToast).toHaveBeenCalledWith(
      expect.objectContaining({
        variant: "error",
        message: expect.stringContaining("verified"),
      }),
    );
  });
});
