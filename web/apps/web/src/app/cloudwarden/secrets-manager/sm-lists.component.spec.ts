import { NO_ERRORS_SCHEMA, Type } from "@angular/core";
import { ComponentFixture, TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { ActivatedRoute, provideRouter } from "@angular/router";
import { mock } from "jest-mock-extended";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";

import { SmApiService, SmMachineAccount, SmProject, SmSecretListItem } from "./sm-api.service";
import { SmMachineAccountsComponent } from "./sm-machine-accounts.component";
import { SmProjectsComponent } from "./sm-projects.component";
import { SmSecretsListComponent } from "./sm-secrets.component";

const ORG = "00000000-0000-4000-8000-000000000000";

const project = (id: string, name: string, write = true): SmProject => ({
  id,
  name,
  creationDate: "2026-01-01",
  revisionDate: "2026-01-02",
  read: true,
  write,
});

describe("Secrets Manager lists", () => {
  let api: ReturnType<typeof mock<SmApiService>>;
  let dialogs: ReturnType<typeof mock<DialogService>>;
  let toast: ReturnType<typeof mock<ToastService>>;

  async function render<T>(component: Type<T>): Promise<ComponentFixture<T>> {
    TestBed.overrideComponent(component, {
      remove: { imports: [HeaderModule] },
      add: { schemas: [NO_ERRORS_SCHEMA] },
    });
    // DialogModule (via SharedModule) provides its own DialogService; replace it everywhere.
    TestBed.overrideProvider(DialogService, { useValue: dialogs });
    await TestBed.configureTestingModule({
      imports: [component],
      providers: [
        provideRouter([]),
        provideNoopAnimations(),
        { provide: SmApiService, useValue: api },
        { provide: DialogService, useValue: dialogs },
        { provide: ToastService, useValue: toast },
        {
          provide: PlatformUtilsService,
          useValue: mock<PlatformUtilsService>(),
        },
        {
          provide: I18nService,
          useValue: { t: (k: string, ...a: string[]) => [k, ...a].join(" ") },
        },
        {
          provide: ActivatedRoute,
          useValue: {
            parent: {
              snapshot: { paramMap: new Map([["organizationId", ORG]]) },
            },
          },
        },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(component);
    return fixture;
  }

  async function settle(fixture: ComponentFixture<unknown>) {
    fixture.detectChanges();
    for (let i = 0; i < 5; i++) {
      await new Promise((r) => setTimeout(r));
    }
    fixture.detectChanges();
  }

  const text = (fixture: ComponentFixture<unknown>) =>
    (fixture.nativeElement as HTMLElement).textContent ?? "";

  beforeEach(() => {
    api = mock<SmApiService>();
    dialogs = mock<DialogService>();
    toast = mock<ToastService>();
  });

  describe("projects", () => {
    it("shows the empty state with no projects", async () => {
      api.listProjects.mockResolvedValue([]);
      const fixture = await render(SmProjectsComponent);
      await settle(fixture);
      expect(api.listProjects).toHaveBeenCalledWith(ORG);
      expect(fixture.nativeElement.querySelector("[data-testid=cw-sm-empty]")).not.toBeNull();
      expect(text(fixture)).toContain("cwSmNoProjects");
    });

    it("lists decrypted project names", async () => {
      api.listProjects.mockResolvedValue([project("p1", "deploy"), project("p2", "web")]);
      const fixture = await render(SmProjectsComponent);
      await settle(fixture);
      expect(text(fixture)).toContain("deploy");
      expect(text(fixture)).toContain("web");
      expect(fixture.nativeElement.querySelector("[data-testid=cw-sm-empty]")).toBeNull();
    });

    it("bulk deletes after confirmation and reports the result", async () => {
      api.listProjects.mockResolvedValue([project("p1", "deploy"), project("p2", "web")]);
      api.deleteProjects.mockResolvedValue([
        { id: "p1", error: null },
        { id: "p2", error: null },
      ]);
      dialogs.openSimpleDialog.mockResolvedValue(true);
      const fixture = await render(SmProjectsComponent);
      await settle(fixture);
      const c = fixture.componentInstance as any;
      c.selection.toggleAll([{ id: "p1" }, { id: "p2" }]);
      await c.removeSelected();
      expect(dialogs.openSimpleDialog).toHaveBeenCalled();
      expect(api.deleteProjects).toHaveBeenCalledWith(["p1", "p2"]);
      expect(toast.showToast).toHaveBeenCalledWith(expect.objectContaining({ variant: "success" }));
    });

    it("does nothing when the deletion is not confirmed", async () => {
      api.listProjects.mockResolvedValue([project("p1", "deploy")]);
      dialogs.openSimpleDialog.mockResolvedValue(false);
      const fixture = await render(SmProjectsComponent);
      await settle(fixture);
      await (fixture.componentInstance as any).remove(["p1"]);
      expect(api.deleteProjects).not.toHaveBeenCalled();
    });

    it("shows errors as toasts", async () => {
      api.listProjects.mockRejectedValue(new Error("boom"));
      const fixture = await render(SmProjectsComponent);
      await settle(fixture);
      expect(toast.showToast).toHaveBeenCalledWith({
        variant: "error",
        message: "boom",
      });
    });
  });

  describe("secrets", () => {
    const secret = (id: string, key: string, projectId: string | null): SmSecretListItem => ({
      id,
      key,
      projectId,
      projectName: projectId ? "deploy" : null,
      revisionDate: "2026-01-02",
      read: true,
      write: true,
    });

    it("lists secrets with their project for the organisation", async () => {
      api.listSecrets.mockResolvedValue([
        secret("s1", "DATABASE_URL", "p1"),
        secret("s2", "LOOSE", null),
      ]);
      api.listProjects.mockResolvedValue([project("p1", "deploy")]);
      api.isOrgAdmin.mockResolvedValue(true);
      const fixture = await render(SmSecretsListComponent);
      fixture.componentRef.setInput("organizationId", ORG);
      await settle(fixture);
      expect(api.listSecrets).toHaveBeenCalledWith(ORG, undefined);
      expect(text(fixture)).toContain("DATABASE_URL");
      expect(text(fixture)).toContain("deploy");
      expect(text(fixture)).toContain("cwSmNoProject");
    });

    it("lists only one project's secrets when given a project", async () => {
      api.listSecrets.mockResolvedValue([]);
      api.listProjects.mockResolvedValue([]);
      api.isOrgAdmin.mockResolvedValue(false);
      const fixture = await render(SmSecretsListComponent);
      fixture.componentRef.setInput("organizationId", ORG);
      fixture.componentRef.setInput("projectId", "p1");
      await settle(fixture);
      expect(api.listSecrets).toHaveBeenCalledWith(ORG, "p1");
      expect(text(fixture)).toContain("cwSmNoSecrets");
    });

    it("bulk deletes selected secrets and reports partial failures", async () => {
      api.listSecrets.mockResolvedValue([secret("s1", "A", null), secret("s2", "B", null)]);
      api.listProjects.mockResolvedValue([]);
      api.isOrgAdmin.mockResolvedValue(true);
      api.deleteSecrets.mockResolvedValue([
        { id: "s1", error: null },
        { id: "s2", error: "access denied" },
      ]);
      dialogs.openSimpleDialog.mockResolvedValue(true);
      const fixture = await render(SmSecretsListComponent);
      fixture.componentRef.setInput("organizationId", ORG);
      await settle(fixture);
      const c = fixture.componentInstance as any;
      c.selection.toggle("s1");
      c.selection.toggle("s2");
      await c.removeSelected();
      expect(api.deleteSecrets).toHaveBeenCalledWith(["s1", "s2"]);
      expect(toast.showToast).toHaveBeenCalledWith({
        variant: "error",
        message: "cwSmBulkPartial 1 1",
      });
    });

    it("refuses to create a secret without a writable project for non-admins", async () => {
      api.listSecrets.mockResolvedValue([]);
      api.listProjects.mockResolvedValue([project("p1", "deploy", false)]);
      api.isOrgAdmin.mockResolvedValue(false);
      const fixture = await render(SmSecretsListComponent);
      fixture.componentRef.setInput("organizationId", ORG);
      await settle(fixture);
      await (fixture.componentInstance as any).create();
      expect(dialogs.open).not.toHaveBeenCalled();
      expect(toast.showToast).toHaveBeenCalledWith(expect.objectContaining({ variant: "error" }));
    });
  });

  describe("machine accounts", () => {
    const account = (id: string, name: string): SmMachineAccount => ({
      id,
      name,
      creationDate: "2026-01-01",
      revisionDate: "2026-01-02",
      accessToSecrets: 2,
    });

    it("shows the empty state", async () => {
      api.listMachineAccounts.mockResolvedValue([]);
      const fixture = await render(SmMachineAccountsComponent);
      await settle(fixture);
      expect(text(fixture)).toContain("cwSmNoMachineAccounts");
    });

    it("lists machine accounts and deletes them in bulk", async () => {
      api.listMachineAccounts.mockResolvedValue([account("m1", "ci machine")]);
      api.deleteMachineAccounts.mockResolvedValue([{ id: "m1", error: null }]);
      dialogs.openSimpleDialog.mockResolvedValue(true);
      const fixture = await render(SmMachineAccountsComponent);
      await settle(fixture);
      expect(text(fixture)).toContain("ci machine");
      await (fixture.componentInstance as any).remove(["m1"]);
      expect(api.deleteMachineAccounts).toHaveBeenCalledWith(["m1"]);
    });
  });
});
