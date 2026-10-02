import { NO_ERRORS_SCHEMA } from "@angular/core";
import { ComponentFixture, TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { mock } from "jest-mock-extended";

import { Utils } from "@bitwarden/common/platform/misc/utils";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { DIALOG_DATA, DialogRef, DialogService, ToastService } from "@bitwarden/components";

import { SmApiService, SmSecretVersion } from "./sm-api.service";
import { SmImportDialogComponent } from "./sm-import-dialog.component";
import { SmSecretVersionsDialogComponent } from "./sm-secret-versions-dialog.component";

const ORG = "00000000-0000-4000-8000-000000000000";
const version = (id: string, value: string, editor: string | null): SmSecretVersion => ({
  id,
  secretId: "s1",
  value,
  versionDate: new Date(0).toISOString(),
  editor,
});

describe("Secrets Manager dialogs", () => {
  let api: ReturnType<typeof mock<SmApiService>>;
  let dialogs: ReturnType<typeof mock<DialogService>>;
  let toast: ReturnType<typeof mock<ToastService>>;
  let ref: ReturnType<typeof mock<DialogRef<boolean>>>;
  let platform: ReturnType<typeof mock<PlatformUtilsService>>;

  async function render<T>(component: new (...a: any[]) => T, data: unknown) {
    TestBed.overrideComponent(component as any, { add: { schemas: [NO_ERRORS_SCHEMA] } });
    TestBed.overrideProvider(DialogService, { useValue: dialogs });
    await TestBed.configureTestingModule({
      imports: [component],
      providers: [
        provideNoopAnimations(),
        { provide: DIALOG_DATA, useValue: data },
        { provide: DialogRef, useValue: ref },
        { provide: SmApiService, useValue: api },
        { provide: DialogService, useValue: dialogs },
        { provide: ToastService, useValue: toast },
        { provide: PlatformUtilsService, useValue: platform },
        { provide: I18nService, useValue: { t: (k: string, ...a: string[]) => [k, ...a].join(" ") } },
      ],
    }).compileComponents();
    return TestBed.createComponent(component);
  }

  async function settle(fixture: ComponentFixture<unknown>) {
    fixture.detectChanges();
    for (let i = 0; i < 5; i++) {
      await new Promise((r) => setTimeout(r));
    }
    fixture.detectChanges();
  }
  const el = (f: ComponentFixture<unknown>) => f.nativeElement as HTMLElement;

  beforeAll(() => {
    // The dialog's scroll shadows observe intersections, which jsdom lacks.
    (globalThis as any).IntersectionObserver ??= class {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  });

  beforeEach(() => {
    api = mock<SmApiService>();
    dialogs = mock<DialogService>();
    toast = mock<ToastService>();
    ref = mock<DialogRef<boolean>>();
    platform = mock<PlatformUtilsService>();
  });

  describe("version history", () => {
    const data = { organizationId: ORG, secretId: "s1", canWrite: true };

    it("lists versions with their editors and hides values until revealed", async () => {
      api.listSecretVersions.mockResolvedValue([
        version("v2", "second", "Ada"),
        version("v1", "first", null),
      ]);
      const fixture = await render(SmSecretVersionsDialogComponent, data);
      await settle(fixture);
      expect(api.listSecretVersions).toHaveBeenCalledWith(ORG, "s1");
      expect(el(fixture).querySelectorAll("[data-testid=cw-sm-version]")).toHaveLength(2);
      expect(el(fixture).textContent).toContain("Ada");
      expect(el(fixture).textContent).toContain("cwSmUnknownEditor");
      expect(el(fixture).textContent).not.toContain("second");
      (fixture.componentInstance as any).toggle("v2");
      fixture.detectChanges();
      expect(el(fixture).textContent).toContain("second");
      expect(el(fixture).textContent).not.toContain("first");
    });

    it("shows an empty state", async () => {
      api.listSecretVersions.mockResolvedValue([]);
      const fixture = await render(SmSecretVersionsDialogComponent, data);
      await settle(fixture);
      expect(el(fixture).querySelector("[data-testid=cw-sm-no-versions]")).not.toBeNull();
    });

    it("restores after confirmation and reports the secret as changed", async () => {
      api.listSecretVersions.mockResolvedValue([version("v1", "first", "Ada")]);
      dialogs.openSimpleDialog.mockResolvedValue(true);
      const fixture = await render(SmSecretVersionsDialogComponent, data);
      await settle(fixture);
      const c = fixture.componentInstance as any;
      await c.restore(version("v1", "first", "Ada"));
      expect(api.restoreSecretVersion).toHaveBeenCalledWith("s1", "v1");
      expect(api.listSecretVersions).toHaveBeenCalledTimes(2);
      expect(c.changed).toBe(true);
      expect(toast.showToast).toHaveBeenCalledWith(expect.objectContaining({ variant: "success" }));
    });

    it("does not restore or delete without confirmation", async () => {
      api.listSecretVersions.mockResolvedValue([version("v1", "first", "Ada")]);
      dialogs.openSimpleDialog.mockResolvedValue(false);
      const fixture = await render(SmSecretVersionsDialogComponent, data);
      await settle(fixture);
      const c = fixture.componentInstance as any;
      await c.restore(version("v1", "first", "Ada"));
      await c.remove(version("v1", "first", "Ada"));
      expect(api.restoreSecretVersion).not.toHaveBeenCalled();
      expect(api.deleteSecretVersions).not.toHaveBeenCalled();
    });

    it("deletes a version after confirmation and reloads", async () => {
      api.listSecretVersions.mockResolvedValue([version("v1", "first", "Ada")]);
      dialogs.openSimpleDialog.mockResolvedValue(true);
      const fixture = await render(SmSecretVersionsDialogComponent, data);
      await settle(fixture);
      await (fixture.componentInstance as any).remove(version("v1", "first", "Ada"));
      expect(api.deleteSecretVersions).toHaveBeenCalledWith(["v1"]);
      expect(api.listSecretVersions).toHaveBeenCalledTimes(2);
    });

    it("offers no restore or delete to read-only users, but still copies", async () => {
      api.listSecretVersions.mockResolvedValue([version("v1", "first", "Ada")]);
      const fixture = await render(SmSecretVersionsDialogComponent, { ...data, canWrite: false });
      await settle(fixture);
      expect(el(fixture).querySelector("[data-testid=cw-sm-version-restore]")).toBeNull();
      expect(el(fixture).querySelector("[data-testid=cw-sm-version-delete]")).toBeNull();
      (fixture.componentInstance as any).copy(version("v1", "first", "Ada"));
      expect(platform.copyToClipboard).toHaveBeenCalledWith("first");
    });

    it("shows load errors as toasts", async () => {
      api.listSecretVersions.mockRejectedValue(new Error("boom"));
      const fixture = await render(SmSecretVersionsDialogComponent, data);
      await settle(fixture);
      expect(toast.showToast).toHaveBeenCalledWith({ variant: "error", message: "boom" });
    });
  });

  describe("import", () => {
    const P1 = Utils.newGuid();
    const good = JSON.stringify({
      projects: [{ id: P1, name: "p" }],
      secrets: [{ id: Utils.newGuid(), key: "k", value: "v", projectIds: [P1] }],
    });

    it("validates the file, shows a summary and imports it", async () => {
      const fixture = await render(SmImportDialogComponent, { organizationId: ORG, admin: true });
      const c = fixture.componentInstance as any;
      c.loadText(good);
      await settle(fixture);
      expect(el(fixture).querySelector("[data-testid=cw-sm-import-summary]")?.textContent).toContain(
        "cwSmImportSummary 1 1",
      );
      await c.run();
      expect(api.importAll).toHaveBeenCalledWith(
        ORG,
        expect.objectContaining({ projects: [{ id: P1, name: "p" }] }),
      );
      expect(ref.close).toHaveBeenCalledWith(true);
    });

    it("lists errors and never imports an invalid file", async () => {
      const fixture = await render(SmImportDialogComponent, { organizationId: ORG, admin: true });
      const c = fixture.componentInstance as any;
      c.loadText("{ nope");
      await settle(fixture);
      expect(el(fixture).querySelector("[data-testid=cw-sm-import-errors]")).not.toBeNull();
      await c.run();
      expect(api.importAll).not.toHaveBeenCalled();
    });

    it("blocks loose secrets for members who are not admins", async () => {
      const fixture = await render(SmImportDialogComponent, { organizationId: ORG, admin: false });
      const c = fixture.componentInstance as any;
      c.loadText(JSON.stringify({ secrets: [{ key: "k", value: "v" }] }));
      await settle(fixture);
      expect(el(fixture).querySelector("[data-testid=cw-sm-import-loose]")).not.toBeNull();
      await c.run();
      expect(api.importAll).not.toHaveBeenCalled();
    });

    it("keeps the dialog open and shows the error when the server refuses", async () => {
      api.importAll.mockRejectedValue(new Error("refused"));
      const fixture = await render(SmImportDialogComponent, { organizationId: ORG, admin: true });
      const c = fixture.componentInstance as any;
      c.loadText(good);
      await c.run();
      expect(ref.close).not.toHaveBeenCalled();
      expect(toast.showToast).toHaveBeenCalledWith({ variant: "error", message: "refused" });
    });
  });
});
