import { NO_ERRORS_SCHEMA } from "@angular/core";
import { TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { ActivatedRoute, provideRouter } from "@angular/router";
import { mock } from "jest-mock-extended";

import { FileDownloadService } from "@bitwarden/common/platform/abstractions/file-download/file-download.service";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";

import { SmApiService } from "./sm-api.service";
import { SmSecretsPageComponent } from "./sm-secrets.component";

const ORG = "00000000-0000-4000-8000-000000000000";

describe("Secrets Manager export", () => {
  async function render(api: ReturnType<typeof mock<SmApiService>>) {
    const download = mock<FileDownloadService>();
    const toast = mock<ToastService>();
    const dialogs = mock<DialogService>();
    TestBed.overrideComponent(SmSecretsPageComponent, {
      remove: { imports: [HeaderModule] },
      add: { schemas: [NO_ERRORS_SCHEMA] },
    });
    TestBed.overrideProvider(DialogService, { useValue: dialogs });
    await TestBed.configureTestingModule({
      imports: [SmSecretsPageComponent],
      providers: [
        provideRouter([]),
        provideNoopAnimations(),
        { provide: SmApiService, useValue: api },
        { provide: DialogService, useValue: dialogs },
        { provide: ToastService, useValue: toast },
        { provide: FileDownloadService, useValue: download },
        { provide: PlatformUtilsService, useValue: mock<PlatformUtilsService>() },
        { provide: I18nService, useValue: { t: (k: string, ...a: string[]) => [k, ...a].join(" ") } },
        {
          provide: ActivatedRoute,
          useValue: { parent: { snapshot: { paramMap: new Map([["organizationId", ORG]]) } } },
        },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(SmSecretsPageComponent);
    return { fixture, download, toast };
  }

  it("downloads the decrypted export as a JSON file", async () => {
    const api = mock<SmApiService>();
    api.listSecrets.mockResolvedValue([]);
    api.listProjects.mockResolvedValue([]);
    api.isOrgAdmin.mockResolvedValue(true);
    const file = {
      projects: [{ id: "p1", name: "deploy" }],
      secrets: [{ id: "s1", key: "K", value: "V", note: "", projectIds: ["p1"] }],
    };
    api.exportAll.mockResolvedValue(file);
    const { fixture, download, toast } = await render(api);
    await (fixture.componentInstance as any).exportFile();
    expect(api.exportAll).toHaveBeenCalledWith(ORG);
    const call = download.download.mock.calls[0][0];
    expect(call.fileName).toMatch(/^secrets-manager-export-\d{4}-\d{2}-\d{2}\.json$/);
    expect(JSON.parse(call.blobData as string)).toEqual(file);
    expect(toast.showToast).toHaveBeenCalledWith(expect.objectContaining({ variant: "success" }));
  });

  it("toasts the error and downloads nothing when decryption fails", async () => {
    const api = mock<SmApiService>();
    api.exportAll.mockRejectedValue(new Error("could not be decrypted"));
    const { fixture, download, toast } = await render(api);
    await (fixture.componentInstance as any).exportFile();
    expect(download.download).not.toHaveBeenCalled();
    expect(toast.showToast).toHaveBeenCalledWith({
      variant: "error",
      message: "could not be decrypted",
    });
  });
});
