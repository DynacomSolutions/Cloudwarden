// Cloudwarden: the "Show this workspace's QR" panel.
import { NO_ERRORS_SCHEMA } from "@angular/core";
import { TestBed } from "@angular/core/testing";
import { mock } from "jest-mock-extended";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";

import { WorkspaceQrShowComponent } from "./workspace-qr-show.component";

const made: { value: string; level: string }[] = [];
jest.mock(
  "qrious",
  () => ({
    __esModule: true,
    default: class {
      constructor(o: { value: string; level: string }) {
        made.push(o);
      }
    },
  }),
  { virtual: true },
);

const HEX = ["ab12cd34", "ef560123", "456789ab", "cdef0123"]
  .concat(["456789ab", "cdef0123", "456789ab", "cdef0123"])
  .join("");

describe("WorkspaceQrShowComponent", () => {
  beforeEach(() => {
    made.length = 0;
    const i18n = mock<I18nService>();
    i18n.t.mockImplementation((k: string) => k);
    TestBed.configureTestingModule({
      providers: [{ provide: I18nService, useValue: i18n }],
    });
    TestBed.overrideComponent(WorkspaceQrShowComponent, {
      add: { schemas: [NO_ERRORS_SCHEMA] },
    });
  });

  const render = async (fingerprint = HEX) => {
    const f = TestBed.createComponent(WorkspaceQrShowComponent);
    f.componentRef.setInput("domain", "vault.example.com");
    f.componentRef.setInput("fingerprint", fingerprint);
    f.detectChanges();
    return f;
  };
  const q = (f: { nativeElement: HTMLElement }, id: string) =>
    f.nativeElement.querySelector(`[data-testid=${id}]`) as HTMLElement | null;

  it("is collapsed until opened", async () => {
    const f = await render();
    expect(q(f, "cw-qr-canvas")).toBeNull();
    expect(made).toHaveLength(0);
  });

  it("draws the versioned URI and shows the domain and grouped fingerprint", async () => {
    const f = await render();
    q(f, "cw-qr-toggle")!.click();
    f.detectChanges();
    await f.whenStable();
    f.detectChanges();
    await f.whenStable();
    expect(made).toHaveLength(1);
    expect(made[0].value).toBe(
      `cloudwarden-workspace:v1?domain=vault.example.com&fp=${HEX}`,
    );
    expect(made[0].level).toBe("M");
    expect(q(f, "cw-qr-domain")!.textContent).toContain("vault.example.com");
    expect(q(f, "cw-qr-fingerprint")!.textContent).toBe(
      (HEX.toUpperCase().match(/.{4}/g) ?? []).join(":"),
    );
  });

  it("draws nothing for an invalid identity", async () => {
    const f = await render("not-a-fingerprint");
    q(f, "cw-qr-toggle")!.click();
    f.detectChanges();
    await f.whenStable();
    expect(q(f, "cw-qr-canvas")).toBeNull();
    expect(made).toHaveLength(0);
  });
});
