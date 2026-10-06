// Cloudwarden: the "Scan QR" control (decoder and camera mocked).
import { NO_ERRORS_SCHEMA } from "@angular/core";
import { TestBed } from "@angular/core/testing";
import { mock } from "jest-mock-extended";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";

import * as decoder from "./qr-decoder";
import {
  ScannedWorkspace,
  WorkspaceQrScanComponent,
} from "./workspace-qr-scan.component";

const HEX = ["ab12cd34", "ef560123", "456789ab", "cdef0123"]
  .concat(["456789ab", "cdef0123", "456789ab", "cdef0123"])
  .join("");
const URI = `cloudwarden-workspace:v1?domain=vault.example.com&fp=${HEX}`;

describe("WorkspaceQrScanComponent", () => {
  const emitted: ScannedWorkspace[] = [];
  const setup = () => {
    emitted.length = 0;
    const i18n = mock<I18nService>();
    i18n.t.mockImplementation((k: string) => k);
    TestBed.configureTestingModule({
      providers: [{ provide: I18nService, useValue: i18n }],
    });
    TestBed.overrideComponent(WorkspaceQrScanComponent, {
      add: { schemas: [NO_ERRORS_SCHEMA] },
    });
    const f = TestBed.createComponent(WorkspaceQrScanComponent);
    f.componentInstance.scanned.subscribe((s) => emitted.push(s));
    f.detectChanges();
    return f;
  };
  const err = (f: { nativeElement: HTMLElement }) =>
    f.nativeElement
      .querySelector("[data-testid=cw-qr-error]")
      ?.textContent?.trim();

  afterEach(() => {
    jest.restoreAllMocks();
    delete (globalThis as { BarcodeDetector?: unknown }).BarcodeDetector;
    Object.defineProperty(navigator, "mediaDevices", {
      value: undefined,
      configurable: true,
    });
  });

  it("emits the domain and fingerprint of a valid pasted URI", () => {
    const f = setup();
    expect(f.componentInstance.handleText(` ${URI} `)).toBe(true);
    expect(emitted).toEqual([
      { domain: "vault.example.com", fingerprint: HEX },
    ]);
  });

  it("refuses an invalid URI with a message and emits nothing", () => {
    const f = setup();
    expect(f.componentInstance.handleText(URI.replace("v1", "v9"))).toBe(false);
    f.detectChanges();
    expect(emitted).toEqual([]);
    expect(err(f)).toBe("cwQrErr_version");
  });

  it("explains when the browser has no camera", async () => {
    const f = setup();
    f.nativeElement.querySelector("[data-testid=cw-qr-scan-button]").click();
    await f.whenStable();
    f.detectChanges();
    expect(err(f)).toBe("cwQrNoCamera");
  });

  it("explains a refused camera permission", async () => {
    const f = setup();
    Object.defineProperty(navigator, "mediaDevices", {
      value: { getUserMedia: jest.fn().mockRejectedValue(new Error("denied")) },
      configurable: true,
    });
    f.nativeElement.querySelector("[data-testid=cw-qr-scan-button]").click();
    await f.whenStable();
    f.detectChanges();
    expect(err(f)).toBe("cwQrCameraDenied");
  });

  it("asks for the rear camera and decodes frames with the detector", async () => {
    const f = setup();
    const stop = jest.fn();
    const getUserMedia = jest
      .fn()
      .mockResolvedValue({ getTracks: () => [{ stop }] });
    Object.defineProperty(navigator, "mediaDevices", {
      value: { getUserMedia },
      configurable: true,
    });
    jest.spyOn(HTMLMediaElement.prototype, "play").mockResolvedValue();
    Object.defineProperty(HTMLMediaElement.prototype, "readyState", {
      get: () => 4,
      configurable: true,
    });
    const decode = jest.spyOn(decoder, "decodeQr").mockResolvedValue(URI);
    f.nativeElement.querySelector("[data-testid=cw-qr-scan-button]").click();
    for (let i = 0; i < 6; i++) {
      await new Promise((r) => setTimeout(r, 120));
      f.detectChanges();
    }
    expect(getUserMedia.mock.calls[0][0].video.facingMode).toEqual({
      ideal: "environment",
    });
    expect(decode).toHaveBeenCalled();
    expect(emitted).toEqual([
      { domain: "vault.example.com", fingerprint: HEX },
    ]);
    expect(stop).toHaveBeenCalled();
  });

  it("uses the native BarcodeDetector when present", async () => {
    const detect = jest.fn().mockResolvedValue([{ rawValue: URI }]);
    (globalThis as { BarcodeDetector?: unknown }).BarcodeDetector = jest
      .fn()
      .mockImplementation(() => ({ detect }));
    expect(decoder.hasNativeDetector()).toBe(true);
    await expect(
      decoder.decodeQr(document.createElement("video")),
    ).resolves.toBe(URI);
    expect(detect).toHaveBeenCalled();
  });
});
