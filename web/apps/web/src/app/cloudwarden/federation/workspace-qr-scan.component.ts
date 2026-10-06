// Cloudwarden: "Scan QR" control (docs/federation.md, "QR codes for pairing"; web/NOTICE.md). Reads
// a workspace QR from the camera, from a picked or pasted image, or from pasted URI text, validates
// it strictly and emits the domain and fingerprint. It only replaces typing: the parent still has
// the server check the fingerprint against the key it fetches and waits for the user's Approve.
import {
  ChangeDetectionStrategy,
  ChangeDetectorRef,
  Component,
  ElementRef,
  OnDestroy,
  inject,
  output,
  signal,
  viewChild,
} from "@angular/core";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";

import { SharedModule } from "../../shared";

import { decodeQr } from "./qr-decoder";
import {
  WorkspaceUriError,
  parseWorkspaceUri,
  workspaceUriErrorKey,
} from "./workspace-qr";

export interface ScannedWorkspace {
  domain: string;
  fingerprint: string;
}

@Component({
  selector: "cw-workspace-qr-scan",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule],
  template: `
    <div data-testid="cw-qr-scan" class="tw-w-full">
      <div class="tw-flex tw-flex-wrap tw-gap-2">
        <button
          type="button"
          bitButton
          buttonType="secondary"
          (click)="camera() ? stopCamera() : startCamera()"
          data-testid="cw-qr-scan-button"
        >
          {{ (camera() ? "cwQrStopScan" : "cwQrScan") | i18n }}
        </button>
        <button
          type="button"
          bitButton
          buttonType="secondary"
          (click)="picker.click()"
          data-testid="cw-qr-image-button"
        >
          {{ "cwQrImage" | i18n }}
        </button>
        <input
          #picker
          type="file"
          accept="image/*"
          class="tw-hidden"
          (change)="onFile($event)"
          data-testid="cw-qr-file"
        />
      </div>
      @if (camera()) {
        <video
          #video
          class="tw-mt-2 tw-w-full tw-max-w-sm tw-rounded"
          playsinline
          muted
          data-testid="cw-qr-video"
        ></video>
      }
      <label class="tw-mt-2 tw-block tw-text-sm">
        <span class="tw-text-muted">{{ "cwQrPaste" | i18n }}</span>
        <input
          bitInput
          type="text"
          autocomplete="off"
          [spellcheck]="false"
          (paste)="onPaste($event)"
          (change)="onText($any($event.target).value)"
          data-testid="cw-qr-text"
        />
      </label>
      @if (message()) {
        <p
          class="tw-mt-1 tw-text-sm tw-text-danger"
          role="alert"
          data-testid="cw-qr-error"
        >
          {{ message() }}
        </p>
      }
    </div>
  `,
})
export class WorkspaceQrScanComponent implements OnDestroy {
  private readonly i18n = inject(I18nService);
  private readonly cdr = inject(ChangeDetectorRef);

  readonly scanned = output<ScannedWorkspace>();

  protected readonly camera = signal(false);
  protected readonly message = signal<string | null>(null);
  private readonly video = viewChild<ElementRef<HTMLVideoElement>>("video");
  private stream: MediaStream | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;

  ngOnDestroy() {
    this.stopCamera();
  }

  /** Validates the decoded text; on success emits it, otherwise shows why it was refused. */
  handleText(text: string): boolean {
    const r = parseWorkspaceUri(text);
    if (!r.ok) {
      this.message.set(
        this.i18n.t(
          workspaceUriErrorKey((r as { error: WorkspaceUriError }).error),
        ),
      );
      return false;
    }
    this.message.set(null);
    this.scanned.emit({ domain: r.domain, fingerprint: r.fingerprint });
    return true;
  }

  protected onPaste(e: ClipboardEvent) {
    const items = Array.from(e.clipboardData?.items ?? []);
    const image = items.find((i) => i.type.startsWith("image/"));
    if (image) {
      e.preventDefault();
      const file = image.getAsFile();
      if (file) {
        void this.decodeFile(file);
      }
    }
  }

  protected onText(value: string) {
    if (value.trim() !== "") {
      this.handleText(value);
    }
  }

  protected async onFile(e: Event) {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    input.value = "";
    if (file) {
      await this.decodeFile(file);
    }
  }

  private async decodeFile(file: File) {
    const url = URL.createObjectURL(file);
    try {
      const img = new Image();
      img.src = url;
      await img.decode();
      const text = await decodeQr(img);
      if (text === null) {
        this.message.set(this.i18n.t("cwQrNotFound"));
        return;
      }
      this.handleText(text);
    } catch {
      this.message.set(this.i18n.t("cwQrNotFound"));
    } finally {
      URL.revokeObjectURL(url);
    }
  }

  protected async startCamera() {
    this.message.set(null);
    if (!navigator.mediaDevices?.getUserMedia) {
      this.message.set(this.i18n.t("cwQrNoCamera"));
      return;
    }
    try {
      this.stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: "environment" } },
        audio: false,
      });
    } catch {
      this.message.set(this.i18n.t("cwQrCameraDenied"));
      return;
    }
    this.camera.set(true);
    // Render the video element now, so it can be attached to the stream.
    this.cdr.detectChanges();
    const el = this.video()?.nativeElement;
    if (!el) {
      this.stopCamera();
      return;
    }
    el.srcObject = this.stream;
    try {
      await el.play();
    } catch {
      // The tick below keeps trying; autoplay of a muted inline video is normally allowed.
    }
    this.tick();
  }

  private tick() {
    this.timer = setTimeout(async () => {
      const el = this.video()?.nativeElement;
      if (!this.camera() || !el) {
        return;
      }
      const text = el.readyState >= 2 ? await decodeQr(el) : null;
      if (text !== null && this.camera()) {
        // A code that is not ours (a different QR in view) is reported and scanning goes on.
        if (this.handleText(text)) {
          this.stopCamera();
          return;
        }
      }
      this.tick();
    }, 250);
  }

  protected stopCamera() {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.stream?.getTracks().forEach((t) => t.stop());
    this.stream = null;
    this.camera.set(false);
  }
}
