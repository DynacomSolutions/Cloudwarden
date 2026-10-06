// Cloudwarden: "Show this workspace's QR" panel (docs/federation.md, "QR codes for pairing";
// web/NOTICE.md). Renders this instance's identity as a compact URI so another administrator can
// scan it instead of typing the fingerprint, with the domain and grouped fingerprint beneath for a
// visual comparison.
import {
  ChangeDetectionStrategy,
  Component,
  ElementRef,
  computed,
  effect,
  input,
  signal,
  viewChild,
} from "@angular/core";

import { SharedModule } from "../../shared";

import { formatFingerprint } from "./federation-api.service";
import { encodeWorkspaceUri } from "./workspace-qr";

@Component({
  selector: "cw-workspace-qr-show",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule],
  template: `
    <div data-testid="cw-qr-show">
      <button
        type="button"
        bitButton
        buttonType="secondary"
        (click)="open.set(!open())"
        [attr.aria-expanded]="open()"
        data-testid="cw-qr-toggle"
      >
        {{ "cwQrShow" | i18n }}
      </button>
      @if (open()) {
        <div class="tw-mt-3 tw-flex tw-flex-col tw-items-center tw-gap-2">
          @if (uri(); as u) {
            <canvas
              #canvas
              class="tw-max-w-full tw-rounded tw-bg-white tw-p-2"
              width="280"
              height="280"
              role="img"
              [attr.aria-label]="'cwQrShow' | i18n"
              data-testid="cw-qr-canvas"
            ></canvas>
            <p bitTypography="helper" class="tw-text-muted tw-text-center">
              {{ "cwQrShowHelp" | i18n }}
            </p>
            <p bitTypography="body2" data-testid="cw-qr-domain">
              {{ domain() }}
            </p>
            <code
              class="tw-break-all tw-text-center tw-text-sm"
              data-testid="cw-qr-fingerprint"
              >{{ grouped() }}</code
            >
          } @else {
            <p class="tw-text-danger">{{ "cwQrNoIdentity" | i18n }}</p>
          }
          @if (renderError()) {
            <p class="tw-text-danger" data-testid="cw-qr-render-error">
              {{ "cwQrRenderFailed" | i18n }}
            </p>
          }
        </div>
      }
    </div>
  `,
})
export class WorkspaceQrShowComponent {
  readonly domain = input.required<string>();
  readonly fingerprint = input.required<string>();

  protected readonly open = signal(false);
  protected readonly renderError = signal(false);
  protected readonly uri = computed(() =>
    encodeWorkspaceUri(this.domain(), this.fingerprint()),
  );
  protected readonly grouped = computed(() =>
    formatFingerprint(this.fingerprint()),
  );
  private readonly canvas = viewChild<ElementRef<HTMLCanvasElement>>("canvas");

  constructor() {
    effect(() => {
      const el = this.canvas()?.nativeElement;
      const value = this.uri();
      if (el && value) {
        void this.render(el, value);
      }
    });
  }

  private async render(el: HTMLCanvasElement, value: string) {
    try {
      // The QR generator already shipped with the web client (authenticator set-up uses it).
      // @ts-expect-error qrious ships no type declarations
      const mod = await import("qrious");
      const QRious = mod.default ?? mod;
      // Level M and a fixed size: the URI is short, so the code stays low density and easy to scan.
      new QRious({ element: el, value, size: 280, level: "M", padding: 8 });
      this.renderError.set(false);
    } catch {
      this.renderError.set(true);
    }
  }
}
