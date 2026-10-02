// Cloudwarden: Instance admin > Mobile push (web/NOTICE.md, docs/push-notifications.md).
// Manages the Bitwarden push relay credentials stored by the server. The key is write only.
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { FormBuilder } from "@angular/forms";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import {
  InstanceAdminApiService,
  PushRegion,
  PushSettings,
  PushSettingsInput,
} from "./instance-admin-api.service";

export const HOST_URL = "https://bitwarden.com/host";

/** Maps a test error class from the server to a message key. */
export function testErrorKey(error: string | null): string {
  switch (error) {
    case "not_configured":
      return "cwPushErrNotConfigured";
    case "rejected":
      return "cwPushErrRejected";
    case "unreachable":
      return "cwPushErrUnreachable";
    default:
      return "cwPushErrBadResponse";
  }
}

/** Builds the save request. A blank key is left out so the server keeps the stored one. */
export function buildPushInput(v: {
  installationId?: string | null;
  installationKey?: string | null;
  region?: PushRegion | null;
  relayUri?: string | null;
  identityUri?: string | null;
}): PushSettingsInput {
  const region = v.region ?? "us";
  const input: PushSettingsInput = { installationId: (v.installationId ?? "").trim(), region };
  const key = (v.installationKey ?? "").trim();
  if (key) {
    input.installationKey = key;
  }
  if (region === "custom") {
    input.relayUri = (v.relayUri ?? "").trim();
    input.identityUri = (v.identityUri ?? "").trim();
  }
  return input;
}

@Component({
  selector: "cw-instance-admin-push",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule],
  template: `
    <app-header></app-header>
    <bit-container>
      <p bitTypography="body1">
        {{ "cwPushDesc" | i18n }}
        <a bitLink [href]="hostUrl" target="_blank" rel="noreferrer noopener">
          {{ "cwPushGetKey" | i18n }}
        </a>
      </p>
      @if (error()) {
        <bit-callout type="danger">{{ error() }}</bit-callout>
      }
      @if (settings(); as s) {
        @if (s.status.envOverride) {
          <bit-callout type="warning" data-testid="cw-push-env-notice">
            {{ "cwPushEnvNotice" | i18n }}
          </bit-callout>
        }
        @if (s.keyUnreadable) {
          <bit-callout type="warning" data-testid="cw-push-unreadable">
            {{ "cwPushKeyUnreadable" | i18n }}
          </bit-callout>
        }
        <div
          class="tw-mb-6 tw-max-w-3xl tw-rounded-lg tw-border tw-border-solid tw-border-secondary-300 tw-p-4"
          data-testid="cw-push-status"
        >
          <div bitTypography="h3">{{ "cwPushStatus" | i18n }}</div>
          <dl class="tw-mb-0 tw-grid tw-grid-cols-[max-content_1fr] tw-gap-x-4 tw-gap-y-1">
            <dt>{{ "cwPushStatus" | i18n }}</dt>
            <dd data-testid="cw-push-state">{{ stateLabel() | i18n }}</dd>
            <dt>{{ "cwPushSource" | i18n }}</dt>
            <dd data-testid="cw-push-source">{{ sourceLabel() | i18n }}</dd>
            @if (s.status.relayHost) {
              <dt>{{ "cwPushRelayHost" | i18n }}</dt>
              <dd class="tw-font-mono">{{ s.status.relayHost }}</dd>
            }
            <dt>{{ "cwPushLastResult" | i18n }}</dt>
            <dd data-testid="cw-push-last">{{ lastResultText() }}</dd>
          </dl>
        </div>
        <form [formGroup]="form" [bitSubmit]="save" class="tw-max-w-3xl">
          <bit-form-field>
            <bit-label>{{ "cwPushInstallationId" | i18n }}</bit-label>
            <input
              bitInput
              type="text"
              formControlName="installationId"
              autocomplete="off"
              data-testid="cw-push-id"
            />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "cwPushInstallationKey" | i18n }}</bit-label>
            <input
              bitInput
              type="password"
              formControlName="installationKey"
              autocomplete="new-password"
              data-testid="cw-push-key"
            />
            <bit-hint>{{ keyHint() }}</bit-hint>
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "cwPushRegion" | i18n }}</bit-label>
            <bit-select formControlName="region" data-testid="cw-push-region">
              @for (r of regions; track r.value) {
                <bit-option [value]="r.value" [label]="r.label | i18n"></bit-option>
              }
            </bit-select>
          </bit-form-field>
          @if (form.value.region === "custom") {
            <bit-form-field>
              <bit-label>{{ "cwPushRelayUri" | i18n }}</bit-label>
              <input bitInput type="text" formControlName="relayUri" placeholder="https://" />
            </bit-form-field>
            <bit-form-field>
              <bit-label>{{ "cwPushIdentityUri" | i18n }}</bit-label>
              <input bitInput type="text" formControlName="identityUri" placeholder="https://" />
            </bit-form-field>
          }
          <div class="tw-flex tw-flex-wrap tw-gap-2">
            <button type="submit" bitButton bitFormButton buttonType="primary" data-testid="cw-push-save">
              {{ "save" | i18n }}
            </button>
            <button
              type="button"
              bitButton
              buttonType="secondary"
              [disabled]="!s.status.configured"
              (click)="test()"
              data-testid="cw-push-test"
            >
              {{ "cwPushTest" | i18n }}
            </button>
            <button
              type="button"
              bitButton
              buttonType="danger"
              [disabled]="!s.keySet"
              (click)="remove()"
              data-testid="cw-push-remove"
            >
              {{ "cwPushRemove" | i18n }}
            </button>
          </div>
        </form>
      } @else if (!error()) {
        <i class="bwi bwi-spinner bwi-spin" aria-hidden="true"></i>
      }
    </bit-container>
  `,
})
export class InstanceAdminPushComponent implements OnInit {
  private readonly api = inject(InstanceAdminApiService);
  private readonly dialogs = inject(DialogService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);

  protected readonly hostUrl = HOST_URL;
  protected readonly regions = [
    { value: "us" as PushRegion, label: "cwPushRegionUs" },
    { value: "eu" as PushRegion, label: "cwPushRegionEu" },
    { value: "custom" as PushRegion, label: "cwPushRegionCustom" },
  ];
  protected readonly settings = signal<PushSettings | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly form = inject(FormBuilder).group({
    installationId: [""],
    installationKey: [""],
    region: ["us" as PushRegion],
    relayUri: [""],
    identityUri: [""],
  });

  async ngOnInit() {
    try {
      this.apply(await this.api.pushSettings());
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
  }

  private apply(s: PushSettings) {
    this.settings.set(s);
    this.error.set(null);
    this.form.setValue({
      installationId: s.installationId,
      installationKey: "",
      region: s.region,
      relayUri: s.region === "custom" ? (s.relayUri ?? "") : "",
      identityUri: s.region === "custom" ? (s.identityUri ?? "") : "",
    });
  }

  protected stateLabel(): string {
    switch (this.settings()?.status.state) {
      case "configured":
        return "cwPushStatusConfigured";
      case "incomplete":
        return "cwPushStatusIncomplete";
      case "key unreadable":
        return "cwPushStatusUnreadable";
      default:
        return "cwPushStatusNotConfigured";
    }
  }

  protected sourceLabel(): string {
    const src = this.settings()?.status.source;
    return src === "env" ? "cwPushSourceEnv" : src === "settings" ? "cwPushSourceSettings" : "-";
  }

  protected keyHint(): string {
    const s = this.settings();
    if (!s?.keySet) {
      return this.i18n.t("cwPushKeyHint");
    }
    return this.i18n.t("cwPushKeyStoredHint");
  }

  protected lastResultText(): string {
    const r = this.settings()?.status.lastResult;
    if (!r) {
      return this.i18n.t("cwPushLastResultNone");
    }
    return this.i18n.t(
      r.ok ? "cwPushLastResultOk" : "cwPushLastResultFail",
      String(r.status ?? "-"),
      new Date(r.at).toLocaleString(),
    );
  }

  save = async () => {
    this.apply(await this.api.savePushSettings(buildPushInput(this.form.value)));
    this.toast.showToast({ variant: "success", message: this.i18n.t("cwPushSaved") });
  };

  protected async test() {
    const r = await this.api.testPushSettings();
    // Refresh the status panel so it shows the result of this test.
    this.settings.set(await this.api.pushSettings());
    this.toast.showToast(
      r.ok
        ? { variant: "success", message: this.i18n.t("cwPushTestOk") }
        : {
            variant: "error",
            message: this.i18n.t("cwPushTestFailed", this.i18n.t(testErrorKey(r.error))),
          },
    );
  }

  protected async remove() {
    const confirmed = await this.dialogs.openSimpleDialog({
      title: { key: "cwPushRemove" },
      content: { key: "cwPushRemoveConfirm" },
      type: "warning",
    });
    if (!confirmed) {
      return;
    }
    this.apply(await this.api.removePushSettings());
    this.toast.showToast({ variant: "success", message: this.i18n.t("cwPushRemoved") });
  }
}
