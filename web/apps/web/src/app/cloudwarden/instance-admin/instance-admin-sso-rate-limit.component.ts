// Cloudwarden: Instance admin > SSO rate limit (web/NOTICE.md, docs/admin.md).
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { FormBuilder } from "@angular/forms";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import { InstanceAdminApiService } from "./instance-admin-api.service";

export const SSO_RATE_LIMIT_MIN = 5;
export const SSO_RATE_LIMIT_MAX = 1000;

@Component({
  selector: "cw-instance-admin-sso-rate-limit",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule],
  template: `
    <app-header></app-header>
    <bit-container>
      <p bitTypography="body1">{{ "cwSsoRateLimitDesc" | i18n }}</p>
      @if (error()) {
        <bit-callout type="danger">{{ error() }}</bit-callout>
      }
      <form [formGroup]="form" [bitSubmit]="save" class="tw-max-w-3xl">
        <bit-form-field>
          <bit-label>{{ "cwSsoRateLimitField" | i18n }}</bit-label>
          <input
            bitInput
            type="number"
            formControlName="limit"
            [min]="min"
            [max]="max"
            step="1"
            data-testid="cw-sso-limit"
          />
          <bit-hint>{{ "cwSsoRateLimitHint" | i18n }}</bit-hint>
        </bit-form-field>
        <button type="submit" bitButton bitFormButton buttonType="primary" data-testid="cw-sso-save">
          {{ "save" | i18n }}
        </button>
      </form>
    </bit-container>
  `,
})
export class InstanceAdminSsoRateLimitComponent implements OnInit {
  private readonly api = inject(InstanceAdminApiService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);

  protected readonly min = SSO_RATE_LIMIT_MIN;
  protected readonly max = SSO_RATE_LIMIT_MAX;
  protected readonly error = signal<string | null>(null);
  protected readonly form = inject(FormBuilder).group({ limit: [20 as number | null] });

  async ngOnInit() {
    try {
      this.form.setValue({ limit: (await this.api.ssoRateLimit()).ssoRateLimitPerMinute });
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
  }

  save = async () => {
    const saved = await this.api.saveSsoRateLimit(Number(this.form.value.limit));
    this.form.setValue({ limit: saved.ssoRateLimitPerMinute });
    this.toast.showToast({ variant: "success", message: this.i18n.t("cwSsoRateLimitSaved") });
  };
}
