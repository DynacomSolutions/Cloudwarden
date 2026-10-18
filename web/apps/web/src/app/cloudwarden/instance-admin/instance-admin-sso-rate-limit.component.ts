// Cloudwarden: Instance admin > SSO rate limit (web/NOTICE.md, docs/admin.md).
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import { InstanceAdminApiService, SsoRateLimit } from "./instance-admin-api.service";

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
        <div class="tw-flex tw-gap-2">
          <button
            type="submit"
            bitButton
            bitFormButton
            buttonType="primary"
            [disabled]="form.invalid"
            data-testid="cw-sso-save"
          >
            {{ "save" | i18n }}
          </button>
          <button
            type="button"
            bitButton
            buttonType="secondary"
            [disabled]="!custom()"
            (click)="reset()"
            data-testid="cw-sso-reset"
          >
            {{ "cwSsoRateLimitReset" | i18n }}
          </button>
        </div>
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
  protected readonly custom = signal(false);
  protected readonly form = inject(FormBuilder).group({
    limit: [
      20 as number | null,
      [
        Validators.required,
        Validators.min(SSO_RATE_LIMIT_MIN),
        Validators.max(SSO_RATE_LIMIT_MAX),
        Validators.pattern(/^\d+$/),
      ],
    ],
  });

  async ngOnInit() {
    try {
      this.apply(await this.api.ssoRateLimit());
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
  }

  private apply(s: SsoRateLimit) {
    this.custom.set(s.custom);
    this.form.setValue({ limit: s.ssoRateLimitPerMinute });
  }

  reset = async () => {
    this.apply(await this.api.resetSsoRateLimit());
    this.toast.showToast({ variant: "success", message: this.i18n.t("cwSsoRateLimitResetDone") });
  };

  save = async () => {
    this.apply(await this.api.saveSsoRateLimit(Number(this.form.value.limit)));
    this.toast.showToast({ variant: "success", message: this.i18n.t("cwSsoRateLimitSaved") });
  };
}
