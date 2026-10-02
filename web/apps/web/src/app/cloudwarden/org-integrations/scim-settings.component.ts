// Cloudwarden: SCIM provisioning settings at /organizations/:id/settings/scim (web/NOTICE.md,
// docs/integrations.md). Enables the SCIM endpoint, shows its URL and manages its API key.
import { DatePipe } from "@angular/common";
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { FormBuilder } from "@angular/forms";
import { ActivatedRoute } from "@angular/router";
import { firstValueFrom } from "rxjs";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import {
  OrgIntegrationsApiService,
  ScimConfig,
  organizationIdFrom,
} from "./org-integrations-api.service";
import { ScimKeyDialogComponent } from "./scim-key-dialog.component";

/** Identity providers, as a hint for the setup steps (value stored with the settings). */
export const SCIM_PROVIDERS = [
  { value: 0, label: "cwScimProviderOther" },
  { value: 1, label: "cwScimProviderEntra" },
  { value: 2, label: "cwScimProviderOkta" },
  { value: 3, label: "cwScimProviderOneLogin" },
  { value: 4, label: "cwScimProviderJumpCloud" },
  { value: 5, label: "cwScimProviderGoogle" },
];

@Component({
  selector: "cw-scim-settings",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, DatePipe],
  template: `
    <app-header></app-header>
    <bit-container>
      <p bitTypography="body1">{{ "cwScimDesc" | i18n }}</p>
      @if (config(); as cfg) {
        <form [formGroup]="form" [bitSubmit]="save" class="tw-max-w-3xl">
          <bit-form-control>
            <input type="checkbox" bitCheckbox formControlName="enabled" data-testid="cw-scim-enabled" />
            <bit-label>{{ "cwScimEnable" | i18n }}</bit-label>
            <bit-hint>{{ "cwScimEnableHint" | i18n }}</bit-hint>
          </bit-form-control>
          <bit-form-field>
            <bit-label>{{ "cwScimProvider" | i18n }}</bit-label>
            <bit-select formControlName="provider">
              @for (p of providers; track p.value) {
                <bit-option [value]="p.value" [label]="p.label | i18n"></bit-option>
              }
            </bit-select>
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "cwScimUrl" | i18n }}</bit-label>
            <input bitInput type="text" readonly [value]="cfg.scimUrl" data-testid="cw-scim-url" />
            <button
              type="button"
              bitSuffix
              bitIconButton="bwi-clone"
              [appCopyClick]="cfg.scimUrl"
              [label]="'copyValue' | i18n"
            ></button>
            <bit-hint>{{ "cwScimUrlHint" | i18n }}</bit-hint>
          </bit-form-field>
          <div class="tw-mb-6 tw-flex tw-flex-wrap tw-items-center tw-gap-2">
            <button type="button" bitButton buttonType="secondary" (click)="openKey(false)">
              {{ "viewApiKey" | i18n }}
            </button>
            <button type="button" bitButton buttonType="secondary" (click)="openKey(true)">
              {{ "rotateApiKey" | i18n }}
            </button>
            @if (cfg.apiKeyRevisionDate) {
              <span class="tw-text-muted">
                {{ "cwScimKeyChanged" | i18n: (cfg.apiKeyRevisionDate | date: "medium") }}
              </span>
            }
          </div>
          <button type="submit" bitButton bitFormButton buttonType="primary" data-testid="cw-scim-save">
            {{ "save" | i18n }}
          </button>
        </form>
      } @else {
        <i class="bwi bwi-spinner bwi-spin" aria-hidden="true"></i>
      }
    </bit-container>
  `,
})
export class ScimSettingsComponent implements OnInit {
  private readonly api = inject(OrgIntegrationsApiService);
  private readonly dialogs = inject(DialogService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly orgId = organizationIdFrom(inject(ActivatedRoute));

  protected readonly providers = SCIM_PROVIDERS;
  protected readonly config = signal<ScimConfig | null>(null);
  protected readonly form = inject(FormBuilder).group({
    enabled: [false],
    provider: [0 as number | null],
  });

  async ngOnInit() {
    this.apply(await this.api.getScimConfig(this.orgId));
  }

  private apply(cfg: ScimConfig) {
    this.config.set(cfg);
    this.form.setValue({ enabled: cfg.enabled, provider: cfg.provider ?? 0 });
  }

  save = async () => {
    const v = this.form.value;
    this.apply(await this.api.saveScimConfig(this.orgId, v.enabled === true, v.provider ?? null));
    this.toast.showToast({ variant: "success", message: this.i18n.t("cwScimSaved") });
  };

  protected async openKey(rotate: boolean) {
    const ref = ScimKeyDialogComponent.open(this.dialogs, { organizationId: this.orgId, rotate });
    await firstValueFrom(ref.closed);
    this.apply(await this.api.getScimConfig(this.orgId));
  }
}
