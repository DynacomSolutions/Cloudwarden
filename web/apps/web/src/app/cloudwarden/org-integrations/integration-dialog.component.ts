// Cloudwarden: create or edit an event integration (web/NOTICE.md, docs/integrations.md).
// Secret fields are write-only: on edit they start empty and an empty value keeps the stored one.
import { ChangeDetectionStrategy, Component, inject, signal } from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import { FormBuilder, FormControl, Validators } from "@angular/forms";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DIALOG_DATA, DialogRef, DialogService } from "@bitwarden/components";

import { SharedModule } from "../../shared";

import {
  EventIntegration,
  FIELDS,
  IntegrationType,
  OrgIntegrationsApiService,
  parseEventTypes,
  splitValues,
} from "./org-integrations-api.service";

export interface IntegrationDialogData {
  organizationId: string;
  integration?: EventIntegration;
}

export const TYPE_LABELS: Record<IntegrationType, string> = {
  webhook: "cwIntWebhook",
  splunk: "cwIntSplunk",
  datadog: "cwIntDatadog",
  sentinel: "cwIntSentinel",
};

const ALL_KEYS = [...new Set(Object.values(FIELDS).flatMap((f) => f.map((x) => x.key)))];

@Component({
  selector: "cw-integration-dialog",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule],
  template: `
    <form [formGroup]="form" [bitSubmit]="submit" bit-dialog dialogSize="large">
      <span bitDialogTitle>
        {{ (data.integration ? "cwIntEdit" : "cwIntAdd") | i18n }}
      </span>
      <div bitDialogContent>
        @if (signingSecret(); as secret) {
          <p bitTypography="body1">{{ "cwIntSigningSecretDesc" | i18n }}</p>
          <bit-form-field>
            <bit-label>{{ "cwIntSigningSecret" | i18n }}</bit-label>
            <input bitInput readonly [value]="secret" data-testid="cw-int-signing-secret" />
            <button
              type="button"
              bitSuffix
              bitIconButton="bwi-clone"
              [appCopyClick]="secret"
              [label]="'copyValue' | i18n"
            ></button>
          </bit-form-field>
        } @else {
          <bit-form-field>
            <bit-label>{{ "type" | i18n }}</bit-label>
            <bit-select formControlName="type" data-testid="cw-int-type">
              @for (t of types; track t) {
                <bit-option [value]="t" [label]="labels[t] | i18n"></bit-option>
              }
            </bit-select>
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "name" | i18n }}</bit-label>
            <input bitInput formControlName="name" data-testid="cw-int-name" />
          </bit-form-field>
          @for (f of fields(); track f.key) {
            <bit-form-field>
              <bit-label>{{ f.labelKey | i18n }}</bit-label>
              @if (f.options) {
                <bit-select [formControl]="control(f.key)">
                  @for (o of f.options; track o) {
                    <bit-option [value]="o" [label]="o"></bit-option>
                  }
                </bit-select>
              } @else {
                <input
                  bitInput
                  [type]="f.secret ? 'password' : 'text'"
                  [formControl]="control(f.key)"
                  [placeholder]="f.placeholder ?? ''"
                  [attr.data-testid]="'cw-int-' + f.key"
                />
              }
              @if (f.secret && data.integration) {
                <bit-hint>{{ "cwIntSecretKeep" | i18n }}</bit-hint>
              }
            </bit-form-field>
          }
          <bit-form-field>
            <bit-label>{{ "cwIntEventTypes" | i18n }}</bit-label>
            <input bitInput formControlName="eventTypes" placeholder="1100-1116, 1500" />
            <bit-hint>{{ "cwIntEventTypesHint" | i18n }}</bit-hint>
          </bit-form-field>
          <bit-form-control>
            <input type="checkbox" bitCheckbox formControlName="enabled" />
            <bit-label>{{ "cwIntEnabled" | i18n }}</bit-label>
          </bit-form-control>
          @if (error()) {
            <bit-callout type="danger">{{ error() }}</bit-callout>
          }
        }
      </div>
      <ng-container bitDialogFooter>
        @if (!signingSecret()) {
          <button type="submit" bitButton bitFormButton buttonType="primary" data-testid="cw-int-save">
            {{ "save" | i18n }}
          </button>
        }
        <button type="button" bitButton bitFormButton (click)="close()">
          {{ (signingSecret() ? "close" : "cancel") | i18n }}
        </button>
      </ng-container>
    </form>
  `,
})
export class IntegrationDialogComponent {
  protected readonly data = inject<IntegrationDialogData>(DIALOG_DATA);
  private readonly ref = inject(DialogRef<boolean>);
  private readonly api = inject(OrgIntegrationsApiService);
  private readonly i18n = inject(I18nService);
  private readonly fb = inject(FormBuilder);

  protected readonly types = Object.keys(FIELDS) as IntegrationType[];
  protected readonly labels = TYPE_LABELS;
  protected readonly signingSecret = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  private saved = false;

  protected readonly form = this.fb.group({
    type: [{ value: this.data.integration?.type ?? "webhook", disabled: !!this.data.integration }],
    name: [this.data.integration?.name ?? "", [Validators.required, Validators.maxLength(100)]],
    enabled: [this.data.integration?.enabled ?? true],
    eventTypes: [this.data.integration?.eventTypes?.join(", ") ?? ""],
    values: this.fb.group(
      Object.fromEntries(
        ALL_KEYS.map((k) => [k, [(this.data.integration?.config[k] as string | null) ?? ""]]),
      ),
    ),
  });

  private readonly type = toSignal(this.form.controls.type.valueChanges, {
    initialValue: this.form.controls.type.value,
  });
  protected readonly fields = () => FIELDS[(this.type() ?? "webhook") as IntegrationType];

  protected control(key: string) {
    return this.form.controls.values.get(key) as FormControl<string | null>;
  }

  submit = async () => {
    this.error.set(null);
    const type = this.form.getRawValue().type as IntegrationType;
    const values = this.form.controls.values.getRawValue() as Record<string, string | null>;
    const missing = FIELDS[type].filter(
      (f) => f.required && !(f.secret && this.data.integration) && !(values[f.key] ?? "").trim(),
    );
    if (this.form.invalid || missing.length) {
      this.form.markAllAsTouched();
      this.error.set(this.i18n.t("cwIntMissing", missing.map((f) => this.i18n.t(f.labelKey)).join(", ")));
      return;
    }
    let eventTypes: number[] | null;
    try {
      eventTypes = parseEventTypes(this.form.value.eventTypes ?? "");
    } catch (e) {
      this.error.set(this.i18n.t("cwIntBadEventType", (e as Error).message));
      return;
    }
    const { config, secrets } = splitValues(type, values);
    const input = {
      name: (this.form.value.name ?? "").trim(),
      enabled: this.form.value.enabled !== false,
      config,
      secrets,
      eventTypes,
    };
    try {
      const result = this.data.integration
        ? await this.api.update(this.data.organizationId, this.data.integration.id, input)
        : await this.api.create(this.data.organizationId, { ...input, type });
      this.saved = true;
      if (result.signingSecret) {
        this.signingSecret.set(result.signingSecret);
        return;
      }
      this.ref.close(true);
    } catch (e: any) {
      const v = e?.validationErrors ?? {};
      const details = Object.entries(v).map(([k, m]) => `${k}: ${(m as string[]).join(" ")}`);
      this.error.set(details.length ? details.join("\n") : (e?.message ?? String(e)));
    }
  };

  protected close() {
    this.ref.close(this.saved);
  }

  static open(dialogs: DialogService, data: IntegrationDialogData) {
    return dialogs.open<boolean, IntegrationDialogData>(IntegrationDialogComponent, { data });
  }
}
