// Cloudwarden: shows or rotates the organisation SCIM API key after re-verifying the user
// (web/NOTICE.md).
import { ChangeDetectionStrategy, Component, inject, signal } from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";

import { UserVerificationFormInputComponent } from "@bitwarden/auth/angular";
import { OrganizationApiKeyRequest } from "@bitwarden/common/admin-console/models/request/organization-api-key.request";
import { UserVerificationService } from "@bitwarden/common/auth/abstractions/user-verification/user-verification.service.abstraction";
import { Verification } from "@bitwarden/common/auth/types/verification";
import { DIALOG_DATA, DialogService } from "@bitwarden/components";

import { SharedModule } from "../../shared";

import { OrgIntegrationsApiService } from "./org-integrations-api.service";

export interface ScimKeyDialogData {
  organizationId: string;
  rotate: boolean;
}

@Component({
  selector: "cw-scim-key-dialog",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, UserVerificationFormInputComponent],
  template: `
    <form [formGroup]="form" [bitSubmit]="submit" bit-dialog>
      <span bitDialogTitle>{{ "cwScimApiKey" | i18n }}</span>
      <div bitDialogContent>
        @if (key(); as k) {
          <bit-form-field>
            <bit-label>{{ "cwScimApiKey" | i18n }}</bit-label>
            <input bitInput type="text" readonly [value]="k" data-testid="cw-scim-key" />
            <button
              type="button"
              bitSuffix
              bitIconButton="bwi-clone"
              [appCopyClick]="k"
              [label]="'copyValue' | i18n"
            ></button>
          </bit-form-field>
          <bit-callout type="warning">{{ "cwScimKeyWarning" | i18n }}</bit-callout>
        } @else {
          <p bitTypography="body1">
            {{ (data.rotate ? "cwScimRotateDesc" : "cwScimViewDesc") | i18n }}
          </p>
          <app-user-verification-form-input formControlName="secret"></app-user-verification-form-input>
        }
      </div>
      <ng-container bitDialogFooter>
        @if (!key()) {
          <button type="submit" bitButton bitFormButton buttonType="primary">
            {{ (data.rotate ? "rotateApiKey" : "viewApiKey") | i18n }}
          </button>
        }
        <button type="button" bitButton bitFormButton bitDialogClose>{{ "close" | i18n }}</button>
      </ng-container>
    </form>
  `,
})
export class ScimKeyDialogComponent {
  protected readonly data = inject<ScimKeyDialogData>(DIALOG_DATA);
  private readonly api = inject(OrgIntegrationsApiService);
  private readonly verification = inject(UserVerificationService);
  protected readonly key = signal<string | null>(null);
  protected readonly form = inject(FormBuilder).group({
    secret: [null as Verification | null, [Validators.required]],
  });

  submit = async () => {
    if (this.form.invalid) {
      this.form.markAllAsTouched();
      return;
    }
    const request = await this.verification.buildRequest(
      this.form.value.secret as Verification,
      OrganizationApiKeyRequest,
    );
    this.key.set(await this.api.scimKey(this.data.organizationId, request, this.data.rotate));
  };

  static open(dialogs: DialogService, data: ScimKeyDialogData) {
    return dialogs.open(ScimKeyDialogComponent, { data });
  }
}
