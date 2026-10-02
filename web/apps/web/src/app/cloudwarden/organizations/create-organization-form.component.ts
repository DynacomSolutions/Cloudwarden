// Cloudwarden: organisation create form (web/NOTICE.md). Replaces the upstream plan picker,
// which on self-hosted servers only offers a licence upload. Cloudwarden organisations are
// always on the Free plan, so there are no billing or payment steps.
import { ChangeDetectionStrategy, Component, OnInit, inject } from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";
import { Router } from "@angular/router";
import { firstValueFrom } from "rxjs";

import { OrganizationApiServiceAbstraction } from "@bitwarden/common/admin-console/abstractions/organization/organization-api.service.abstraction";
import { OrganizationCreateRequest } from "@bitwarden/common/admin-console/models/request/organization-create.request";
import { OrganizationKeysRequest } from "@bitwarden/common/admin-console/models/request/organization-keys.request";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { InitiationPath, PlanType } from "@bitwarden/common/billing/enums";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { SyncService } from "@bitwarden/common/platform/sync";
import { ToastService } from "@bitwarden/components";

import { PremiumOrgUpgradeService } from "../../billing/individual/upgrade/premium-org-upgrade-payment/services/premium-org-upgrade.service";
import { SharedModule } from "../../shared";

@Component({
  selector: "cw-create-organization-form",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule],
  template: `
    <form [formGroup]="form" [bitSubmit]="submit" class="tw-max-w-xl" data-testid="cw-create-org">
      <bit-form-field>
        <bit-label>{{ "organizationName" | i18n }}</bit-label>
        <input bitInput type="text" formControlName="name" appAutofocus />
      </bit-form-field>
      <bit-form-field>
        <bit-label>{{ "billingEmail" | i18n }}</bit-label>
        <input bitInput type="email" formControlName="billingEmail" />
      </bit-form-field>
      <bit-radio-group formControlName="plan">
        <bit-label>{{ "choosePlan" | i18n }}</bit-label>
        <bit-radio-button [value]="free">
          <bit-label>{{ "cwFreePlan" | i18n }}</bit-label>
          <bit-hint>{{ "cwFreePlanDesc" | i18n }}</bit-hint>
        </bit-radio-button>
      </bit-radio-group>
      <button type="submit" bitButton bitFormButton buttonType="primary">
        {{ "submit" | i18n }}
      </button>
    </form>
  `,
})
export class CloudwardenCreateOrganizationFormComponent implements OnInit {
  private readonly accountService = inject(AccountService);
  private readonly organizationApiService = inject(OrganizationApiServiceAbstraction);
  private readonly encryption = inject(PremiumOrgUpgradeService);
  private readonly syncService = inject(SyncService);
  private readonly toastService = inject(ToastService);
  private readonly i18nService = inject(I18nService);
  private readonly router = inject(Router);

  protected readonly free = PlanType.Free;
  protected readonly form = inject(FormBuilder).group({
    name: ["", [Validators.required, Validators.maxLength(50)]],
    billingEmail: ["", [Validators.required, Validators.email]],
    plan: [PlanType.Free],
  });

  async ngOnInit() {
    const account = await firstValueFrom(this.accountService.activeAccount$);
    if (account?.email) {
      this.form.controls.billingEmail.setValue(account.email);
    }
  }

  protected submit = async () => {
    this.form.markAllAsTouched();
    if (this.form.invalid) {
      return;
    }
    const account = await firstValueFrom(this.accountService.activeAccount$);
    if (!account) {
      return;
    }
    const data = await this.encryption.generateOrganizationEncryptionData(account.id);
    const request = new OrganizationCreateRequest(
      data.key,
      new OrganizationKeysRequest(data.orgKeys[0], data.orgKeys[1].encryptedString as string),
      data.collectionCt,
    );
    request.name = this.form.value.name ?? "";
    request.billingEmail = this.form.value.billingEmail ?? "";
    request.planType = PlanType.Free;
    request.initiationPath = InitiationPath.NewOrganizationCreationInProduct;
    const org = await this.organizationApiService.create(request);
    this.toastService.showToast({
      variant: "success",
      title: this.i18nService.t("organizationCreated"),
      message: this.i18nService.t("organizationReadyToGo"),
    });
    await this.syncService.fullSync(true);
    await this.router.navigate(["/organizations", org.id]);
  };
}
