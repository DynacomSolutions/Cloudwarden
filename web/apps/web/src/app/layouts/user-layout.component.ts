// FIXME: Update this file to be type safe and remove this and next line
// @ts-strict-ignore
import { CommonModule } from "@angular/common";
import { Component, computed, inject, OnInit, Signal } from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import { RouterModule } from "@angular/router";
import { map, Observable, of, switchMap } from "rxjs";

import { PasswordManagerLogo } from "@bitwarden/assets/svg";
import {
  canAccessEmergencyAccess,
  singleOrganizationPolicyApplies$,
} from "@bitwarden/common/admin-console/abstractions/organization/organization.service.abstraction";
import { PolicyService } from "@bitwarden/common/admin-console/abstractions/policy/policy.service.abstraction";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";
import { FeatureFlag } from "@bitwarden/common/enums/feature-flag.enum";
import { ConfigService } from "@bitwarden/common/platform/abstractions/config/config.service";
import { SyncService } from "@bitwarden/common/platform/sync";
import {
  PopoverModule,
  SideNavService,
  SvgModule,
} from "@bitwarden/components";
import { SendPolicyService } from "@bitwarden/send-ui";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { I18nPipe } from "@bitwarden/ui-common";
import {
  VaultManageNavComponent,
  VaultNavSectionComponent,
} from "@bitwarden/vault";
import { PremiumSubscriptionRoutingService } from "@bitwarden/web-vault/app/billing/individual/services/premium-subscription-routing.service";

import { FederationApiService } from "../cloudwarden/federation/federation-api.service";
import { InstanceAdminApiService } from "../cloudwarden/instance-admin/instance-admin-api.service";
import { BillingFreeFamiliesNavItemComponent } from "../billing/shared/billing-free-families-nav-item.component";
import {
  CoachmarkComponent,
  CoachmarkService,
} from "../vault/components/coachmark";

import { WebLayoutModule } from "./web-layout.module";

// FIXME(https://bitwarden.atlassian.net/browse/CL-764): Migrate to OnPush
// eslint-disable-next-line @angular-eslint/prefer-on-push-component-change-detection
@Component({
  selector: "app-user-layout",
  templateUrl: "user-layout.component.html",
  imports: [
    CommonModule,
    RouterModule,
    I18nPipe,
    WebLayoutModule,
    SvgModule,
    VaultManageNavComponent,
    VaultNavSectionComponent,
    BillingFreeFamiliesNavItemComponent,
    PopoverModule,
    CoachmarkComponent,
  ],
})
export class UserLayoutComponent implements OnInit {
  protected readonly logo = PasswordManagerLogo;
  // Cloudwarden: instance admin entry, shown only to instance admins (web/NOTICE.md).
  protected readonly isInstanceAdmin = toSignal(
    inject(InstanceAdminApiService).isAdmin$,
    {
      initialValue: false,
    },
  );
  // Cloudwarden: "Add plan" creates an organisation, so only owners and admins see it.
  protected readonly canCreateOrganizations = toSignal(
    inject(InstanceAdminApiService).canCreateOrganizations$,
    { initialValue: false },
  );
  // Cloudwarden: federated organisations entry, shown when the server has federation on.
  protected readonly federationEnabled = toSignal(
    inject(FederationApiService).enabled$,
    {
      initialValue: false,
    },
  );
  // Cloudwarden: open workspace requests, shown as a count next to the admin's Federation entry.
  protected readonly federationPending = toSignal(
    inject(FederationApiService).status$.pipe(
      map((s) => s?.pendingRequests ?? 0),
    ),
    { initialValue: 0 },
  );
  private readonly i18nService = inject(I18nService);
  protected readonly federationNavText = computed(() => {
    const n = this.federationPending();
    const text = this.i18nService.t("cwFederation");
    return n > 0 ? `${text} (${n})` : text;
  });
  protected readonly showEmergencyAccess: Signal<boolean>;
  protected readonly sendEnabled$: Observable<boolean> =
    this.sendPolicyService.disableSend$.pipe(
      map((disableSend) => !disableSend),
    );
  protected subscriptionRoute$: Observable<string | null>;

  protected readonly coachmarkService = inject(CoachmarkService);
  protected readonly sideNavService = inject(SideNavService);
  private readonly configService = inject(ConfigService);

  protected readonly exportRoute = computed(() => {
    const vfo1Enabled = this.vfo1Enabled();
    return vfo1Enabled ? "/settings/export" : "/tools/export";
  });

  protected readonly vfo1Enabled: Signal<boolean> = toSignal(
    inject(ConfigService).getFeatureFlag$(FeatureFlag.VFO1Foundation),
    { initialValue: false },
  );

  protected readonly singleOrgPolicyApplies = toSignal(
    this.accountService.activeAccount$.pipe(
      getUserId,
      switchMap((userId) =>
        singleOrganizationPolicyApplies$(userId, this.policyService),
      ),
    ),
    { initialValue: true },
  );

  protected readonly importCoachmarkOpen = computed(
    () => this.coachmarkService.activeStepId() === "importData",
  );

  protected readonly reportsCoachmarkOpen = computed(
    () => this.coachmarkService.activeStepId() === "monitorSecurity",
  );

  /** Expand tools nav group when import coachmark is active */
  protected readonly toolsNavGroupOpen = computed(
    () => this.coachmarkService.activeStepId() === "importData",
  );

  constructor(
    private syncService: SyncService,
    private accountService: AccountService,
    private policyService: PolicyService,
    private sendPolicyService: SendPolicyService,
    private premiumSubscriptionRoutingService: PremiumSubscriptionRoutingService,
  ) {
    this.showEmergencyAccess = toSignal(
      this.accountService.activeAccount$.pipe(
        getUserId,
        switchMap((userId) =>
          canAccessEmergencyAccess(userId, this.policyService),
        ),
      ),
    );

    // Cloudwarden: no subscription page; billing is not part of this build (web/NOTICE.md).
    this.subscriptionRoute$ = of(null);
  }

  async ngOnInit() {
    document.body.classList.remove("layout_frontend");
    await this.syncService.fullSync(false);
  }
}
