import { NgModule } from "@angular/core";
import { RouterModule, Routes } from "@angular/router";

import { authGuard } from "@bitwarden/angular/auth/guards";
import {
  canAccessOrgAdmin,
  canAccessGroupsTab,
  canAccessMembersTab,
  canAccessVaultTab,
  canAccessReportingTab,
  canAccessSettingsTab,
} from "@bitwarden/common/admin-console/abstractions/organization/organization.service.abstraction";
import { Organization } from "@bitwarden/common/admin-console/models/domain/organization";

import { deepLinkGuard } from "../../auth/guards/deep-link/deep-link.guard";

import { VaultModule } from "./collections/vault.module";
import { organizationPermissionsGuard } from "./guards/org-permissions.guard";
import { organizationRedirectGuard } from "./guards/org-redirect.guard";
import { OrganizationLayoutComponent } from "./layouts/organization-layout.component";
import { GroupsComponent } from "./manage/groups.component";

const routes: Routes = [
  {
    path: ":organizationId",
    component: OrganizationLayoutComponent,
    canActivate: [deepLinkGuard(), authGuard, organizationPermissionsGuard(canAccessOrgAdmin)],
    children: [
      {
        path: "",
        pathMatch: "full",
        canActivate: [organizationRedirectGuard(getOrganizationRoute)],
        children: [], // This is required to make the auto redirect work, },
      },
      {
        path: "vault",
        loadChildren: () => VaultModule,
      },
      {
        path: "settings",
        loadChildren: () =>
          import("./settings/organization-settings.module").then(
            (m) => m.OrganizationSettingsModule,
          ),
      },
      {
        path: "members",
        loadChildren: () => import("./members").then((m) => m.MembersModule),
      },
      {
        component: GroupsComponent,
        path: "groups",
        canActivate: [organizationPermissionsGuard(canAccessGroupsTab)],
        data: {
          titleId: "groups",
        },
      },
      {
        path: "reporting",
        loadChildren: () =>
          import("../organizations/reporting/organization-reporting.module").then(
            (m) => m.OrganizationReportingModule,
          ),
      },
      {
        // Cloudwarden: native event integrations page (web/NOTICE.md, docs/integrations.md).
        path: "integrations",
        loadComponent: () =>
          import("../../cloudwarden/org-integrations/event-integrations.component").then(
            (m) => m.EventIntegrationsComponent,
          ),
        canActivate: [organizationPermissionsGuard((o) => o.isAdmin)],
        data: { titleId: "integrations" },
      },
      {
        // Cloudwarden: federated members (web/NOTICE.md, docs/federation.md).
        path: "federation",
        loadComponent: () =>
          import("../../cloudwarden/federation/federated-members.component").then(
            (m) => m.FederatedMembersComponent,
          ),
        canActivate: [organizationPermissionsGuard((o) => o.canManageUsers)],
        data: { titleId: "cwFederatedMembers" },
      },
      {
        path: "billing",
        loadChildren: () =>
          import("../../billing/organizations/organization-billing.module").then(
            (m) => m.OrganizationBillingModule,
          ),
      },
    ],
  },
];

function getOrganizationRoute(organization: Organization): string | undefined {
  if (canAccessVaultTab(organization)) {
    return "vault";
  }
  if (canAccessMembersTab(organization)) {
    return "members";
  }
  if (canAccessGroupsTab(organization)) {
    return "groups";
  }
  if (canAccessReportingTab(organization)) {
    return "reporting";
  }
  if (canAccessSettingsTab(organization)) {
    return "settings";
  }
  return undefined;
}

@NgModule({
  imports: [RouterModule.forChild(routes)],
  exports: [RouterModule],
})
export class OrganizationsRoutingModule {}
