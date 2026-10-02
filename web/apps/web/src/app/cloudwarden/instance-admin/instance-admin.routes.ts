// Cloudwarden: instance admin routes, mounted at /instance-admin (web/NOTICE.md).
import { Routes } from "@angular/router";

import { RouteDataProperties } from "../../core/router.service";

import { InstanceAdminInvitationsComponent } from "./instance-admin-invitations.component";
import { InstanceAdminOrganizationsComponent } from "./instance-admin-organizations.component";
import { InstanceAdminOverviewComponent } from "./instance-admin-overview.component";
import { InstanceAdminUsersComponent } from "./instance-admin-users.component";
import { instanceAdminGuard } from "./instance-admin.guard";

export const instanceAdminRoutes: Routes = [
  {
    path: "",
    canActivate: [instanceAdminGuard],
    children: [
      { path: "", pathMatch: "full", redirectTo: "overview" },
      {
        path: "overview",
        component: InstanceAdminOverviewComponent,
        data: { titleId: "cwOverview", mode: "overview" } satisfies RouteDataProperties & {
          mode: string;
        },
      },
      {
        path: "users",
        component: InstanceAdminUsersComponent,
        data: { titleId: "cwUsers" } satisfies RouteDataProperties,
      },
      {
        path: "invitations",
        component: InstanceAdminInvitationsComponent,
        data: { titleId: "cwInvitations" } satisfies RouteDataProperties,
      },
      {
        path: "organizations",
        component: InstanceAdminOrganizationsComponent,
        data: { titleId: "organizations" } satisfies RouteDataProperties,
      },
      {
        path: "diagnostics",
        component: InstanceAdminOverviewComponent,
        data: { titleId: "cwDiagnostics", mode: "diagnostics" } satisfies RouteDataProperties & {
          mode: string;
        },
      },
    ],
  },
];
