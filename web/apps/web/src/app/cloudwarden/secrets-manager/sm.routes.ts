// Cloudwarden: Secrets Manager routes, mounted at /sm/:organizationId (web/NOTICE.md).
import { Routes } from "@angular/router";

import { RouteDataProperties } from "../../core/router.service";

import { SmLayoutComponent } from "./sm-layout.component";
import { SmMachineAccountComponent } from "./sm-machine-account.component";
import { SmMachineAccountsComponent } from "./sm-machine-accounts.component";
import { SmProjectComponent } from "./sm-project.component";
import { SmProjectsComponent } from "./sm-projects.component";
import { SmSecretsPageComponent } from "./sm-secrets.component";
import { smOrganizationGuard } from "./sm.guard";

export const smRoutes: Routes = [
  {
    path: ":organizationId",
    component: SmLayoutComponent,
    canActivate: [smOrganizationGuard],
    children: [
      { path: "", pathMatch: "full", redirectTo: "projects" },
      {
        path: "projects",
        component: SmProjectsComponent,
        data: { titleId: "projects" } satisfies RouteDataProperties,
      },
      {
        path: "projects/:projectId",
        component: SmProjectComponent,
        data: { titleId: "project" } satisfies RouteDataProperties,
      },
      {
        path: "secrets",
        component: SmSecretsPageComponent,
        data: { titleId: "secrets" } satisfies RouteDataProperties,
      },
      {
        path: "machine-accounts",
        component: SmMachineAccountsComponent,
        data: { titleId: "machineAccounts" } satisfies RouteDataProperties,
      },
      {
        path: "machine-accounts/:machineAccountId",
        component: SmMachineAccountComponent,
        data: { titleId: "machineAccount" } satisfies RouteDataProperties,
      },
    ],
  },
];
