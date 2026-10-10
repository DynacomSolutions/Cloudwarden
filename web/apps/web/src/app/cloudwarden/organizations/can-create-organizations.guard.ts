// Cloudwarden: only instance owners and admins create organisations (web/NOTICE.md). The server
// enforces this; the guard keeps everyone else off the create pages and out of dead-end links.
import { inject } from "@angular/core";
import { CanActivateFn, Router } from "@angular/router";
import { map, take } from "rxjs";

import { InstanceAdminApiService } from "../instance-admin/instance-admin-api.service";

export const canCreateOrganizationsGuard: CanActivateFn = () => {
  const router = inject(Router);
  return inject(InstanceAdminApiService).canCreateOrganizations$.pipe(
    take(1),
    map((allowed) => (allowed ? true : router.createUrlTree(["/vault"]))),
  );
};
