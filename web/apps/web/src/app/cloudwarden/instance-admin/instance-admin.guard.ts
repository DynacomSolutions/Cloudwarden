// Cloudwarden: only instance admins may open the instance admin pages (web/NOTICE.md).
// The server enforces this on every request; the guard only keeps others out of the UI.
import { inject } from "@angular/core";
import { CanActivateFn, Router } from "@angular/router";
import { map, take } from "rxjs";

import { InstanceAdminApiService } from "./instance-admin-api.service";

export const instanceAdminGuard: CanActivateFn = () => {
  const router = inject(Router);
  return inject(InstanceAdminApiService).isAdmin$.pipe(
    take(1),
    map((isAdmin) => (isAdmin ? true : router.createUrlTree(["/vault"]))),
  );
};
