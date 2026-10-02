// Cloudwarden: the Secrets Manager pages open only for an organisation that uses Secrets Manager
// and a member with access to it (web/NOTICE.md). The server enforces this on every request; the
// guard only keeps others out of the UI.
import { inject } from "@angular/core";
import { CanActivateFn, Router } from "@angular/router";
import { firstValueFrom } from "rxjs";

import { OrganizationService } from "@bitwarden/common/admin-console/abstractions/organization/organization.service.abstraction";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";

export const smOrganizationGuard: CanActivateFn = async (route) => {
  const router = inject(Router);
  const accountService = inject(AccountService);
  const organizationService = inject(OrganizationService);
  const userId = await firstValueFrom(accountService.activeAccount$.pipe(getUserId));
  const orgs = await firstValueFrom(organizationService.organizations$(userId));
  const org = orgs.find((o) => o.id === route.paramMap.get("organizationId"));
  if (org?.canAccessSecretsManager && org.enabled) {
    return true;
  }
  // An unknown or inaccessible id: fall back to the first organisation with access, if any.
  const first = orgs.find((o) => o.canAccessSecretsManager && o.enabled);
  return first ? router.createUrlTree(["/sm", first.id]) : router.createUrlTree(["/vault"]);
};
