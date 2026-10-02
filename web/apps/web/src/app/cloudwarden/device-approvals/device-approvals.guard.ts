// Cloudwarden: who sees device approvals (TASKS #241, web/NOTICE.md). Upstream shows the page only
// for organisations using SSO with trusted devices; Cloudwarden answers admin approval requests for
// any member enrolled in account recovery, so it is shown to everyone who manages account recovery.
import { Organization } from "@bitwarden/common/admin-console/models/domain/organization";

export const cwCanManageDeviceApprovals = (o: Organization) =>
  o.canManageDeviceApprovals || (o.canManageUsersPassword && o.useResetPassword);
