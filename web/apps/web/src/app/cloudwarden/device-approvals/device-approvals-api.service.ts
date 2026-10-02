// Cloudwarden: device approvals client (TASKS #241, web/NOTICE.md). Written from the Cloudwarden
// API contract (docs/api/openapi.yaml); nothing here comes from bitwarden_license.
import { Injectable, inject } from "@angular/core";

import { ApiService } from "@bitwarden/common/abstractions/api.service";

export interface PendingDeviceRequest {
  id: string;
  userId: string;
  organizationUserId: string;
  email: string;
  publicKey: string;
  requestDeviceIdentifier: string;
  requestDeviceType: string;
  requestIpAddress: string | null;
  creationDate: string;
  expirationDate: string;
}

export interface RecoveryDetails {
  resetPasswordKey: string;
  encryptedPrivateKey: string;
}

const base = (orgId: string) => `/organizations/${encodeURIComponent(orgId)}`;

@Injectable({ providedIn: "root" })
export class DeviceApprovalsApiService {
  private readonly api = inject(ApiService);

  async pending(orgId: string): Promise<PendingDeviceRequest[]> {
    const r = await this.api.send("GET", `${base(orgId)}/auth-requests`, null, true, true);
    return (r?.data ?? r?.Data ?? []) as PendingDeviceRequest[];
  }

  recoveryDetails(orgId: string, organizationUserId: string): Promise<RecoveryDetails> {
    return this.api.send(
      "GET",
      `${base(orgId)}/users/${encodeURIComponent(organizationUserId)}/reset-password-details`,
      null,
      true,
      true,
    );
  }

  approve(orgId: string, requestId: string, encryptedUserKey: string): Promise<void> {
    return this.api.send(
      "POST",
      `${base(orgId)}/auth-requests/${encodeURIComponent(requestId)}`,
      { requestApproved: true, encryptedUserKey },
      true,
      false,
    );
  }

  deny(orgId: string, ids: string[]): Promise<void> {
    return this.api.send("POST", `${base(orgId)}/auth-requests/deny`, { ids }, true, false);
  }
}
