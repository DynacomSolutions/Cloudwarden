// Cloudwarden: client for `POST /api/cloudwarden/registration/redeem` (docs/emailless.md).
import { Injectable, inject } from "@angular/core";

import { ApiService } from "@bitwarden/common/abstractions/api.service";

@Injectable({ providedIn: "root" })
export class InstanceSetupApiService {
  private readonly apiService = inject(ApiService);

  /** Exchanges a setup or invite code for the registration token of the finish sign up page. */
  async redeem(email: string, code: string): Promise<string> {
    const r = await this.apiService.send(
      "POST",
      "/cloudwarden/registration/redeem",
      { email, code },
      false,
      true,
    );
    const token = r?.emailVerificationToken;
    if (typeof token !== "string" || token === "") {
      throw new Error("The server did not return a registration token.");
    }
    return token;
  }
}
