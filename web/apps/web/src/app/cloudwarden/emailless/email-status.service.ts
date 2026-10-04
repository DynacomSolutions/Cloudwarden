// Cloudwarden: whether the server can send email (web/NOTICE.md, docs/emailless.md).
// Read from `/api/config` (`cloudwarden.email`). Any failure counts as "mail works" so the
// upstream behaviour is kept whenever the answer is unknown.
import { Injectable, inject } from "@angular/core";

import { ApiService } from "@bitwarden/common/abstractions/api.service";

export type EmailFeatureState = "available" | "link" | "refused" | "skipped" | "manual";

export interface EmailFeature {
  id: string;
  label: string;
  state: EmailFeatureState;
}

export interface EmailStatus {
  configured: boolean;
  features: EmailFeature[];
}

@Injectable({ providedIn: "root" })
export class EmailStatusService {
  private readonly apiService = inject(ApiService, { optional: true });
  private cached: Promise<EmailStatus | null> | null = null;

  /** The status block of `/api/config`, or null when it cannot be read. */
  status(): Promise<EmailStatus | null> {
    if (this.cached == null) {
      this.cached = this.fetch();
    }
    return this.cached;
  }

  /** False only when the server says it cannot send email. */
  async configured(): Promise<boolean> {
    return (await this.status())?.configured !== false;
  }

  private async fetch(): Promise<EmailStatus | null> {
    try {
      const config = await this.apiService?.send("GET", "/config", null, false, true);
      const email = config?.cloudwarden?.email;
      return typeof email?.configured === "boolean" ? (email as EmailStatus) : null;
    } catch {
      return null;
    }
  }
}
