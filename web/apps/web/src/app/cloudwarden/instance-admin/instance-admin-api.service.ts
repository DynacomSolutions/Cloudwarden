// Cloudwarden: client for the instance admin API (/api/cloudwarden/admin/*, web/NOTICE.md).
// Uses the vault's authenticated ApiService, so the access token never leaves the client's own
// request pipeline.
import { Injectable, inject } from "@angular/core";
import { BehaviorSubject, Observable, from, map, of, shareReplay, switchMap, catchError } from "rxjs";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";

export interface AdminCounts {
  [key: string]: number;
}

export interface AdminOverview {
  counts: AdminCounts;
  [key: string]: unknown;
}

export interface AdminUser {
  id: string;
  email: string;
  name: string | null;
  createdAt: string | null;
  lastActive: string | null;
  itemCount: number;
  twoFactorProviders: { type: number; name: string }[];
  enabled: boolean;
  emailVerified: boolean;
}

export interface AdminUserPage {
  data: AdminUser[];
  page: number;
  pageSize: number;
  total: number;
  hasMore: boolean;
}

export interface AdminInvitation {
  email: string;
  createdAt: string | null;
}

export interface AdminOrganization {
  id: string;
  name: string;
  createdAt: string | null;
  memberCount: number;
  itemCount: number;
}

export type AdminUserAction = "disable" | "enable" | "deauthorize" | "remove-2fa";

const ADMIN = "/cloudwarden/admin";

@Injectable({ providedIn: "root" })
export class InstanceAdminApiService {
  private readonly apiService = inject(ApiService);
  private readonly accountService = inject(AccountService);
  private readonly refresh$ = new BehaviorSubject<void>(undefined);

  /** True when the signed in user is an instance admin. Errors count as "not an admin". */
  readonly isAdmin$: Observable<boolean> = this.accountService.activeAccount$.pipe(
    switchMap((account) =>
      account == null
        ? of(false)
        : this.refresh$.pipe(
            switchMap(() =>
              from(this.apiService.send("GET", "/cloudwarden/me", null, true, true)).pipe(
                map((r: { isAdmin?: boolean }) => r?.isAdmin === true),
                catchError(() => of(false)),
              ),
            ),
          ),
    ),
    shareReplay({ bufferSize: 1, refCount: true }),
  );

  overview(): Promise<AdminOverview> {
    return this.apiService.send("GET", `${ADMIN}/overview`, null, true, true);
  }

  diagnostics(): Promise<Record<string, unknown>> {
    return this.apiService.send("GET", `${ADMIN}/diagnostics`, null, true, true);
  }

  users(page: number, pageSize = 50): Promise<AdminUserPage> {
    return this.apiService.send(
      "GET",
      `${ADMIN}/users?page=${page}&pageSize=${pageSize}`,
      null,
      true,
      true,
    );
  }

  userAction(id: string, action: AdminUserAction): Promise<void> {
    return this.apiService.send(
      "POST",
      `${ADMIN}/users/${encodeURIComponent(id)}/${action}`,
      null,
      true,
      false,
    );
  }

  deleteUser(id: string): Promise<void> {
    return this.apiService.send(
      "DELETE",
      `${ADMIN}/users/${encodeURIComponent(id)}`,
      null,
      true,
      false,
    );
  }

  invitations(): Promise<{ data: AdminInvitation[] }> {
    return this.apiService.send("GET", `${ADMIN}/invitations`, null, true, true);
  }

  invite(email: string): Promise<AdminInvitation & { emailStatus?: string }> {
    return this.apiService.send("POST", `${ADMIN}/invitations`, { email }, true, true);
  }

  revokeInvitation(email: string): Promise<void> {
    return this.apiService.send(
      "DELETE",
      `${ADMIN}/invitations/${encodeURIComponent(email)}`,
      null,
      true,
      false,
    );
  }

  organizations(): Promise<{ data: AdminOrganization[] }> {
    return this.apiService.send("GET", `${ADMIN}/organizations`, null, true, true);
  }

  deleteOrganization(id: string): Promise<void> {
    return this.apiService.send(
      "DELETE",
      `${ADMIN}/organizations/${encodeURIComponent(id)}`,
      null,
      true,
      false,
    );
  }
}
