// Cloudwarden: Admin Console device approvals (TASKS #241, web/NOTICE.md). Written from scratch for
// the Cloudwarden API contract; the upstream page is not open source.
//
// Approving a request: fetch the member's account recovery details, unwrap the organisation private
// key with the organisation key, decrypt the member's user key with it, and encrypt the user key to
// the requesting device's public key. Only that ciphertext is sent to the server.
import { DatePipe } from "@angular/common";
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { ActivatedRoute } from "@angular/router";
import { firstValueFrom, map } from "rxjs";

import { AuthRequestServiceAbstraction } from "@bitwarden/auth/common";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { Utils } from "@bitwarden/common/platform/misc/utils";
import { OrganizationId } from "@bitwarden/common/types/guid";
import { DialogService, ToastService } from "@bitwarden/components";
import { KeyService } from "@bitwarden/key-management";
import { EncryptService } from "@bitwarden/legacy-crypto";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import { DeviceApprovalsApiService, PendingDeviceRequest } from "./device-approvals-api.service";
import { rewrapUserKey } from "./rewrap";

interface Row extends PendingDeviceRequest {
  fingerprint: string;
}

@Component({
  selector: "cw-device-approvals",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, DatePipe],
  template: `
    <app-header>
      @if (rows().length > 0) {
        <button type="button" bitButton buttonType="danger" (click)="denyAll()">
          {{ "denyAllRequests" | i18n }}
        </button>
      }
    </app-header>
    <bit-container>
      <p bitTypography="body1">{{ "deviceApprovalsDesc" | i18n }}</p>
      @if (error()) {
        <bit-callout type="danger">{{ error() }}</bit-callout>
      }
      @if (loading()) {
        <i class="bwi bwi-spinner bwi-spin" aria-hidden="true"></i>
      } @else if (rows().length === 0) {
        <div class="tw-mt-6 tw-text-center" data-testid="device-approvals-empty">
          <h2 bitTypography="h4">{{ "noDeviceRequests" | i18n }}</h2>
          <p bitTypography="body2" class="tw-text-muted">{{ "noDeviceRequestsDesc" | i18n }}</p>
        </div>
      } @else {
        <bit-table>
          <ng-container header>
            <tr>
              <th bitCell>{{ "member" | i18n }}</th>
              <th bitCell>{{ "deviceInfo" | i18n }}</th>
              <th bitCell>{{ "time" | i18n }}</th>
              <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
            </tr>
          </ng-container>
          <ng-template body>
            @for (r of rows(); track r.id) {
              <tr bitRow data-testid="device-approval-row">
                <td bitCell>
                  <div>{{ r.email }}</div>
                  <div class="tw-text-sm tw-text-muted">
                    {{ "fingerprintPhrase" | i18n }}
                    <code class="tw-font-mono">{{ r.fingerprint }}</code>
                  </div>
                </td>
                <td bitCell>
                  <div>{{ r.requestDeviceType }}</div>
                  @if (r.requestIpAddress) {
                    <div class="tw-text-sm tw-text-muted">{{ r.requestIpAddress }}</div>
                  }
                </td>
                <td bitCell>{{ r.creationDate | date: "medium" }}</td>
                <td bitCell class="tw-text-right tw-whitespace-nowrap">
                  <button
                    type="button"
                    bitButton
                    buttonType="primary"
                    class="tw-mr-2"
                    (click)="approve(r)"
                  >
                    {{ "approveRequest" | i18n }}
                  </button>
                  <button type="button" bitButton buttonType="danger" (click)="deny(r)">
                    {{ "denyRequest" | i18n }}
                  </button>
                </td>
              </tr>
            }
          </ng-template>
        </bit-table>
      }
    </bit-container>
  `,
})
export class DeviceApprovalsComponent implements OnInit {
  private readonly api = inject(DeviceApprovalsApiService);
  private readonly route = inject(ActivatedRoute);
  private readonly accountService = inject(AccountService);
  private readonly keyService = inject(KeyService);
  private readonly encryptService = inject(EncryptService);
  private readonly authRequestService = inject(AuthRequestServiceAbstraction);
  private readonly dialogService = inject(DialogService);
  private readonly toastService = inject(ToastService);
  private readonly i18n = inject(I18nService);

  protected readonly rows = signal<Row[]>([]);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);

  private get orgId(): OrganizationId {
    return this.route.snapshot.params.organizationId as OrganizationId;
  }

  async ngOnInit() {
    await this.load();
  }

  private async load() {
    try {
      const pending = await this.api.pending(this.orgId);
      const rows: Row[] = [];
      for (const p of pending) {
        rows.push({
          ...p,
          fingerprint: await this.authRequestService.getFingerprintPhrase(
            p.email,
            Utils.fromB64ToArray(p.publicKey),
          ),
        });
      }
      this.rows.set(rows);
      this.error.set(null);
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    } finally {
      this.loading.set(false);
    }
  }

  protected async approve(r: Row) {
    try {
      const userId = await firstValueFrom(this.accountService.activeAccount$.pipe(getUserId));
      const orgKey = await firstValueFrom(
        this.keyService.orgKeys$(userId).pipe(map((keys) => keys?.[this.orgId] ?? null)),
      );
      if (orgKey == null) {
        throw new Error("No organization key found");
      }
      const details = await this.api.recoveryDetails(this.orgId, r.organizationUserId);
      const encryptedUserKey = await rewrapUserKey(this.encryptService, {
        orgKey,
        encryptedOrgPrivateKey: details.encryptedPrivateKey,
        resetPasswordKey: details.resetPasswordKey,
        devicePublicKey: r.publicKey,
      });
      await this.api.approve(this.orgId, r.id, encryptedUserKey);
      this.toastService.showToast({
        variant: "success",
        message: this.i18n.t("loginRequestApproved"),
      });
    } catch (e) {
      this.toastService.showToast({ variant: "error", message: (e as Error)?.message ?? "" });
    }
    await this.load();
  }

  protected async deny(r: Row) {
    await this.denyIds([r.id], "loginRequestDenied");
  }

  protected async denyAll() {
    const ok = await this.dialogService.openSimpleDialog({
      title: { key: "denyAllRequests" },
      content: { key: "deviceApprovalsDesc" },
      type: "warning",
    });
    if (ok) {
      await this.denyIds(
        this.rows().map((r) => r.id),
        "allLoginRequestsDenied",
      );
    }
  }

  private async denyIds(ids: string[], message: string) {
    try {
      await this.api.deny(this.orgId, ids);
      this.toastService.showToast({ variant: "success", message: this.i18n.t(message) });
    } catch (e) {
      this.toastService.showToast({ variant: "error", message: (e as Error)?.message ?? "" });
    }
    await this.load();
  }
}
