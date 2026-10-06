// Cloudwarden: the invited user's side of federation (docs/federation.md, web/NOTICE.md). Lists
// invitations from organisations hosted on paired instances, to accept or decline, and the
// federated organisations the account already belongs to.
import { DatePipe } from "@angular/common";
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  inject,
  signal,
} from "@angular/core";

import { SyncService } from "@bitwarden/common/platform/sync";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import {
  FederatedInvitation,
  FederatedMembership,
  FederationApiService,
} from "./federation-api.service";

@Component({
  selector: "cw-federated-invitations",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, DatePipe],
  template: `
    <app-header></app-header>
    <bit-container>
      @if (disabled()) {
        <bit-callout type="info" data-testid="cw-fed-disabled">{{
          "cwFedDisabled" | i18n
        }}</bit-callout>
      } @else {
        <p bitTypography="body1">{{ "cwFedInvitationsDesc" | i18n }}</p>
        <p
          bitTypography="body2"
          class="tw-text-muted"
          data-testid="cw-fed-invitations-explain"
        >
          {{ "cwFedInvitationsExplain" | i18n }}
        </p>
        @if (error()) {
          <bit-callout type="danger">{{ error() }}</bit-callout>
        }
        <bit-table>
          <ng-container header>
            <tr>
              <th bitCell>{{ "organization" | i18n }}</th>
              <th bitCell>{{ "cwFedHomeInstance" | i18n }}</th>
              <th bitCell>{{ "cwFedInvitedBy" | i18n }}</th>
              <th bitCell>{{ "status" | i18n }}</th>
              <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
            </tr>
          </ng-container>
          <ng-template body>
            @for (i of invitations(); track i.id) {
              <tr bitRow>
                <td bitCell>
                  {{ i.organizationName }}
                  @if (i.verified === false) {
                    <div
                      class="tw-text-xs tw-text-warning"
                      data-testid="cw-fed-invite-unverified"
                    >
                      {{ "cwFedInvitationUnverified" | i18n: i.peerDomain }}
                    </div>
                  }
                  @if (!i.peerActive && i.status === "pending") {
                    <div
                      class="tw-text-xs tw-text-danger"
                      data-testid="cw-fed-invite-blocked"
                    >
                      {{ "cwFedInvitationBlocked" | i18n: i.peerDomain }}
                    </div>
                  }
                </td>
                <td bitCell>{{ i.peerDomain }}</td>
                <td bitCell>{{ i.inviterEmail }}</td>
                <td bitCell>
                  {{ i.creationDate | date: "short" }} · {{ i.status }}
                </td>
                <td bitCell class="tw-text-right">
                  @if (i.status === "pending") {
                    <div class="tw-flex tw-justify-end tw-gap-1">
                      <button
                        type="button"
                        bitButton
                        buttonType="primary"
                        [disabled]="!i.peerActive"
                        (click)="respond(i, true)"
                      >
                        {{ "accept" | i18n }}
                      </button>
                      <button
                        type="button"
                        bitButton
                        buttonType="secondary"
                        (click)="respond(i, false)"
                      >
                        {{ "decline" | i18n }}
                      </button>
                    </div>
                  }
                </td>
              </tr>
            }
          </ng-template>
        </bit-table>
        <bit-section class="tw-mt-6">
          <h2 bitTypography="h4">{{ "cwFedMemberships" | i18n }}</h2>
          <bit-table>
            <ng-container header>
              <tr>
                <th bitCell>{{ "organization" | i18n }}</th>
                <th bitCell>{{ "cwFedHomeInstance" | i18n }}</th>
                <th bitCell>{{ "cwFedLastSynced" | i18n }}</th>
              </tr>
            </ng-container>
            <ng-template body>
              @for (m of memberships(); track m.organizationId) {
                <tr bitRow>
                  <td bitCell>{{ m.name }}</td>
                  <td bitCell>
                    {{ m.peerDomain }}
                    @if (m.peerStatus !== "active") {
                      <span bitBadge variant="danger">{{
                        "cwFedSuspended" | i18n
                      }}</span>
                    }
                  </td>
                  <td bitCell>{{ m.syncedDate | date: "short" }}</td>
                </tr>
              }
            </ng-template>
          </bit-table>
        </bit-section>
      }
    </bit-container>
  `,
})
export class FederatedInvitationsComponent implements OnInit {
  private readonly api = inject(FederationApiService);
  private readonly syncService = inject(SyncService);
  private readonly toastService = inject(ToastService);
  private readonly i18n = inject(I18nService);

  protected readonly disabled = signal(false);
  protected readonly invitations = signal<FederatedInvitation[]>([]);
  protected readonly memberships = signal<FederatedMembership[]>([]);
  protected readonly error = signal<string | null>(null);

  async ngOnInit() {
    await this.load();
  }

  private async load() {
    try {
      const [inv, mem] = await Promise.all([
        this.api.invitations(),
        this.api.memberships(),
      ]);
      this.invitations.set(inv.data);
      this.memberships.set(mem.data);
      this.error.set(null);
    } catch (e) {
      if ((e as { statusCode?: number })?.statusCode === 404) {
        this.disabled.set(true);
      } else {
        this.error.set((e as Error)?.message ?? String(e));
      }
    }
  }

  protected async respond(i: FederatedInvitation, accept: boolean) {
    try {
      await this.api.respond(i.id, accept);
      this.toastService.showToast({
        variant: "success",
        message: this.i18n.t(
          accept ? "cwFedAccepted" : "cwFedDeclined",
          i.organizationName,
        ),
      });
      if (accept) {
        await this.syncService.fullSync(true);
      }
    } catch (e) {
      this.toastService.showToast({
        variant: "error",
        message: (e as Error)?.message ?? "",
      });
    }
    await this.load();
  }
}
