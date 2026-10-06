// Cloudwarden: instance admin, trusted workspaces (docs/federation.md, web/NOTICE.md). A trusted
// workspace is a signed trust channel with another Cloudwarden instance; it links no organisations.
// Admins add one by domain (or approve a request made from a collection's Access dialog), compare
// fingerprints with the other admin out of band, approve, and can check, suspend, resume or remove
// it. The list shows which organisations currently share collections through each workspace.
import { DatePipe } from "@angular/common";
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  inject,
  signal,
} from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import {
  FederationApiService,
  FederationDescriptor,
  FederationEvent,
  FederationPeer,
  TrustSettings,
  sameFingerprint,
} from "./federation-api.service";
import {
  ScannedWorkspace,
  WorkspaceQrScanComponent,
} from "./workspace-qr-scan.component";
import { WorkspaceQrShowComponent } from "./workspace-qr-show.component";
import { normalizeFingerprint, sameDomain } from "./workspace-qr";

@Component({
  selector: "cw-instance-admin-federation",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    SharedModule,
    HeaderModule,
    DatePipe,
    WorkspaceQrShowComponent,
    WorkspaceQrScanComponent,
  ],
  template: `
    <app-header></app-header>
    <bit-container>
      @if (disabled()) {
        <bit-callout type="info" data-testid="cw-fed-disabled">{{
          "cwFedDisabled" | i18n
        }}</bit-callout>
      } @else {
        <p bitTypography="body1">{{ "cwFedAdminDesc" | i18n }}</p>
        @if (identity(); as id) {
          <bit-section>
            <h2 bitTypography="h4">{{ "cwFedThisInstance" | i18n }}</h2>
            <p bitTypography="body2">{{ id.domain }}</p>
            <p bitTypography="body2">
              {{ "cwFedFingerprint" | i18n }}:
              <code class="tw-break-all" data-testid="cw-fed-own-fingerprint">{{
                id.fingerprint
              }}</code>
            </p>
            <cw-workspace-qr-show
              [domain]="id.domain"
              [fingerprint]="id.fingerprint"
            ></cw-workspace-qr-show>
          </bit-section>
        }
        @if (trust(); as t) {
          <bit-section data-testid="cw-fed-trust">
            <h2 bitTypography="h4">{{ "cwFedIncomingTitle" | i18n }}</h2>
            <label class="tw-flex tw-items-start tw-gap-2">
              <input
                type="checkbox"
                [checked]="t.requireIncomingApproval"
                (change)="setRequire($any($event.target).checked)"
                data-testid="cw-fed-require-approval"
              />
              <span>
                {{ "cwFedRequireApproval" | i18n }}
                <span class="tw-block tw-text-xs tw-text-muted">{{
                  "cwFedRequireApprovalHint" | i18n
                }}</span>
              </span>
            </label>
            <form
              [formGroup]="blockForm"
              [bitSubmit]="addBlock"
              class="tw-mt-3 tw-flex tw-flex-col tw-gap-2 sm:tw-flex-row sm:tw-items-start"
            >
              <bit-form-field class="tw-grow tw-max-w-md">
                <bit-label>{{ "cwFedBlockRule" | i18n }}</bit-label>
                <input
                  bitInput
                  type="text"
                  formControlName="rule"
                  placeholder="*.example.com"
                  data-testid="cw-fed-block-rule"
                />
                <bit-hint>{{ "cwFedBlockRuleHint" | i18n }}</bit-hint>
              </bit-form-field>
              <button
                type="submit"
                bitButton
                bitFormButton
                buttonType="secondary"
                class="sm:tw-mt-6"
              >
                {{ "cwFedBlock" | i18n }}
              </button>
            </form>
            @if (t.blockedDomains.length > 0) {
              <h3 bitTypography="h5" class="tw-mt-3">
                {{ "cwFedBlocked" | i18n }}
              </h3>
              <ul data-testid="cw-fed-blocked">
                @for (b of t.blockedDomains; track b.domain) {
                  <li class="tw-flex tw-items-center tw-gap-2">
                    <span class="tw-break-all">{{ b.domain }}</span>
                    <button
                      type="button"
                      bitButton
                      buttonType="secondary"
                      size="small"
                      (click)="unblock(b.domain)"
                    >
                      {{ "cwFedUnblock" | i18n }}
                    </button>
                  </li>
                }
              </ul>
            }
          </bit-section>
        }
        <bit-section>
          <form
            [formGroup]="form"
            [bitSubmit]="add"
            class="tw-flex tw-flex-col tw-items-stretch tw-gap-2 sm:tw-flex-row sm:tw-items-start"
          >
            <bit-form-field class="tw-grow tw-max-w-md">
              <bit-label>{{ "cwFedPeerDomain" | i18n }}</bit-label>
              <input
                bitInput
                type="text"
                formControlName="domain"
                placeholder="vault.example.com"
              />
            </bit-form-field>
            <button
              type="submit"
              bitButton
              bitFormButton
              buttonType="primary"
              class="tw-mt-6"
            >
              {{ "cwFedAddPeer" | i18n }}
            </button>
          </form>
          <div class="tw-mt-2 tw-max-w-md">
            <cw-workspace-qr-scan
              (scanned)="scannedForAdd($event)"
            ></cw-workspace-qr-scan>
          </div>
        </bit-section>
        @if (error()) {
          <bit-callout type="danger">{{ error() }}</bit-callout>
        }
        <bit-table>
          <ng-container header>
            <tr>
              <th bitCell>{{ "cwFedPeer" | i18n }}</th>
              <th bitCell>{{ "status" | i18n }}</th>
              <th bitCell>{{ "cwFedLastSeen" | i18n }}</th>
              <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
            </tr>
          </ng-container>
          <ng-template body>
            @for (p of peers(); track p.id) {
              <tr bitRow>
                <td bitCell>
                  <div>{{ p.domain }}</div>
                  <div class="tw-text-muted tw-text-xs tw-break-all">
                    {{ p.fingerprint }}
                  </div>
                  @if (p.lastError) {
                    <div class="tw-text-danger tw-text-xs">
                      {{ p.lastError }}
                    </div>
                  }
                  @if (p.inboundOnly) {
                    <div class="tw-text-xs" data-testid="cw-fed-inbound-only">
                      {{ "cwFedIncomingOnly" | i18n }}
                    </div>
                  } @else if (p.approvedByEmail) {
                    <div class="tw-text-xs" data-testid="cw-fed-approved-by">
                      {{ "cwFedApprovedBy" | i18n: p.approvedByEmail }}
                    </div>
                  }
                  @if (p.requestedByEmail) {
                    <div class="tw-text-xs" data-testid="cw-fed-requested-by">
                      {{ "cwFedRequestedBy" | i18n: p.requestedByEmail }}
                    </div>
                  }
                  @if ((p.queued ?? []).length > 0) {
                    <div class="tw-mt-1 tw-text-xs" data-testid="cw-fed-queued">
                      <div class="tw-font-semibold">
                        {{ "cwFedQueuedBehind" | i18n }}
                      </div>
                      @for (
                        q of p.queued;
                        track q.organizationId + q.requestedByEmail
                      ) {
                        <div>
                          {{
                            "cwFedQueuedLine"
                              | i18n
                                : q.organizationName
                                : q.collections
                                : q.people
                          }}
                        </div>
                      }
                    </div>
                  }
                  <div class="tw-mt-1 tw-text-xs" data-testid="cw-fed-sharing">
                    @if ((p.sharing ?? []).length === 0) {
                      <span class="tw-text-muted">{{
                        "cwFedNothingShared" | i18n
                      }}</span>
                    } @else {
                      <div class="tw-font-semibold">
                        {{ "cwFedSharedCollections" | i18n }}
                      </div>
                      @for (o of p.sharing; track o.organizationId) {
                        <div>
                          {{
                            "cwFedSharedLine"
                              | i18n
                                : o.organizationName
                                : o.collections
                                : o.people
                          }}
                        </div>
                      }
                    }
                  </div>
                </td>
                <td bitCell>
                  <span bitBadge [variant]="badge(p)">{{
                    statusKey(p) | i18n
                  }}</span>
                </td>
                <td bitCell>{{ p.lastSeenDate | date: "short" }}</td>
                <td bitCell class="tw-text-right">
                  <div class="tw-flex tw-flex-wrap tw-justify-end tw-gap-1">
                    @if (!p.localApproved || p.inboundOnly) {
                      <button
                        type="button"
                        bitButton
                        buttonType="primary"
                        (click)="approving.set(p.id)"
                      >
                        {{ "cwFedApprove" | i18n }}
                      </button>
                    }
                    <button
                      type="button"
                      bitButton
                      buttonType="secondary"
                      (click)="check(p)"
                    >
                      {{ "cwFedCheck" | i18n }}
                    </button>
                    @if (p.status === "suspended") {
                      <button
                        type="button"
                        bitButton
                        buttonType="secondary"
                        (click)="act(p, 'resume')"
                      >
                        {{ "cwFedResume" | i18n }}
                      </button>
                    } @else {
                      <button
                        type="button"
                        bitButton
                        buttonType="secondary"
                        (click)="act(p, 'suspend')"
                      >
                        {{ "cwFedSuspend" | i18n }}
                      </button>
                    }
                    <button
                      type="button"
                      bitButton
                      buttonType="danger"
                      (click)="remove(p)"
                    >
                      {{ "remove" | i18n }}
                    </button>
                  </div>
                  @if (approving() === p.id) {
                    <form
                      [formGroup]="approveForm"
                      [bitSubmit]="approve"
                      class="tw-mt-2 tw-text-left"
                    >
                      <bit-form-field>
                        <bit-label>{{
                          "cwFedEnterFingerprint" | i18n
                        }}</bit-label>
                        <input
                          bitInput
                          type="text"
                          formControlName="fingerprint"
                        />
                        <bit-hint>{{
                          "cwFedFingerprintHint" | i18n: p.domain
                        }}</bit-hint>
                      </bit-form-field>
                      <button
                        type="submit"
                        bitButton
                        bitFormButton
                        buttonType="primary"
                      >
                        {{ "cwFedApprove" | i18n }}
                      </button>
                      <div class="tw-mt-2">
                        <cw-workspace-qr-scan
                          (scanned)="scannedForApprove($event, p)"
                        ></cw-workspace-qr-scan>
                      </div>
                    </form>
                  }
                </td>
              </tr>
            }
          </ng-template>
        </bit-table>
        <bit-section class="tw-mt-6">
          <h2 bitTypography="h4">{{ "cwFedEvents" | i18n }}</h2>
          <bit-table>
            <ng-container header>
              <tr>
                <th bitCell>{{ "date" | i18n }}</th>
                <th bitCell>{{ "event" | i18n }}</th>
                <th bitCell>{{ "cwFedPeer" | i18n }}</th>
              </tr>
            </ng-container>
            <ng-template body>
              @for (e of events(); track $index) {
                <tr bitRow>
                  <td bitCell>{{ e.date | date: "short" }}</td>
                  <td bitCell>{{ e.name }}</td>
                  <td bitCell>{{ e.peer }}</td>
                </tr>
              }
            </ng-template>
          </bit-table>
        </bit-section>
      }
    </bit-container>
  `,
})
export class InstanceAdminFederationComponent implements OnInit {
  private readonly api = inject(FederationApiService);
  private readonly dialogService = inject(DialogService);
  private readonly toastService = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly fb = inject(FormBuilder);

  protected readonly disabled = signal(false);
  protected readonly identity = signal<FederationDescriptor | null>(null);
  protected readonly peers = signal<FederationPeer[]>([]);
  protected readonly events = signal<FederationEvent[]>([]);
  protected readonly trust = signal<TrustSettings | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly approving = signal<string | null>(null);
  protected readonly form = this.fb.group({
    domain: ["", [Validators.required]],
  });
  protected readonly blockForm = this.fb.group({
    rule: ["", [Validators.required]],
  });
  protected readonly approveForm = this.fb.group({
    fingerprint: ["", [Validators.required]],
  });

  async ngOnInit() {
    await this.load();
  }

  protected statusKey(p: FederationPeer): string {
    if (p.inboundOnly && p.status !== "suspended") {
      return this.trust()?.requireIncomingApproval
        ? "cwFedReview"
        : "cwFedIncomingOnlyBadge";
    }
    if (p.status === "suspended") {
      return "cwFedSuspended";
    }
    if (p.active) {
      return "cwFedActive";
    }
    if (p.localApproved) {
      return "cwFedWaitingForPeer";
    }
    return p.remoteApproved ? "cwFedRemoteRequested" : "cwFedPendingApproval";
  }

  protected badge(p: FederationPeer): "success" | "warning" | "danger" {
    return p.status === "suspended"
      ? "danger"
      : p.active
        ? "success"
        : "warning";
  }

  private async load() {
    try {
      const [identity, peers, events, trust] = await Promise.all([
        this.api.identity(),
        this.api.peers(),
        this.api.events(),
        this.api.trustSettings(),
      ]);
      this.trust.set(trust);
      this.identity.set(identity);
      this.peers.set(peers.data);
      this.events.set(events.data);
      this.error.set(null);
    } catch (e) {
      const status = (e as { statusCode?: number })?.statusCode;
      if (status === 404) {
        this.disabled.set(true);
      } else {
        this.error.set(this.message(e));
      }
    }
  }

  private message(e: unknown): string {
    return (e as Error)?.message ?? String(e);
  }

  private toast(variant: "success" | "error", message: string) {
    this.toastService.showToast({ variant, message });
  }

  /** A fingerprint scanned while adding, kept until the peer exists and is shown for approval. */
  private scannedFingerprint: { domain: string; fingerprint: string } | null =
    null;

  protected scannedForAdd(s: ScannedWorkspace) {
    this.form.patchValue({ domain: s.domain });
    this.scannedFingerprint = s;
  }

  /** Fills the fingerprint field only; approving still needs the server match and an explicit click. */
  protected scannedForApprove(s: ScannedWorkspace, p: FederationPeer) {
    if (!sameDomain(s.domain, p.domain)) {
      this.toast(
        "error",
        this.i18n.t("cwQrDomainMismatch", s.domain, p.domain),
      );
      return;
    }
    this.approveForm.patchValue({ fingerprint: s.fingerprint });
  }

  protected add = async () => {
    this.form.markAllAsTouched();
    if (this.form.invalid) {
      return;
    }
    try {
      const peer = await this.api.addPeer(this.form.value.domain ?? "");
      this.toast("success", this.i18n.t("cwFedPeerAdded", peer.domain));
      this.form.reset();
      this.approving.set(peer.id);
      const scanned = this.scannedFingerprint;
      this.scannedFingerprint = null;
      if (
        scanned &&
        sameDomain(scanned.domain, peer.domain) &&
        normalizeFingerprint(scanned.fingerprint)
      ) {
        this.approveForm.patchValue({ fingerprint: scanned.fingerprint });
      }
    } catch (e) {
      this.toast("error", this.message(e));
    }
    await this.load();
  };

  protected approve = async () => {
    const id = this.approving();
    const peer = this.peers().find((p) => p.id === id);
    const typed = this.approveForm.value.fingerprint ?? "";
    if (!peer) {
      return;
    }
    // Checked here for a quick answer, and again by the server.
    if (!sameFingerprint(typed, peer.fingerprint)) {
      this.toast("error", this.i18n.t("cwFedFingerprintMismatch"));
      return;
    }
    try {
      const updated = await this.api.approvePeer(peer.id, typed);
      this.toast(
        "success",
        this.i18n.t(
          updated.active ? "cwFedPaired" : "cwFedApprovedWaiting",
          updated.domain,
        ),
      );
      this.approving.set(null);
      this.approveForm.reset();
    } catch (e) {
      this.toast("error", this.message(e));
    }
    await this.load();
  };

  protected async check(p: FederationPeer) {
    try {
      const r = await this.api.checkPeer(p.id);
      this.toast(
        r.ok ? "success" : "error",
        r.ok
          ? this.i18n.t("cwFedHealthy", String(r.latencyMs ?? 0))
          : (r.error ?? ""),
      );
    } catch (e) {
      this.toast("error", this.message(e));
    }
    await this.load();
  }

  protected async act(p: FederationPeer, action: "suspend" | "resume") {
    if (action === "suspend") {
      const ok = await this.dialogService.openSimpleDialog({
        title: { key: "cwFedSuspend" },
        content: this.i18n.t("cwFedSuspendDesc", p.domain),
        type: "warning",
      });
      if (!ok) {
        return;
      }
    }
    try {
      await this.api.peerAction(p.id, action);
    } catch (e) {
      this.toast("error", this.message(e));
    }
    await this.load();
  }

  protected addBlock = async () => {
    this.blockForm.markAllAsTouched();
    if (this.blockForm.invalid) {
      return;
    }
    try {
      await this.api.blockDomain(this.blockForm.value.rule ?? "");
      this.blockForm.reset();
    } catch (e) {
      this.toast("error", this.message(e));
    }
    await this.load();
  };

  protected async setRequire(value: boolean) {
    try {
      const r = await this.api.setRequireIncomingApproval(value);
      if (value && (r.reviewPeers ?? 0) > 0) {
        this.toast(
          "success",
          this.i18n.t("cwFedReviewToast", String(r.reviewPeers)),
        );
      }
    } catch (e) {
      this.toast("error", this.message(e));
    }
    await this.load();
  }

  protected async unblock(domain: string) {
    try {
      await this.api.unblockDomain(domain);
    } catch (e) {
      this.toast("error", this.message(e));
    }
    await this.load();
  }

  protected async remove(p: FederationPeer) {
    // "Yes" removes; the dialog's second question asks whether to refuse its pairing requests too.
    const ok = await this.dialogService.openSimpleDialog({
      title: { key: "remove" },
      content: this.i18n.t("cwFedRemoveDesc", p.domain),
      type: "danger",
    });
    if (!ok) {
      return;
    }
    const block = await this.dialogService.openSimpleDialog({
      title: { key: "cwFedBlockTitle" },
      content: this.i18n.t("cwFedBlockDesc", p.domain),
      type: "warning",
      acceptButtonText: { key: "cwFedBlock" },
      cancelButtonText: { key: "no" },
    });
    try {
      await this.api.removePeer(p.id, block);
    } catch (e) {
      this.toast("error", this.message(e));
    }
    await this.load();
  }
}
