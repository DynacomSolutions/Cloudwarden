// Cloudwarden: "External workspace" section of the collection dialog's Access tab
// (docs/federation.md, "Sharing a collection"; web/NOTICE.md). Written for Cloudwarden's own API;
// it shares a collection with people of another workspace (a paired Cloudwarden instance), lists
// them with their status, and confirms accepted people with the standard fingerprint check.
// Changes made here apply at once, they are not part of the dialog's Save.
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  inject,
  input,
  signal,
} from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";
import { firstValueFrom, lastValueFrom } from "rxjs";

import { OrganizationUserService } from "@bitwarden/admin-console/common";
import { ApiService } from "@bitwarden/common/abstractions/api.service";
import {
  getOrganizationById,
  OrganizationService,
} from "@bitwarden/common/admin-console/abstractions/organization/organization.service.abstraction";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { Utils } from "@bitwarden/common/platform/misc/utils";
import { DialogService, ToastService } from "@bitwarden/components";

import { UserConfirmComponent } from "../../admin-console/organizations/manage/user-confirm.component";
import { CollectionPermission } from "../../admin-console/organizations/shared/components/access-selector/access-selector.models";
import { SharedModule } from "../../shared";

import {
  EXTERNAL_PERMISSIONS,
  accessToPermission,
  granteeStatusKey,
  isEmailLike,
  parseEmails,
  permissionToAccess,
  workspaceWaitKey,
} from "./external-access";
import {
  ExternalAccessState,
  ExternalGrantee,
  ExternalWorkspace,
  FederationApiService,
  FederationDescriptor,
  formatFingerprint,
  sameFingerprint,
} from "./federation-api.service";
import { sameDomain } from "./workspace-qr";
import {
  ScannedWorkspace,
  WorkspaceQrScanComponent,
} from "./workspace-qr-scan.component";
import { WorkspaceQrShowComponent } from "./workspace-qr-show.component";

/** Value of the workspace select that opens the "add a workspace" form. */
const NEW_WORKSPACE = "__new";

@Component({
  selector: "cw-collection-external-access",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, WorkspaceQrShowComponent, WorkspaceQrScanComponent],
  template: `
    @if (state(); as s) {
      <bit-section class="tw-mt-6" data-testid="cw-ext-access">
        <h3 bitTypography="h5">{{ "cwExtTitle" | i18n }}</h3>
        <p bitTypography="body2" class="tw-text-muted">
          {{ "cwExtDesc" | i18n }}
        </p>
        @if (!s.available) {
          <bit-callout type="info">{{ "cwExtUnavailable" | i18n }}</bit-callout>
        } @else if (!readonly()) {
          <form
            [formGroup]="form"
            [bitSubmit]="share"
            class="tw-grid tw-gap-2 md:tw-grid-cols-2"
          >
            <bit-form-field class="md:tw-col-span-2">
              <bit-label>{{ "cwExtWorkspace" | i18n }}</bit-label>
              <select
                bitInput
                formControlName="workspaceId"
                data-testid="cw-ext-workspace"
              >
                <option value="" disabled>
                  {{ "cwExtChooseWorkspace" | i18n }}
                </option>
                @for (w of s.workspaces; track w.id) {
                  <option [value]="w.id">
                    {{ w.domain
                    }}{{
                      w.state === "active"
                        ? ""
                        : " (" + (stateKey(w) | i18n) + ")"
                    }}
                  </option>
                }
                <option [value]="newWorkspace">
                  {{ "cwExtAddWorkspace" | i18n }}
                </option>
              </select>
            </bit-form-field>

            @if (adding()) {
              <div class="md:tw-col-span-2" data-testid="cw-ext-add-workspace">
                <bit-form-field>
                  <bit-label>{{ "cwExtWorkspaceUrl" | i18n }}</bit-label>
                  <input
                    bitInput
                    type="text"
                    formControlName="domain"
                    placeholder="vault.example.com"
                    data-testid="cw-ext-domain"
                  />
                  <button
                    type="button"
                    bitSuffix
                    bitButton
                    buttonType="secondary"
                    (click)="lookup()"
                    [disabled]="busy()"
                    data-testid="cw-ext-lookup"
                  >
                    {{ "cwExtLookup" | i18n }}
                  </button>
                </bit-form-field>
                <div class="tw-mb-3">
                  <cw-workspace-qr-scan
                    (scanned)="scanned($event)"
                  ></cw-workspace-qr-scan>
                </div>
                @if (found(); as f) {
                  <bit-callout type="info" [title]="f.domain">
                    {{ "cwExtFingerprintShown" | i18n }}
                    <code
                      class="tw-block tw-break-all"
                      data-testid="cw-ext-found-fingerprint"
                      >{{ f.fingerprint }}</code
                    >
                  </bit-callout>
                  <bit-form-field>
                    <bit-label>{{ "cwFedEnterFingerprint" | i18n }}</bit-label>
                    <input
                      bitInput
                      type="text"
                      formControlName="fingerprint"
                      data-testid="cw-ext-fingerprint"
                    />
                    <bit-hint>{{
                      (s.isInstanceAdmin
                        ? "cwExtFingerprintHintAdmin"
                        : "cwExtFingerprintHintUser"
                      ) | i18n: f.domain
                    }}</bit-hint>
                  </bit-form-field>
                  <button
                    type="button"
                    bitButton
                    buttonType="primary"
                    (click)="addWorkspace()"
                    [disabled]="busy()"
                    data-testid="cw-ext-add"
                  >
                    {{
                      (s.isInstanceAdmin
                        ? "cwExtAddTrust"
                        : "cwExtRequestTrust"
                      ) | i18n
                    }}
                  </button>
                }
                @if (own(); as o) {
                  <div class="tw-mt-4">
                    <cw-workspace-qr-show
                      [domain]="o.domain"
                      [fingerprint]="o.fingerprint"
                    ></cw-workspace-qr-show>
                  </div>
                }
              </div>
            }

            @if (selected(); as w) {
              @if (waitKey(w); as key) {
                <bit-callout
                  class="md:tw-col-span-2"
                  [type]="w.state === 'suspended' ? 'danger' : 'warning'"
                  data-testid="cw-ext-wait"
                >
                  {{ key | i18n: w.domain }}
                  <div class="tw-mt-2">
                    <button
                      type="button"
                      bitButton
                      buttonType="secondary"
                      (click)="refresh()"
                    >
                      {{ "cwExtRefresh" | i18n }}
                    </button>
                  </div>
                </bit-callout>
              } @else {
                @if (!s.canInvite) {
                  <bit-callout
                    class="md:tw-col-span-2"
                    type="info"
                    data-testid="cw-ext-no-invite"
                  >
                    {{ "cwExtNoInvite" | i18n }}
                  </bit-callout>
                }
                <bit-form-field class="md:tw-col-span-2">
                  <bit-label>{{
                    (s.canInvite ? "cwExtEmails" : "cwExtEmailsExisting") | i18n
                  }}</bit-label>
                  <textarea
                    bitInput
                    rows="2"
                    formControlName="emails"
                    placeholder="user@example.com"
                    data-testid="cw-ext-emails"
                  ></textarea>
                  <bit-hint>{{ "cwExtEmailsHint" | i18n: w.domain }}</bit-hint>
                </bit-form-field>
                <bit-form-field>
                  <bit-label>{{ "permission" | i18n }}</bit-label>
                  <select
                    bitInput
                    formControlName="permission"
                    data-testid="cw-ext-permission"
                  >
                    @for (p of permissions; track p.perm) {
                      <option [value]="p.perm">{{ p.labelId | i18n }}</option>
                    }
                  </select>
                </bit-form-field>
                <div class="tw-flex tw-items-end">
                  <button
                    type="submit"
                    bitButton
                    bitFormButton
                    buttonType="primary"
                    data-testid="cw-ext-share"
                  >
                    {{ "cwExtShare" | i18n }}
                  </button>
                </div>
              }
            }
          </form>
        }

        @if (error()) {
          <bit-callout type="danger">{{ error() }}</bit-callout>
        }

        @if (s.grantees.length > 0) {
          <bit-table class="tw-mt-4" data-testid="cw-ext-grantees">
            <ng-container header>
              <tr>
                <th bitCell>{{ "email" | i18n }}</th>
                <th bitCell>{{ "cwExtWorkspace" | i18n }}</th>
                <th bitCell>{{ "status" | i18n }}</th>
                <th bitCell>{{ "permission" | i18n }}</th>
                <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
              </tr>
            </ng-container>
            <ng-template body>
              @for (g of s.grantees; track g.id) {
                <tr bitRow>
                  <td bitCell>{{ g.email }}</td>
                  <td bitCell>
                    <span bitBadge variant="secondary">{{ g.peerDomain }}</span>
                  </td>
                  <td bitCell>
                    <span
                      bitBadge
                      [variant]="g.status === 2 ? 'success' : 'warning'"
                    >
                      {{ statusKey(g) | i18n }}
                    </span>
                    @if (g.status === 1) {
                      <div class="tw-text-xs tw-text-muted">
                        {{ "cwExtConfirmHint" | i18n }}
                      </div>
                    }
                  </td>
                  <td bitCell>
                    @if (readonly()) {
                      {{ permissionLabel(g) | i18n }}
                    } @else {
                      <select
                        bitInput
                        [value]="permissionOf(g)"
                        (change)="
                          changePermission(g, $any($event.target).value)
                        "
                        [attr.aria-label]="'permission' | i18n"
                      >
                        @for (p of permissions; track p.perm) {
                          <option
                            [value]="p.perm"
                            [selected]="p.perm === permissionOf(g)"
                          >
                            {{ p.labelId | i18n }}
                          </option>
                        }
                      </select>
                    }
                  </td>
                  <td bitCell class="tw-text-right">
                    <div class="tw-flex tw-justify-end tw-gap-1">
                      @if (g.status === 1 && canConfirm()) {
                        <button
                          type="button"
                          bitButton
                          buttonType="primary"
                          (click)="confirm(g)"
                          data-testid="cw-ext-confirm"
                        >
                          {{ "confirm" | i18n }}
                        </button>
                      }
                      @if (!readonly()) {
                        <button
                          type="button"
                          bitButton
                          buttonType="danger"
                          (click)="remove(g)"
                          data-testid="cw-ext-remove"
                        >
                          {{ "remove" | i18n }}
                        </button>
                      }
                    </div>
                  </td>
                </tr>
              }
            </ng-template>
          </bit-table>
        }
        <p bitTypography="helper" class="tw-mt-3 tw-text-muted">
          {{ "cwExtVaultNote" | i18n }}
        </p>
      </bit-section>
    }
  `,
})
export class CollectionExternalAccessComponent implements OnInit {
  readonly organizationId = input.required<string>();
  readonly collectionId = input.required<string>();
  readonly readonly = input<boolean>(false);

  private readonly api = inject(FederationApiService);
  private readonly apiService = inject(ApiService);
  private readonly organizationService = inject(OrganizationService);
  private readonly organizationUserService = inject(OrganizationUserService);
  private readonly accountService = inject(AccountService);
  private readonly dialogService = inject(DialogService);
  private readonly toastService = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly fb = inject(FormBuilder);

  protected readonly permissions = EXTERNAL_PERMISSIONS;
  protected readonly newWorkspace = NEW_WORKSPACE;
  /** Null while loading, and when the server has federation off or the user may not share. */
  protected readonly state = signal<ExternalAccessState | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly found = signal<{
    domain: string;
    fingerprint: string;
  } | null>(null);
  protected readonly canConfirm = signal(false);
  /** This instance's own identity, for the "Show this workspace's QR" panel. */
  protected readonly own = signal<FederationDescriptor | null>(null);
  private readonly choice = signal("");

  protected readonly form = this.fb.group({
    workspaceId: ["", [Validators.required]],
    domain: [""],
    fingerprint: [""],
    emails: [""],
    permission: [CollectionPermission.View as string],
  });

  protected readonly adding = computed(() => this.choice() === NEW_WORKSPACE);
  protected readonly selected = computed<ExternalWorkspace | null>(
    () => this.state()?.workspaces.find((w) => w.id === this.choice()) ?? null,
  );

  async ngOnInit() {
    this.form.controls.workspaceId.valueChanges.subscribe((v) => {
      this.choice.set(v ?? "");
      this.found.set(null);
      if (v === NEW_WORKSPACE && this.own() === null) {
        void this.loadOwn();
      }
    });
    await this.load();
    try {
      const userId = await firstValueFrom(
        this.accountService.activeAccount$.pipe(getUserId),
      );
      const org = await firstValueFrom(
        this.organizationService
          .organizations$(userId)
          .pipe(getOrganizationById(this.organizationId())),
      );
      this.canConfirm.set(org?.canManageUsers === true);
    } catch {
      this.canConfirm.set(false);
    }
  }

  private async loadOwn() {
    try {
      this.own.set((await this.api.ownDescriptor()) ?? null);
    } catch {
      this.own.set(null);
    }
  }

  protected stateKey(w: ExternalWorkspace): string {
    return (
      {
        active: "cwFedActive",
        suspended: "cwFedSuspended",
        awaitingInstanceAdmin: "cwExtStateAwaitingAdmin",
        awaitingRemote: "cwExtStateAwaitingRemote",
      } as const
    )[w.state];
  }

  protected waitKey(w: ExternalWorkspace): string | null {
    return workspaceWaitKey(w.state, this.state()?.isInstanceAdmin === true);
  }

  protected statusKey(g: ExternalGrantee): string {
    return granteeStatusKey(g.status, g.peerState);
  }

  protected permissionOf(g: ExternalGrantee): CollectionPermission {
    return accessToPermission(g);
  }

  protected permissionLabel(g: ExternalGrantee): string {
    return (
      EXTERNAL_PERMISSIONS.find((p) => p.perm === accessToPermission(g))
        ?.labelId ?? "viewItems"
    );
  }

  private message(e: unknown): string {
    return (e as Error)?.message ?? String(e);
  }

  private toast(variant: "success" | "error" | "warning", message: string) {
    this.toastService.showToast({ variant, message });
  }

  private async load() {
    try {
      this.state.set(
        await this.api.externalAccess(
          this.organizationId(),
          this.collectionId(),
        ),
      );
      this.error.set(null);
    } catch {
      // Federation is off (404) or the caller cannot manage the collection: the section is hidden.
      this.state.set(null);
    }
  }

  protected async refresh() {
    await this.load();
  }

  protected async lookup() {
    const domain = (this.form.value.domain ?? "").trim();
    if (domain === "") {
      return;
    }
    this.busy.set(true);
    try {
      const r = await this.api.lookupWorkspace(
        this.organizationId(),
        this.collectionId(),
        domain,
      );
      if (r.awaitingAdmin || !r.fingerprint) {
        // Known to this server but not visible to non-admins: nothing more to show or add.
        this.error.set(this.i18n.t("cwExtKnownAwaitingAdmin", r.domain));
        return;
      }
      if (r.workspace) {
        // Already known: pick it instead of adding it again.
        this.form.patchValue({ workspaceId: r.workspace.id });
        await this.load();
        return;
      }
      this.found.set({
        domain: r.domain,
        fingerprint: formatFingerprint(r.fingerprint),
      });
      this.error.set(null);
    } catch (e) {
      this.error.set(this.message(e));
    } finally {
      this.busy.set(false);
    }
  }

  /**
   * A scanned QR fills the domain and runs the same server lookup as typing it. The fingerprint is
   * put in the field only when the server's own fetch of that domain matches the scanned domain;
   * adding the workspace is still the user's click and the server checks the fingerprint again.
   */
  protected async scanned(s: ScannedWorkspace) {
    this.form.patchValue({ domain: s.domain, fingerprint: "" });
    await this.lookup();
    const f = this.found();
    if (f && sameDomain(f.domain, s.domain)) {
      this.form.patchValue({ fingerprint: s.fingerprint });
    } else if (f) {
      this.found.set(null);
      this.error.set(this.i18n.t("cwQrDomainMismatch", s.domain, f.domain));
    }
  }

  protected async addWorkspace() {
    const f = this.found();
    const typed = this.form.value.fingerprint ?? "";
    if (!f) {
      return;
    }
    // Checked here for a quick answer, and again by the server against the key it fetched.
    if (!sameFingerprint(typed, f.fingerprint)) {
      this.error.set(this.i18n.t("cwFedFingerprintMismatch"));
      return;
    }
    this.busy.set(true);
    try {
      const r = await this.api.addWorkspace(
        this.organizationId(),
        this.collectionId(),
        f.domain,
        typed,
      );
      this.found.set(null);
      this.form.patchValue({ domain: "", fingerprint: "" });
      if (!r.workspace) {
        this.error.set(this.i18n.t("cwExtKnownAwaitingAdmin", f.domain));
        return;
      }
      await this.load();
      this.form.patchValue({ workspaceId: r.workspace.id });
      this.error.set(null);
      this.toast(
        "success",
        this.i18n.t(
          this.waitKey(r.workspace) ?? "cwExtWsReady",
          r.workspace.domain,
        ),
      );
    } catch (e) {
      this.error.set(this.message(e));
    } finally {
      this.busy.set(false);
    }
  }

  protected share = async () => {
    const w = this.selected();
    const emails = parseEmails(this.form.value.emails ?? "");
    if (!w || emails.length === 0) {
      this.error.set(this.i18n.t("cwExtNeedEmail"));
      return;
    }
    const bad = emails.find((e) => !isEmailLike(e));
    if (bad) {
      this.error.set(this.i18n.t("cwExtBadEmail", bad));
      return;
    }
    try {
      const res = await this.api.share(
        this.organizationId(),
        this.collectionId(),
        w.id,
        emails,
        permissionToAccess(
          (this.form.value.permission ??
            CollectionPermission.View) as CollectionPermission,
        ),
      );
      const failed = res.data.filter((r) => !r.ok);
      const ok = res.data.length - failed.length;
      if (ok > 0) {
        this.toast("success", this.i18n.t("cwExtShared", String(ok)));
      }
      this.error.set(
        failed.length
          ? failed.map((r) => `${r.email}: ${r.error ?? ""}`).join(" ")
          : null,
      );
      this.form.patchValue({ emails: failed.map((r) => r.email).join("\n") });
    } catch (e) {
      this.error.set(this.message(e));
    }
    await this.load();
  };

  protected async changePermission(g: ExternalGrantee, value: string) {
    try {
      await this.api.updateExternalAccess(
        this.organizationId(),
        this.collectionId(),
        g.id,
        permissionToAccess(value as CollectionPermission),
      );
    } catch (e) {
      this.error.set(this.message(e));
    }
    await this.load();
  }

  protected async remove(g: ExternalGrantee) {
    const ok = await this.dialogService.openSimpleDialog({
      title: { key: "remove" },
      content: this.i18n.t("cwExtRemoveDesc", g.email, g.peerDomain),
      type: "warning",
    });
    if (!ok) {
      return;
    }
    try {
      await this.api.removeExternalAccess(
        this.organizationId(),
        this.collectionId(),
        g.id,
      );
    } catch (e) {
      this.error.set(this.message(e));
    }
    await this.load();
  }

  /** The standard confirm flow: fingerprint phrase shown, organisation key wrapped in this browser. */
  protected async confirm(g: ExternalGrantee) {
    if (!g.userId) {
      return;
    }
    try {
      const response = await this.apiService.getUserPublicKey(g.userId);
      const publicKey = Utils.fromB64ToArray(response.publicKey);
      const dialog = UserConfirmComponent.open(this.dialogService, {
        data: { name: g.email, userId: g.userId, publicKey },
      });
      if (!(await lastValueFrom(dialog.closed))) {
        return;
      }
      const userId = await firstValueFrom(
        this.accountService.activeAccount$.pipe(getUserId),
      );
      const organization = await firstValueFrom(
        this.organizationService
          .organizations$(userId)
          .pipe(getOrganizationById(this.organizationId())),
      );
      if (!organization) {
        return;
      }
      await firstValueFrom(
        this.organizationUserService.confirmUser(organization, g.id, publicKey),
      );
      this.toast("success", this.i18n.t("hasBeenConfirmed", g.email));
    } catch (e) {
      this.toast("error", this.message(e));
    }
    await this.load();
  }
}
