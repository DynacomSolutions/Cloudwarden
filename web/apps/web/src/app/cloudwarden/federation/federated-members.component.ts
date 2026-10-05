// Cloudwarden: Admin Console, external people (docs/federation.md, web/NOTICE.md): an overview of
// the people of other workspaces who belong to this organisation, with the collections they hold.
// Sharing starts from a collection's Access dialog; this page also still invites people, and
// confirms accepted ones: the fingerprint phrase is always shown and the organisation key is
// wrapped in this browser.
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  inject,
  signal,
} from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";
import { ActivatedRoute, RouterModule } from "@angular/router";
import { firstValueFrom, lastValueFrom } from "rxjs";

import {
  CollectionAdminService,
  OrganizationUserService,
} from "@bitwarden/admin-console/common";
import { ApiService } from "@bitwarden/common/abstractions/api.service";
import {
  getOrganizationById,
  OrganizationService,
} from "@bitwarden/common/admin-console/abstractions/organization/organization.service.abstraction";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { Utils } from "@bitwarden/common/platform/misc/utils";
import { OrganizationId } from "@bitwarden/common/types/guid";
import { DialogService, ToastService } from "@bitwarden/components";

import { UserConfirmComponent } from "../../admin-console/organizations/manage/user-confirm.component";
import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import {
  FederatedMember,
  FederationApiService,
  FederationStatus,
  organizationIdFrom,
} from "./federation-api.service";

/** Membership status values, as on the wire. */
const STATUS_KEYS: Record<number, string> = {
  [-1]: "revoked",
  0: "invited",
  1: "accepted",
  2: "confirmed",
};
const ROLE_KEYS: Record<number, string> = {
  0: "owner",
  1: "admin",
  2: "user",
  4: "custom",
};

@Component({
  selector: "cw-federated-members",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, RouterModule],
  template: `
    <app-header></app-header>
    <bit-container>
      @if (status() === null && !loading()) {
        <bit-callout type="info" data-testid="cw-fed-disabled">{{
          "cwFedDisabled" | i18n
        }}</bit-callout>
      } @else {
        <p bitTypography="body1">{{ "cwFedMembersDesc" | i18n }}</p>
        <p bitTypography="body2" class="tw-text-muted">
          {{ "cwExtPeopleHowTo" | i18n }}
        </p>
        @if ((status()?.peers ?? []).length === 0) {
          <bit-callout type="warning">{{ "cwFedNoPeers" | i18n }}</bit-callout>
        } @else {
          <bit-section>
            <h2 bitTypography="h4">{{ "cwFedInvite" | i18n }}</h2>
            <form
              [formGroup]="form"
              [bitSubmit]="invite"
              class="tw-grid tw-gap-2 md:tw-grid-cols-2"
            >
              <bit-form-field>
                <bit-label>{{ "email" | i18n }}</bit-label>
                <input
                  bitInput
                  type="email"
                  formControlName="email"
                  data-testid="cw-fed-email"
                />
              </bit-form-field>
              <bit-form-field>
                <bit-label>{{ "cwFedHomeInstance" | i18n }}</bit-label>
                <select bitInput formControlName="peerId">
                  @for (p of status()?.peers ?? []; track p.id) {
                    <option [value]="p.id">{{ p.domain }}</option>
                  }
                </select>
              </bit-form-field>
              <bit-form-field>
                <bit-label>{{ "memberRole" | i18n }}</bit-label>
                <select bitInput formControlName="type">
                  <option [ngValue]="2">{{ "user" | i18n }}</option>
                  <option [ngValue]="1">{{ "admin" | i18n }}</option>
                </select>
              </bit-form-field>
              <bit-form-control class="tw-mt-6">
                <input
                  type="checkbox"
                  bitCheckbox
                  formControlName="accessAll"
                />
                <bit-label>{{ "cwFedAccessAll" | i18n }}</bit-label>
              </bit-form-control>
              <p bitTypography="helper" class="md:tw-col-span-2">
                {{ "cwFedInviteHint" | i18n }}
              </p>
              <div>
                <button
                  type="submit"
                  bitButton
                  bitFormButton
                  buttonType="primary"
                >
                  {{ "invite" | i18n }}
                </button>
              </div>
            </form>
          </bit-section>
        }
        @if (error()) {
          <bit-callout type="danger">{{ error() }}</bit-callout>
        }
        <bit-table>
          <ng-container header>
            <tr>
              <th bitCell>{{ "email" | i18n }}</th>
              <th bitCell>{{ "cwFedHomeInstance" | i18n }}</th>
              <th bitCell>{{ "memberRole" | i18n }}</th>
              <th bitCell>{{ "status" | i18n }}</th>
              <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
            </tr>
          </ng-container>
          <ng-template body>
            @for (m of members(); track m.id) {
              <tr bitRow>
                <td bitCell>
                  {{ m.email }}
                  <div class="tw-text-xs" data-testid="cw-fed-collections">
                    @if ((m.collectionIds ?? []).length === 0) {
                      <span class="tw-text-muted">{{
                        "cwExtNoCollections" | i18n
                      }}</span>
                    } @else {
                      @for (name of collectionNames(m); track $index) {
                        <a
                          bitLink
                          class="tw-mr-2"
                          [routerLink]="['../vault']"
                          [queryParams]="{ collectionId: name.id }"
                          >{{ name.name }}</a
                        >
                      }
                    }
                  </div>
                </td>
                <td bitCell>
                  {{ m.peerDomain }}
                  @if (m.peerStatus !== "active") {
                    <span bitBadge variant="danger">{{
                      "cwFedSuspended" | i18n
                    }}</span>
                  }
                </td>
                <td bitCell>{{ roleKey(m.type) | i18n }}</td>
                <td bitCell>
                  <span
                    bitBadge
                    [variant]="m.status === 2 ? 'success' : 'warning'"
                  >
                    {{ statusKey(m.status) | i18n }}
                  </span>
                </td>
                <td bitCell class="tw-text-right">
                  <div class="tw-flex tw-justify-end tw-gap-1">
                    @if (m.status === 1) {
                      <button
                        type="button"
                        bitButton
                        buttonType="primary"
                        (click)="confirm(m)"
                      >
                        {{ "confirm" | i18n }}
                      </button>
                    }
                    <button
                      type="button"
                      bitButton
                      buttonType="danger"
                      (click)="remove(m)"
                    >
                      {{ "remove" | i18n }}
                    </button>
                  </div>
                </td>
              </tr>
            }
          </ng-template>
        </bit-table>
        <p bitTypography="helper" class="tw-mt-4">
          {{ "cwFedNotFederated" | i18n }}
        </p>
      }
    </bit-container>
  `,
})
export class FederatedMembersComponent implements OnInit {
  private readonly api = inject(FederationApiService);
  private readonly apiService = inject(ApiService);
  private readonly organizationService = inject(OrganizationService);
  private readonly organizationUserService = inject(OrganizationUserService);
  private readonly collectionAdminService = inject(CollectionAdminService);
  private readonly accountService = inject(AccountService);
  private readonly dialogService = inject(DialogService);
  private readonly toastService = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly route = inject(ActivatedRoute);
  private readonly orgId = organizationIdFrom(this.route);

  protected readonly loading = signal(true);
  protected readonly status = signal<FederationStatus | null>(null);
  protected readonly members = signal<FederatedMember[]>([]);
  protected readonly error = signal<string | null>(null);
  protected readonly inviteSetting = signal<{
    collectionManagersMayInvite: boolean;
    canChange: boolean;
  } | null>(null);
  /** Collection names (encrypted on the server, decrypted in this browser) by id. */
  private readonly collectionNameById = signal<Map<string, string>>(new Map());
  protected readonly form = inject(FormBuilder).group({
    email: ["", [Validators.required, Validators.email]],
    peerId: ["", [Validators.required]],
    type: [2, [Validators.required]],
    accessAll: [false],
  });

  async ngOnInit() {
    try {
      const status = await this.api.status();
      this.status.set(status);
      if (status.peers[0]) {
        this.form.patchValue({ peerId: status.peers[0].id });
      }
      await this.load();
      this.inviteSetting.set(
        await this.api.inviteSetting(this.orgId).catch((): null => null),
      );
    } catch {
      this.status.set(null);
    } finally {
      this.loading.set(false);
    }
  }

  protected async toggleInvite(enabled: boolean) {
    try {
      await this.api.setInviteSetting(this.orgId, enabled);
      this.inviteSetting.update((s) =>
        s ? { ...s, collectionManagersMayInvite: enabled } : s,
      );
    } catch (e) {
      this.toast("error", (e as Error)?.message ?? String(e));
      this.inviteSetting.set(
        await this.api.inviteSetting(this.orgId).catch((): null => null),
      );
    }
  }

  protected statusKey(s: number) {
    return STATUS_KEYS[s] ?? "unknown";
  }

  protected roleKey(t: number) {
    return ROLE_KEYS[t] ?? "user";
  }

  private async load() {
    try {
      this.members.set((await this.api.members(this.orgId)).data);
      this.error.set(null);
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
    await this.loadCollectionNames();
  }

  private async loadCollectionNames() {
    try {
      const userId = await firstValueFrom(
        this.accountService.activeAccount$.pipe(getUserId),
      );
      const views = await firstValueFrom(
        this.collectionAdminService.collectionAdminViews$(
          this.orgId as OrganizationId,
          userId,
        ),
      );
      this.collectionNameById.set(
        new Map(views.map((v) => [v.id as string, v.name])),
      );
    } catch {
      // Names are a convenience: the ids are shown when they cannot be decrypted here.
    }
  }

  protected collectionNames(
    m: FederatedMember,
  ): { id: string; name: string }[] {
    const names = this.collectionNameById();
    return (m.collectionIds ?? []).map((id) => ({
      id,
      name: names.get(id) ?? id,
    }));
  }

  private toast(variant: "success" | "error", message: string) {
    this.toastService.showToast({ variant, message });
  }

  protected invite = async () => {
    this.form.markAllAsTouched();
    if (this.form.invalid) {
      return;
    }
    const v = this.form.getRawValue();
    try {
      await this.api.invite(this.orgId, {
        email: v.email ?? "",
        peerId: v.peerId ?? "",
        type: Number(v.type),
        accessAll: v.accessAll === true,
        collections: [],
      });
      this.toast("success", this.i18n.t("cwFedInvited", v.email ?? ""));
      this.form.patchValue({ email: "" });
    } catch (e) {
      this.toast("error", (e as Error)?.message ?? String(e));
    }
    await this.load();
  };

  /** The standard confirm flow, with the fingerprint check always shown. */
  protected async confirm(m: FederatedMember) {
    if (!m.userId) {
      return;
    }
    try {
      const response = await this.apiService.getUserPublicKey(m.userId);
      const publicKey = Utils.fromB64ToArray(response.publicKey);
      const dialog = UserConfirmComponent.open(this.dialogService, {
        data: { name: m.email, userId: m.userId, publicKey },
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
          .pipe(getOrganizationById(this.orgId)),
      );
      if (!organization) {
        return;
      }
      await firstValueFrom(
        this.organizationUserService.confirmUser(organization, m.id, publicKey),
      );
      this.toast("success", this.i18n.t("hasBeenConfirmed", m.email));
    } catch (e) {
      this.toast("error", (e as Error)?.message ?? String(e));
    }
    await this.load();
  }

  protected async remove(m: FederatedMember) {
    const ok = await this.dialogService.openSimpleDialog({
      title: { key: "remove" },
      content: this.i18n.t("cwFedRemoveMemberDesc", m.email, m.peerDomain),
      type: "warning",
    });
    if (!ok) {
      return;
    }
    try {
      await this.api.removeMember(this.orgId, m.id);
    } catch (e) {
      this.toast("error", (e as Error)?.message ?? String(e));
    }
    await this.load();
  }
}
