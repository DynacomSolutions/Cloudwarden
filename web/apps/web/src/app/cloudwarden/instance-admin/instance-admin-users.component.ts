// Cloudwarden: instance user management (web/NOTICE.md).
import { DatePipe } from "@angular/common";
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  inject,
  signal,
} from "@angular/core";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import {
  AdminRole,
  AdminUser,
  AdminUserAction,
  InstanceAdminApiService,
} from "./instance-admin-api.service";

@Component({
  selector: "cw-instance-admin-users",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, DatePipe],
  template: `
    <app-header></app-header>
    <bit-container>
      <p bitTypography="body1">{{ "cwUsersDesc" | i18n: total() }}</p>
      @if (error()) {
        <bit-callout type="danger">{{ error() }}</bit-callout>
      }
      <bit-table>
        <ng-container header>
          <tr>
            <th bitCell>{{ "email" | i18n }}</th>
            <th bitCell>{{ "name" | i18n }}</th>
            <th bitCell>{{ "cwCreated" | i18n }}</th>
            <th bitCell>{{ "cwLastActive" | i18n }}</th>
            <th bitCell>{{ "items" | i18n }}</th>
            <th bitCell>{{ "twoStepLogin" | i18n }}</th>
            <th bitCell>{{ "cwRole" | i18n }}</th>
            <th bitCell>{{ "status" | i18n }}</th>
            <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
          </tr>
        </ng-container>
        <ng-template body>
          @for (u of users(); track u.id) {
            <tr bitRow data-testid="cw-user-row">
              <td bitCell>
                {{ u.email }}
                @if (!u.emailVerified) {
                  <span bitBadge variant="warning">{{
                    "cwUnverified" | i18n
                  }}</span>
                }
              </td>
              <td bitCell>{{ u.name }}</td>
              <td bitCell>{{ u.createdAt | date: "short" }}</td>
              <td bitCell>
                {{ u.lastActive ? (u.lastActive | date: "short") : "-" }}
              </td>
              <td bitCell>{{ u.itemCount }}</td>
              <td bitCell>
                @for (p of u.twoFactorProviders; track p.type) {
                  <span bitBadge variant="secondary">{{ p.name }}</span>
                }
              </td>
              <td bitCell data-testid="cw-user-role">
                <span
                  bitBadge
                  [variant]="roleVariant(u.role)"
                  [attr.title]="roleTip(u)"
                  >{{ roleLabelKey(u.role) | i18n }}</span
                >
                @if (canChangeRole(u)) {
                  <button
                    type="button"
                    bitIconButton="bwi-angle-down"
                    [label]="'cwChangeRole' | i18n"
                    [bitMenuTriggerFor]="roleMenu"
                    data-testid="cw-role-trigger"
                  ></button>
                  <bit-menu #roleMenu>
                    @for (r of grantable; track r) {
                      <button
                        type="button"
                        bitMenuItem
                        [disabled]="r === u.role"
                        [attr.data-testid]="'cw-role-' + r"
                        (click)="changeRole(u, r)"
                      >
                        {{ roleLabelKey(r) | i18n }}
                      </button>
                    }
                  </bit-menu>
                } @else {
                  <button
                    type="button"
                    bitIconButton="bwi-angle-down"
                    [label]="'cwChangeRole' | i18n"
                    [disabled]="true"
                    [attr.title]="roleTip(u)"
                    data-testid="cw-role-locked"
                  ></button>
                }
              </td>
              <td bitCell>
                @if (u.enabled) {
                  <span bitBadge variant="success">{{
                    "cwStatusEnabled" | i18n
                  }}</span>
                } @else {
                  <span bitBadge variant="danger">{{
                    "cwStatusDisabled" | i18n
                  }}</span>
                }
              </td>
              <td bitCell class="tw-text-right">
                <button
                  type="button"
                  bitIconButton="bwi-ellipsis-v"
                  [label]="'options' | i18n"
                  [bitMenuTriggerFor]="userMenu"
                ></button>
                <bit-menu #userMenu>
                  @if (u.enabled) {
                    <button
                      type="button"
                      bitMenuItem
                      (click)="act(u, 'disable')"
                    >
                      {{ "cwDisable" | i18n }}
                    </button>
                  } @else {
                    <button
                      type="button"
                      bitMenuItem
                      (click)="act(u, 'enable')"
                    >
                      {{ "cwEnable" | i18n }}
                    </button>
                  }
                  <button
                    type="button"
                    bitMenuItem
                    (click)="act(u, 'deauthorize')"
                  >
                    {{ "cwDeauthorize" | i18n }}
                  </button>
                  @if (u.twoFactorProviders.length) {
                    <button
                      type="button"
                      bitMenuItem
                      (click)="act(u, 'remove-2fa')"
                    >
                      {{ "cwRemove2fa" | i18n }}
                    </button>
                  }
                  <button type="button" bitMenuItem (click)="remove(u)">
                    <span class="tw-text-danger">{{ "delete" | i18n }}</span>
                  </button>
                </bit-menu>
              </td>
            </tr>
          }
        </ng-template>
      </bit-table>
      <div class="tw-flex tw-gap-2 tw-mt-4">
        <button
          type="button"
          bitButton
          buttonType="secondary"
          [disabled]="page() <= 1"
          (click)="go(-1)"
        >
          {{ "cwPrevious" | i18n }}
        </button>
        <button
          type="button"
          bitButton
          buttonType="secondary"
          [disabled]="!hasMore()"
          (click)="go(1)"
        >
          {{ "next" | i18n }}
        </button>
      </div>
    </bit-container>
  `,
})
export class InstanceAdminUsersComponent implements OnInit {
  private readonly api = inject(InstanceAdminApiService);
  private readonly dialogService = inject(DialogService);
  private readonly toastService = inject(ToastService);
  private readonly i18n = inject(I18nService);

  protected readonly grantable = ["admin", "user"] as const;
  protected readonly users = signal<AdminUser[]>([]);
  protected readonly page = signal(1);
  protected readonly total = signal(0);
  protected readonly hasMore = signal(false);
  protected readonly error = signal<string | null>(null);

  async ngOnInit() {
    await this.load();
  }

  protected async go(delta: number) {
    this.page.update((p) => Math.max(1, p + delta));
    await this.load();
  }

  private async load() {
    try {
      const r = await this.api.users(this.page());
      this.users.set(r.data);
      this.total.set(r.total);
      this.hasMore.set(r.hasMore);
      this.error.set(null);
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
  }

  private async confirm(title: string, content: string, danger = false) {
    return this.dialogService.openSimpleDialog({
      title,
      content,
      type: danger ? "danger" : "warning",
      acceptButtonText: { key: "yes" },
      cancelButtonText: { key: "no" },
    });
  }

  private async run(work: () => Promise<void>, message: string) {
    try {
      await work();
      this.toastService.showToast({ variant: "success", message });
    } catch (e) {
      this.toastService.showToast({
        variant: "error",
        message: (e as Error)?.message ?? String(e),
      });
    }
    await this.load();
  }

  protected async act(u: AdminUser, action: AdminUserAction) {
    const key = {
      disable: "cwDisable",
      enable: "cwEnable",
      deauthorize: "cwDeauthorize",
      "remove-2fa": "cwRemove2fa",
    }[action];
    if (
      !(await this.confirm(
        this.i18n.t(key),
        this.i18n.t("cwConfirmUserAction", u.email),
      ))
    ) {
      return;
    }
    await this.run(
      () => this.api.userAction(u.id, action),
      this.i18n.t("cwDone"),
    );
  }

  protected roleLabelKey(role: AdminRole) {
    return { owner: "cwRoleOwner", admin: "cwRoleAdmin", user: "cwRoleUser" }[
      role
    ];
  }

  protected roleVariant(role: AdminRole) {
    return role === "owner"
      ? "primary"
      : role === "admin"
        ? "success"
        : "secondary";
  }

  /** Owners come from ADMIN_EMAILS and your own role is never changed from here. */
  protected canChangeRole(u: AdminUser) {
    return u.role !== "owner" && !u.self;
  }

  protected roleTip(u: AdminUser): string | null {
    if (u.role === "owner") {
      return this.i18n.t("cwRoleOwnerTip");
    }
    return u.self ? this.i18n.t("cwRoleSelfTip") : null;
  }

  protected async changeRole(u: AdminUser, role: "admin" | "user") {
    if (!this.canChangeRole(u) || role === u.role) {
      return;
    }
    const ok = await this.confirm(
      this.i18n.t("cwChangeRole"),
      this.i18n.t(
        role === "admin" ? "cwConfirmMakeAdmin" : "cwConfirmMakeUser",
        u.email,
      ),
    );
    if (ok) {
      await this.run(
        () => this.api.setUserRole(u.id, role),
        this.i18n.t("cwRoleChanged"),
      );
    }
  }

  protected async remove(u: AdminUser) {
    const ok = await this.confirm(
      this.i18n.t("cwDeleteUser"),
      this.i18n.t("cwDeleteUserDesc", u.email),
      true,
    );
    if (ok) {
      await this.run(() => this.api.deleteUser(u.id), this.i18n.t("cwDone"));
    }
  }
}
