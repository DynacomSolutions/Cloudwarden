// Cloudwarden: member and group access editor for a project or machine account (web/NOTICE.md).
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  inject,
  input,
  signal,
} from "@angular/core";
import { FormsModule } from "@angular/forms";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { ToastService } from "@bitwarden/components";

import { SharedModule } from "../../shared";

import { SmApiService, SmGrantee, SmPeoplePolicy } from "./sm-api.service";
import { toastError, toastSuccess } from "./sm-dialogs";

export type Permission = "read" | "write";

/** Grantees not yet in `policies`, for the add picker. */
export function availableGrantees(grantees: SmGrantee[], policies: SmPeoplePolicy[]) {
  const taken = new Set(policies.map((p) => `${p.kind}:${p.id}`));
  return grantees.filter(
    (g) => (g.kind === "user" || g.kind === "group") && !taken.has(`${g.kind}:${g.id}`),
  );
}

@Component({
  selector: "cw-sm-people-access",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, FormsModule],
  template: `
    <p bitTypography="body2" class="tw-text-muted">
      {{ "cwSmPeopleDesc" | i18n }}
    </p>
    @if (canEdit()) {
      <div class="tw-mb-4 tw-flex tw-flex-wrap tw-items-end tw-gap-3">
        <bit-form-field class="tw-mb-0 tw-min-w-64 tw-grow">
          <bit-label>{{ "cwSmAddPeople" | i18n }}</bit-label>
          <bit-select [(ngModel)]="pick" data-testid="cw-sm-people-pick">
            @for (g of available(); track g.kind + g.id) {
              <bit-option
                [value]="g.kind + ':' + g.id"
                [label]="g.name + (g.kind === 'group' ? ' (' + ('group' | i18n) + ')' : '')"
              ></bit-option>
            }
          </bit-select>
        </bit-form-field>
        <bit-form-field class="tw-mb-0 tw-w-48">
          <bit-label>{{ "permission" | i18n }}</bit-label>
          <bit-select [(ngModel)]="pickPermission">
            <bit-option value="read" [label]="'canRead' | i18n"></bit-option>
            <bit-option value="write" [label]="'canReadWrite' | i18n"></bit-option>
          </bit-select>
        </bit-form-field>
        <button type="button" bitButton buttonType="secondary" [disabled]="!pick" (click)="add()">
          {{ "add" | i18n }}
        </button>
      </div>
    }
    @if (policies().length === 0) {
      <p bitTypography="body1" data-testid="cw-sm-empty">
        {{ "cwSmNoPeople" | i18n }}
      </p>
    } @else {
      <bit-table>
        <ng-container header>
          <tr>
            <th bitCell>{{ "name" | i18n }}</th>
            <th bitCell>{{ "permission" | i18n }}</th>
            <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
          </tr>
        </ng-container>
        <ng-template body>
          @for (p of policies(); track p.kind + p.id) {
            <tr bitRow>
              <td bitCell>
                <i
                  class="bwi"
                  [ngClass]="p.kind === 'group' ? 'bwi-users' : 'bwi-user'"
                  aria-hidden="true"
                ></i>
                {{ p.name }}
              </td>
              <td bitCell>
                <select
                  class="tw-rounded tw-border tw-border-secondary-500 tw-bg-background tw-p-1"
                  [disabled]="!canEdit()"
                  [ngModel]="p.write ? 'write' : 'read'"
                  (ngModelChange)="setPermission(p, $event)"
                  [attr.aria-label]="'permission' | i18n"
                >
                  <option value="read">{{ "canRead" | i18n }}</option>
                  <option value="write">{{ "canReadWrite" | i18n }}</option>
                </select>
              </td>
              <td bitCell class="tw-text-right">
                @if (canEdit()) {
                  <button
                    type="button"
                    bitIconButton="bwi-close"
                    [label]="'remove' | i18n"
                    (click)="removePolicy(p)"
                  ></button>
                }
              </td>
            </tr>
          }
        </ng-template>
      </bit-table>
    }
    @if (canEdit()) {
      <div class="tw-mt-4">
        <button
          type="button"
          bitButton
          buttonType="primary"
          [disabled]="!dirty() || saving()"
          (click)="save()"
          data-testid="cw-sm-people-save"
        >
          {{ "save" | i18n }}
        </button>
      </div>
    }
  `,
})
export class SmPeopleAccessComponent implements OnInit {
  readonly organizationId = input.required<string>();
  readonly target = input.required<"projects" | "service-accounts">();
  readonly targetId = input.required<string>();
  readonly canEdit = input(true);

  private readonly api = inject(SmApiService);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);

  protected readonly policies = signal<SmPeoplePolicy[]>([]);
  protected readonly grantees = signal<SmGrantee[]>([]);
  protected readonly dirty = signal(false);
  protected readonly saving = signal(false);
  protected readonly available = computed(() =>
    availableGrantees(this.grantees(), this.policies()),
  );
  protected pick: string | null = null;
  protected pickPermission: Permission = "read";

  async ngOnInit() {
    try {
      const [policies, grantees] = await Promise.all([
        this.api.getPeoplePolicies(this.target(), this.targetId()),
        this.api.peopleGrantees(this.organizationId()),
      ]);
      this.policies.set(policies);
      this.grantees.set(grantees);
    } catch (e) {
      toastError(this.toast, e);
    }
  }

  protected add() {
    const g = this.available().find((x) => `${x.kind}:${x.id}` === this.pick);
    if (!g) {
      return;
    }
    this.policies.set([
      ...this.policies(),
      {
        kind: g.kind as "user" | "group",
        id: g.id,
        name: g.name,
        read: true,
        write: this.pickPermission === "write",
      },
    ]);
    this.pick = null;
    this.dirty.set(true);
  }

  protected setPermission(p: SmPeoplePolicy, value: Permission) {
    this.policies.set(
      this.policies().map((x) => (x === p ? { ...x, read: true, write: value === "write" } : x)),
    );
    this.dirty.set(true);
  }

  protected removePolicy(p: SmPeoplePolicy) {
    this.policies.set(this.policies().filter((x) => x !== p));
    this.dirty.set(true);
  }

  protected async save() {
    this.saving.set(true);
    try {
      this.policies.set(
        await this.api.putPeoplePolicies(this.target(), this.targetId(), this.policies()),
      );
      this.dirty.set(false);
      toastSuccess(this.toast, this.i18n.t("cwSmAccessSaved"));
    } catch (e) {
      toastError(this.toast, e);
    } finally {
      this.saving.set(false);
    }
  }
}
