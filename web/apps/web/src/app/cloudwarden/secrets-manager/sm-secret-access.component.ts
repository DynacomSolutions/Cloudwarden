// Cloudwarden: direct access policies of one secret, for members, groups and machine accounts
// (web/NOTICE.md). The editor only collects changes; the secret dialog sends them with the secret.
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  computed,
  inject,
  input,
  output,
  signal,
} from "@angular/core";
import { FormsModule } from "@angular/forms";

import { ToastService } from "@bitwarden/components";

import { SharedModule } from "../../shared";

import {
  SmApiService,
  SmGrantee,
  SmMachinePolicy,
  SmPeoplePolicy,
  SmSecretAccess,
} from "./sm-api.service";
import { toastError } from "./sm-dialogs";
import { availableGrantees } from "./sm-people-access.component";

export type Row = { key: string; name: string; icon: string; read: boolean; write: boolean };

/** Grantees (machine accounts) not yet in `policies`. */
export function availableMachines(
  all: { id: string; name: string }[],
  policies: SmMachinePolicy[],
) {
  const taken = new Set(policies.map((p) => p.id));
  return all.filter((m) => !taken.has(m.id));
}

@Component({
  selector: "cw-sm-secret-access",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, FormsModule],
  template: `
    <p bitTypography="body2" class="tw-text-muted">{{ "cwSmSecretAccessDesc" | i18n }}</p>
    @if (canEdit()) {
      <div class="tw-mb-3 tw-flex tw-flex-wrap tw-items-end tw-gap-3">
        <bit-form-field class="tw-mb-0 tw-min-w-48 tw-grow">
          <bit-label>{{ "cwSmAddPeople" | i18n }}</bit-label>
          <bit-select [(ngModel)]="pick" data-testid="cw-sm-secret-access-pick">
            @for (g of availablePeople(); track g.kind + g.id) {
              <bit-option
                [value]="'p:' + g.kind + ':' + g.id"
                [label]="g.name + (g.kind === 'group' ? ' (' + ('group' | i18n) + ')' : '')"
              ></bit-option>
            }
            @for (m of availableMachineAccounts(); track m.id) {
              <bit-option
                [value]="'m:' + m.id"
                [label]="m.name + ' (' + ('machineAccount' | i18n) + ')'"
              ></bit-option>
            }
          </bit-select>
        </bit-form-field>
        <bit-form-field class="tw-mb-0 tw-w-40">
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
    @if (rows().length === 0) {
      <p bitTypography="body1" data-testid="cw-sm-secret-access-empty">
        {{ "cwSmNoSecretAccess" | i18n }}
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
          @for (r of rows(); track r.key) {
            <tr bitRow data-testid="cw-sm-secret-access-row">
              <td bitCell>
                <i class="bwi" [ngClass]="r.icon" aria-hidden="true"></i>
                {{ r.name }}
              </td>
              <td bitCell>
                <select
                  class="tw-rounded tw-border tw-border-secondary-500 tw-bg-background tw-p-1"
                  [disabled]="!canEdit()"
                  [ngModel]="r.write ? 'write' : 'read'"
                  (ngModelChange)="setPermission(r.key, $event)"
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
                    (click)="remove(r.key)"
                  ></button>
                }
              </td>
            </tr>
          }
        </ng-template>
      </bit-table>
    }
  `,
})
export class SmSecretAccessComponent implements OnInit {
  readonly organizationId = input.required<string>();
  /** Absent for a secret that is not saved yet. */
  readonly secretId = input<string | null>(null);
  readonly canEdit = input(true);
  /** Emits the complete new access once the user changes anything. */
  readonly accessChange = output<SmSecretAccess>();

  private readonly api = inject(SmApiService);
  private readonly toast = inject(ToastService);

  protected readonly people = signal<SmPeoplePolicy[]>([]);
  protected readonly machines = signal<SmMachinePolicy[]>([]);
  private readonly peopleGrantees = signal<SmGrantee[]>([]);
  private readonly machineGrantees = signal<{ id: string; name: string }[]>([]);
  protected pick: string | null = null;
  protected pickPermission: "read" | "write" = "read";

  protected readonly availablePeople = computed(() =>
    availableGrantees(this.peopleGrantees(), this.people()),
  );
  protected readonly availableMachineAccounts = computed(() =>
    availableMachines(this.machineGrantees(), this.machines()),
  );
  protected readonly rows = computed<Row[]>(() => [
    ...this.people().map((p) => ({
      key: `p:${p.kind}:${p.id}`,
      name: p.name,
      icon: p.kind === "group" ? "bwi-users" : "bwi-user",
      read: p.read,
      write: p.write,
    })),
    ...this.machines().map((m) => ({
      key: `m:${m.id}`,
      name: m.name,
      icon: "bwi-wrench",
      read: m.read,
      write: m.write,
    })),
  ]);

  async ngOnInit() {
    try {
      const orgId = this.organizationId();
      const id = this.secretId();
      if (id) {
        const access = await this.api.getSecretAccess(orgId, id);
        this.people.set(access.people);
        this.machines.set(access.machines);
      }
      if (this.canEdit()) {
        const [people, machines] = await Promise.all([
          this.api.peopleGrantees(orgId),
          this.api.machineGrantees(orgId),
        ]);
        this.peopleGrantees.set(people);
        this.machineGrantees.set(machines);
      }
    } catch (e) {
      toastError(this.toast, e);
    }
  }

  private emit() {
    this.accessChange.emit({ people: this.people(), machines: this.machines() });
  }

  protected add() {
    const write = this.pickPermission === "write";
    if (this.pick?.startsWith("m:")) {
      const m = this.availableMachineAccounts().find((x) => `m:${x.id}` === this.pick);
      if (!m) {
        return;
      }
      this.machines.set([...this.machines(), { id: m.id, name: m.name, read: true, write }]);
    } else {
      const g = this.availablePeople().find((x) => `p:${x.kind}:${x.id}` === this.pick);
      if (!g) {
        return;
      }
      this.people.set([
        ...this.people(),
        { kind: g.kind as "user" | "group", id: g.id, name: g.name, read: true, write },
      ]);
    }
    this.pick = null;
    this.emit();
  }

  protected setPermission(key: string, value: "read" | "write") {
    const write = value === "write";
    this.people.set(
      this.people().map((p) => (`p:${p.kind}:${p.id}` === key ? { ...p, read: true, write } : p)),
    );
    this.machines.set(
      this.machines().map((m) => (`m:${m.id}` === key ? { ...m, read: true, write } : m)),
    );
    this.emit();
  }

  protected remove(key: string) {
    this.people.set(this.people().filter((p) => `p:${p.kind}:${p.id}` !== key));
    this.machines.set(this.machines().filter((m) => `m:${m.id}` !== key));
    this.emit();
  }
}
