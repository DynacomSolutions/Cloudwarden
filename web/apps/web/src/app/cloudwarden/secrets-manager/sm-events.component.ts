// Cloudwarden: activity of one machine account from the Secrets Manager event log (web/NOTICE.md).
import { DatePipe } from "@angular/common";
import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from "@angular/core";

import { ToastService } from "@bitwarden/components";

import { SharedModule } from "../../shared";

import { SmApiService, SmEvent } from "./sm-api.service";
import { toastError } from "./sm-dialogs";

/** Message key of each Secrets Manager event code (see `EventType` on the server). */
export const SM_EVENT_KEYS: Record<number, string> = {
  2100: "cwSmEventSecretRetrieved",
  2101: "cwSmEventSecretCreated",
  2102: "cwSmEventSecretEdited",
  2103: "cwSmEventSecretDeleted",
  2201: "cwSmEventProjectCreated",
  2202: "cwSmEventProjectEdited",
  2203: "cwSmEventProjectDeleted",
  2300: "cwSmEventUserAdded",
  2301: "cwSmEventUserRemoved",
  2302: "cwSmEventGroupAdded",
  2303: "cwSmEventGroupRemoved",
  2304: "cwSmEventMachineCreated",
  2305: "cwSmEventMachineDeleted",
};

export const eventKey = (type: number) => SM_EVENT_KEYS[type] ?? "cwSmEventOther";

/** The object an event is about, as a short id: secret, project or granted machine account. */
export const eventTarget = (e: SmEvent) =>
  (e.secretId ?? e.projectId ?? e.grantedServiceAccountId ?? "")?.slice(0, 8) ?? "";

@Component({
  selector: "cw-sm-events",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, DatePipe],
  template: `
    @if (loading()) {
      <i class="bwi bwi-spinner bwi-spin" aria-hidden="true"></i>
    } @else if (events().length === 0) {
      <p bitTypography="body1" data-testid="cw-sm-no-events">{{ "cwSmNoEvents" | i18n }}</p>
    } @else {
      <bit-table>
        <ng-container header>
          <tr>
            <th bitCell>{{ "timestamp" | i18n }}</th>
            <th bitCell>{{ "event" | i18n }}</th>
            <th bitCell>{{ "cwSmEventTarget" | i18n }}</th>
            <th bitCell>{{ "ipAddress" | i18n }}</th>
          </tr>
        </ng-container>
        <ng-template body>
          @for (e of events(); track $index) {
            <tr bitRow data-testid="cw-sm-event">
              <td bitCell>{{ e.date | date: "medium" }}</td>
              <td bitCell>{{ key(e.type) | i18n }}</td>
              <td bitCell class="tw-font-mono">{{ target(e) }}</td>
              <td bitCell>{{ e.ipAddress }}</td>
            </tr>
          }
        </ng-template>
      </bit-table>
      @if (next()) {
        <button
          type="button"
          bitButton
          buttonType="secondary"
          class="tw-mt-3"
          [disabled]="loadingMore()"
          (click)="more()"
          data-testid="cw-sm-events-more"
        >
          {{ "loadMore" | i18n }}
        </button>
      }
    }
  `,
})
export class SmEventsComponent implements OnInit {
  readonly machineAccountId = input.required<string>();

  private readonly api = inject(SmApiService);
  private readonly toast = inject(ToastService);

  protected readonly events = signal<SmEvent[]>([]);
  protected readonly next = signal<string | null>(null);
  protected readonly loading = signal(true);
  protected readonly loadingMore = signal(false);
  protected readonly key = eventKey;
  protected readonly target = eventTarget;

  async ngOnInit() {
    try {
      const page = await this.api.listMachineAccountEvents(this.machineAccountId());
      this.events.set(page.events);
      this.next.set(page.continuationToken);
    } catch (e) {
      toastError(this.toast, e);
    } finally {
      this.loading.set(false);
    }
  }

  protected async more() {
    const token = this.next();
    if (!token) {
      return;
    }
    this.loadingMore.set(true);
    try {
      const page = await this.api.listMachineAccountEvents(this.machineAccountId(), token);
      this.events.set([...this.events(), ...page.events]);
      this.next.set(page.continuationToken);
    } catch (e) {
      toastError(this.toast, e);
    } finally {
      this.loadingMore.set(false);
    }
  }
}
