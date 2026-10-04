// Cloudwarden: instance invitations (web/NOTICE.md).
import { DatePipe } from "@angular/common";
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import { AdminInvitation, InstanceAdminApiService } from "./instance-admin-api.service";

@Component({
  selector: "cw-instance-admin-invitations",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, DatePipe],
  template: `
    <app-header></app-header>
    <bit-container>
      <bit-section>
        <form [formGroup]="form" [bitSubmit]="invite" class="tw-flex tw-items-start tw-gap-2">
          <bit-form-field class="tw-grow tw-max-w-md">
            <bit-label>{{ "email" | i18n }}</bit-label>
            <input bitInput type="email" formControlName="email" />
          </bit-form-field>
          <button type="submit" bitButton bitFormButton buttonType="primary" class="tw-mt-6">
            {{ "invite" | i18n }}
          </button>
        </form>
      </bit-section>
      @if (error()) {
        <bit-callout type="danger">{{ error() }}</bit-callout>
      }
      @if (issued(); as link) {
        <bit-callout type="info" [title]="'cwInviteLinkTitle' | i18n" data-testid="cw-invite-link">
          <p>{{ issuedNote() }}</p>
          <input bitInput readonly class="tw-font-mono" [value]="link" />
          <button type="button" bitButton buttonType="primary" class="tw-mt-2" (click)="copy(link)">
            {{ "cwCopyLink" | i18n }}
          </button>
        </bit-callout>
      }
      <bit-table>
        <ng-container header>
          <tr>
            <th bitCell>{{ "email" | i18n }}</th>
            <th bitCell>{{ "cwCreated" | i18n }}</th>
            <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
          </tr>
        </ng-container>
        <ng-template body>
          @for (i of invitations(); track i.email) {
            <tr bitRow>
              <td bitCell>{{ i.email }}</td>
              <td bitCell>{{ i.createdAt | date: "short" }}</td>
              <td bitCell class="tw-text-right">
                @if (mailOff()) {
                  <button type="button" bitButton (click)="newLink(i)">
                    {{ "cwNewInviteLink" | i18n }}
                  </button>
                }
                <button type="button" bitButton buttonType="danger" (click)="revoke(i)">
                  {{ "revoke" | i18n }}
                </button>
              </td>
            </tr>
          }
        </ng-template>
      </bit-table>
    </bit-container>
  `,
})
export class InstanceAdminInvitationsComponent implements OnInit {
  private readonly api = inject(InstanceAdminApiService);
  private readonly dialogService = inject(DialogService);
  private readonly toastService = inject(ToastService);
  private readonly i18n = inject(I18nService);
  private readonly platform = inject(PlatformUtilsService);

  /** True when the server cannot send email: invitations are links to copy (docs/emailless.md). */
  protected readonly mailOff = signal(false);
  protected readonly issued = signal<string | null>(null);
  protected readonly issuedNote = signal("");

  protected readonly invitations = signal<AdminInvitation[]>([]);
  protected readonly error = signal<string | null>(null);
  protected readonly form = inject(FormBuilder).group({
    email: ["", [Validators.required, Validators.email]],
  });

  async ngOnInit() {
    try {
      this.mailOff.set((await this.api.overview()).email?.configured === false);
    } catch {
      // The list below reports connection problems.
    }
    await this.load();
  }

  protected copy(link: string) {
    this.platform.copyToClipboard(link);
    this.toastService.showToast({ variant: "success", message: this.i18n.t("valueCopied", this.i18n.t("cwInviteLinkTitle")),
    });
  }

  protected async newLink(i: AdminInvitation) {
    await this.create(i.email);
    await this.load();
  }

  private async create(email: string) {
    const r = await this.api.invite(email);
    if (r.link) {
      this.issued.set(r.link);
      this.issuedNote.set(
        this.i18n.t("cwInviteLinkDesc", new Date(r.codeExpiresAt ?? "").toLocaleDateString()),
      );
    } else {
      this.issued.set(null);
      this.toastService.showToast({
        variant: "success",
        message: this.i18n.t("cwInvited", r.email),
      });
    }
  }

  private async load() {
    try {
      this.invitations.set((await this.api.invitations()).data);
      this.error.set(null);
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
  }

  protected invite = async () => {
    this.form.markAllAsTouched();
    if (this.form.invalid) {
      return;
    }
    try {
      await this.create(this.form.value.email ?? "");
      this.form.reset();
    } catch (e) {
      this.toastService.showToast({
        variant: "error",
        message: (e as Error)?.message ?? String(e),
      });
    }
    await this.load();
  };

  protected async revoke(i: AdminInvitation) {
    const ok = await this.dialogService.openSimpleDialog({
      title: { key: "revoke" },
      content: this.i18n.t("cwRevokeInvitationDesc", i.email),
      type: "warning",
    });
    if (!ok) {
      return;
    }
    try {
      await this.api.revokeInvitation(i.email);
    } catch (e) {
      this.toastService.showToast({ variant: "error", message: (e as Error)?.message ?? "" });
    }
    await this.load();
  }
}
