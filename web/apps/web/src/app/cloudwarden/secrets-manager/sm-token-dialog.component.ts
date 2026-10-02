// Cloudwarden: create a machine account access token and show it once (web/NOTICE.md).
import { ChangeDetectionStrategy, Component, inject, signal } from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";
import { firstValueFrom } from "rxjs";

import {
  CopyClickDirective,
  DIALOG_DATA,
  DialogRef,
  DialogService,
  ToastService,
} from "@bitwarden/components";

import { SharedModule } from "../../shared";

import { SmApiService } from "./sm-api.service";
import { TOKEN_EXPIRY_DAYS, expiryDate } from "./sm-crypto";
import { toastError } from "./sm-dialogs";

export interface TokenDialogData {
  organizationId: string;
  machineAccountId: string;
}

@Component({
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, CopyClickDirective],
  template: `
    @if (token(); as t) {
      <bit-dialog [title]="'cwSmTokenCreated' | i18n" dialogSize="large">
        <div bitDialogContent>
          <bit-callout type="warning" [title]="'cwSmTokenOnceTitle' | i18n">
            {{ "cwSmTokenOnce" | i18n }}
          </bit-callout>
          <bit-form-field>
            <bit-label>{{ "accessToken" | i18n }}</bit-label>
            <textarea
              bitInput
              rows="3"
              readonly
              class="tw-font-mono tw-break-all"
              [value]="t"
              data-testid="cw-sm-token-value"
            ></textarea>
            <button
              type="button"
              bitIconButton="bwi-clone"
              bitSuffix
              showToast
              [valueLabel]="'accessToken' | i18n"
              [appCopyClick]="t"
              [label]="'copyValue' | i18n"
              data-testid="cw-sm-token-copy"
            ></button>
          </bit-form-field>
        </div>
        <ng-container bitDialogFooter>
          <button
            type="button"
            bitButton
            buttonType="primary"
            (click)="ref.close(true)"
            data-testid="cw-sm-token-done"
          >
            {{ "close" | i18n }}
          </button>
        </ng-container>
      </bit-dialog>
    } @else {
      <form [formGroup]="form" (ngSubmit)="create()">
        <bit-dialog [title]="'cwSmNewAccessToken' | i18n" dialogSize="default">
          <div bitDialogContent>
            <bit-form-field>
              <bit-label>{{ "name" | i18n }}</bit-label>
              <input bitInput type="text" formControlName="name" data-testid="cw-sm-token-name" />
            </bit-form-field>
            <bit-form-field>
              <bit-label>{{ "expires" | i18n }}</bit-label>
              <bit-select formControlName="days">
                @for (d of expiry; track d) {
                  <bit-option
                    [value]="d"
                    [label]="d === null ? ('never' | i18n) : ('cwSmDays' | i18n: d)"
                  ></bit-option>
                }
              </bit-select>
            </bit-form-field>
          </div>
          <ng-container bitDialogFooter>
            <button
              type="submit"
              bitButton
              buttonType="primary"
              [disabled]="form.invalid || saving()"
              data-testid="cw-sm-token-create"
            >
              {{ "cwSmCreateToken" | i18n }}
            </button>
            <button type="button" bitButton buttonType="secondary" (click)="ref.close(false)">
              {{ "cancel" | i18n }}
            </button>
          </ng-container>
        </bit-dialog>
      </form>
    }
  `,
})
export class SmTokenDialogComponent {
  protected readonly data = inject<TokenDialogData>(DIALOG_DATA);
  protected readonly ref = inject<DialogRef<boolean>>(DialogRef);
  private readonly api = inject(SmApiService);
  private readonly toast = inject(ToastService);

  protected readonly expiry = TOKEN_EXPIRY_DAYS;
  protected readonly token = signal<string | null>(null);
  protected readonly saving = signal(false);
  protected readonly form = inject(FormBuilder).group({
    name: ["", [Validators.required, Validators.maxLength(200)]],
    days: [null as number | null],
  });

  protected async create() {
    if (this.form.invalid) {
      return;
    }
    this.saving.set(true);
    try {
      const r = await this.api.createAccessToken(
        this.data.organizationId,
        this.data.machineAccountId,
        (this.form.value.name ?? "").trim(),
        expiryDate(this.form.value.days ?? null),
      );
      this.token.set(r.token);
    } catch (e) {
      toastError(this.toast, e);
    } finally {
      this.saving.set(false);
    }
  }

  /** Resolves to true when a token was created. */
  static async open(dialogs: DialogService, data: TokenDialogData) {
    const ref = dialogs.open<boolean, TokenDialogData>(SmTokenDialogComponent, {
      data,
      disableClose: true,
    });
    return (await firstValueFrom(ref.closed)) === true;
  }
}
