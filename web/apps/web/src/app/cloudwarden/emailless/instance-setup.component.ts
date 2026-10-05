// Cloudwarden: setup and invite page for servers that cannot send email (web/NOTICE.md,
// docs/emailless.md). The operator (setup secret) or an invited person (invite link code) proves
// the right to register here; the server then issues the usual registration token and the
// standard "finish sign up" page takes over.
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";
import { ActivatedRoute, Router } from "@angular/router";

import { SharedModule } from "../../shared";

import { InstanceSetupApiService } from "./instance-setup-api.service";

/** Query parameters of the standard finish sign up page for a redeemed registration token. */
export function finishSignupParams(email: string, token: string) {
  return { queryParams: { token, email } };
}

@Component({
  selector: "cw-instance-setup",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule],
  template: `
    <p bitTypography="body2">{{ "cwInstanceSetupDesc" | i18n }}</p>
    <form [formGroup]="form" [bitSubmit]="submit">
      <bit-form-field>
        <bit-label>{{ "emailAddress" | i18n }}</bit-label>
        <input bitInput type="email" formControlName="email" inputmode="email" />
      </bit-form-field>
      <bit-form-field>
        <bit-label>{{ "cwSetupCode" | i18n }}</bit-label>
        <input
          bitInput
          type="password"
          formControlName="code"
          autocomplete="off"
          data-testid="cw-setup-code"
        />
        <button type="button" bitIconButton bitSuffix bitPasswordInputToggle></button>
      </bit-form-field>
      @if (error()) {
        <bit-callout type="danger" data-testid="cw-setup-error">{{ error() }}</bit-callout>
      }
      <button type="submit" bitButton bitFormButton buttonType="primary" block>
        {{ "continue" | i18n }}
      </button>
    </form>
  `,
})
export class InstanceSetupComponent implements OnInit {
  private readonly api = inject(InstanceSetupApiService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);

  protected readonly error = signal<string | null>(null);
  protected readonly form = inject(FormBuilder).group({
    email: ["", [Validators.required, Validators.email]],
    code: ["", [Validators.required]],
  });

  ngOnInit() {
    // Invite links carry both values in the fragment query, so they never reach a server log.
    const params = this.route.snapshot.queryParams;
    this.form.patchValue({ email: params["email"] ?? "", code: params["code"] ?? "" });
    if (params["code"] !== undefined) {
      // Do not leave the one-time code in the address bar and the browser history.
      void this.router.navigate([], {
        relativeTo: this.route,
        queryParams: {},
        replaceUrl: true,
      });
    }
  }

  protected submit = async () => {
    this.form.markAllAsTouched();
    if (this.form.invalid) {
      return;
    }
    const email = (this.form.value.email ?? "").trim().toLowerCase();
    try {
      const token = await this.api.redeem(email, this.form.value.code ?? "");
      this.error.set(null);
      await this.router.navigate(["/finish-signup"], finishSignupParams(email, token));
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
  };
}
