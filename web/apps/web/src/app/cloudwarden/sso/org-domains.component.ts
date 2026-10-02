// Cloudwarden: claimed domains of an organisation, verified with a DNS TXT record. Written for
// Cloudwarden (web/NOTICE.md); upstream's domain verification screen is not used.
import { DatePipe } from "@angular/common";
import {
  ChangeDetectionStrategy,
  Component,
  OnInit,
  inject,
  signal,
} from "@angular/core";
import { FormBuilder, Validators } from "@angular/forms";
import { ActivatedRoute } from "@angular/router";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import {
  CopyClickDirective,
  DialogService,
  ToastService,
} from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import {
  CloudwardenSsoApiService,
  OrganizationDomain,
} from "./sso-api.service";

@Component({
  selector: "cw-org-domains",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, DatePipe, CopyClickDirective],
  template: `
    <app-header></app-header>
    <bit-container>
      <p bitTypography="body1">{{ "cwDomainsIntro" | i18n }}</p>
      <form
        [formGroup]="form"
        [bitSubmit]="add"
        class="tw-flex tw-items-start tw-gap-2 tw-max-w-xl"
      >
        <bit-form-field class="tw-grow">
          <bit-label>{{ "domainName" | i18n }}</bit-label>
          <input
            bitInput
            type="text"
            formControlName="domainName"
            placeholder="example.com"
            data-testid="cw-domain-name"
          />
        </bit-form-field>
        <button
          type="submit"
          bitButton
          bitFormButton
          buttonType="primary"
          class="tw-mt-6"
          data-testid="cw-domain-add"
        >
          {{ "addDomain" | i18n }}
        </button>
      </form>
      @if (error()) {
        <bit-callout type="danger">{{ error() }}</bit-callout>
      }
      @if (domains().length === 0) {
        <p bitTypography="body2" class="tw-text-muted">
          {{ "noDomainsSubText" | i18n }}
        </p>
      } @else {
        <bit-table>
          <ng-container header>
            <tr>
              <th bitCell>{{ "domainNameTh" | i18n }}</th>
              <th bitCell>{{ "domainStatusTh" | i18n }}</th>
              <th bitCell>{{ "dnsTxtRecord" | i18n }}</th>
              <th bitCell>{{ "lastChecked" | i18n }}</th>
              <th bitCell class="tw-text-right">{{ "options" | i18n }}</th>
            </tr>
          </ng-container>
          <ng-template body>
            @for (d of domains(); track d.id) {
              <tr bitRow data-testid="cw-domain-row">
                <td bitCell>{{ d.domainName }}</td>
                <td bitCell>
                  @if (d.verifiedDate) {
                    <span bitBadge variant="success">{{
                      "verified" | i18n
                    }}</span>
                  } @else {
                    <span bitBadge variant="warning">{{
                      "unverified" | i18n
                    }}</span>
                  }
                </td>
                <td bitCell>
                  <code class="tw-break-all">{{ d.txt }}</code>
                  <button
                    type="button"
                    bitIconButton="bwi-clone"
                    size="small"
                    [appCopyClick]="d.txt"
                    [label]="'copyDnsTxtRecord' | i18n"
                  ></button>
                </td>
                <td bitCell>
                  {{
                    d.lastCheckedDate
                      ? (d.lastCheckedDate | date: "short")
                      : "-"
                  }}
                </td>
                <td bitCell class="tw-text-right tw-whitespace-nowrap">
                  @if (!d.verifiedDate) {
                    <button
                      type="button"
                      bitButton
                      buttonType="secondary"
                      (click)="verify(d)"
                      data-testid="cw-domain-verify"
                    >
                      {{ "cwVerify" | i18n }}
                    </button>
                  }
                  <button
                    type="button"
                    bitButton
                    buttonType="danger"
                    (click)="remove(d)"
                  >
                    {{ "remove" | i18n }}
                  </button>
                </td>
              </tr>
            }
          </ng-template>
        </bit-table>
        <p bitTypography="helper" class="tw-mt-2">
          {{ "cwDomainsTxtHelp" | i18n }}
        </p>
      }
    </bit-container>
  `,
})
export class OrgDomainsComponent implements OnInit {
  private readonly api = inject(CloudwardenSsoApiService);
  private readonly route = inject(ActivatedRoute);
  private readonly toast = inject(ToastService);
  private readonly dialog = inject(DialogService);
  private readonly i18n = inject(I18nService);

  protected readonly domains = signal<OrganizationDomain[]>([]);
  protected readonly error = signal<string | null>(null);
  protected readonly form = inject(FormBuilder).group({
    domainName: ["", [Validators.required, Validators.maxLength(255)]],
  });

  private get orgId(): string {
    return (
      this.route.pathFromRoot
        .map((r) => r.snapshot.paramMap.get("organizationId"))
        .find((id) => !!id) ?? ""
    );
  }

  async ngOnInit() {
    await this.load();
  }

  private async load() {
    try {
      this.domains.set(await this.api.listDomains(this.orgId));
      this.error.set(null);
    } catch (e) {
      this.error.set((e as Error)?.message ?? String(e));
    }
  }

  protected add = async () => {
    this.form.markAllAsTouched();
    if (this.form.invalid) {
      return;
    }
    try {
      await this.api.addDomain(this.orgId, this.form.value.domainName ?? "");
      this.toast.showToast({
        variant: "success",
        message: this.i18n.t("domainSaved"),
      });
      this.form.reset();
    } catch (e) {
      this.toast.showToast({
        variant: "error",
        message: (e as Error)?.message ?? String(e),
      });
    }
    await this.load();
  };

  protected async verify(d: OrganizationDomain) {
    try {
      const r = await this.api.verifyDomain(this.orgId, d.id);
      this.toast.showToast({
        variant: r.verifiedDate ? "success" : "warning",
        message: this.i18n.t(
          r.verifiedDate ? "domainVerified" : "cwDomainNotYetVerified",
          d.domainName,
        ),
      });
    } catch (e) {
      this.toast.showToast({
        variant: "error",
        message: (e as Error)?.message ?? String(e),
      });
    }
    await this.load();
  }

  protected async remove(d: OrganizationDomain) {
    const ok = await this.dialog.openSimpleDialog({
      title: { key: "removeDomain" },
      content: { key: "removeDomainWarning" },
      type: "warning",
    });
    if (!ok) {
      return;
    }
    try {
      await this.api.removeDomain(this.orgId, d.id);
      this.toast.showToast({
        variant: "success",
        message: this.i18n.t("domainRemoved"),
      });
    } catch (e) {
      this.toast.showToast({
        variant: "error",
        message: (e as Error)?.message ?? String(e),
      });
    }
    await this.load();
  }
}
