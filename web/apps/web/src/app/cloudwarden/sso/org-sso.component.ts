// Cloudwarden: organisation single sign-on settings (OIDC and SAML 2.0), member decryption
// options and a configuration test. Written for Cloudwarden (web/NOTICE.md); upstream's SSO
// settings screen is not used.
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
import { CopyClickDirective, ToastService } from "@bitwarden/components";

import { HeaderModule } from "../../layouts/header/header.module";
import { SharedModule } from "../../shared";

import {
  CloudwardenSsoApiService,
  SsoConfigData,
  SsoTestResult,
  SsoUrls,
} from "./sso-api.service";

const SIG = {
  sha1: "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
  sha256: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  sha384: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
  sha512: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
};

@Component({
  selector: "cw-org-sso",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [SharedModule, HeaderModule, CopyClickDirective],
  template: `
    <app-header></app-header>
    <bit-container>
      @if (loadError()) {
        <bit-callout type="danger">{{ loadError() }}</bit-callout>
      }
      <form [formGroup]="form" [bitSubmit]="save" class="tw-max-w-3xl">
        <p bitTypography="body1">{{ "cwSsoIntro" | i18n }}</p>

        <bit-form-control>
          <input
            type="checkbox"
            bitCheckbox
            formControlName="enabled"
            data-testid="cw-sso-enabled"
          />
          <bit-label>{{ "allowSso" | i18n }}</bit-label>
          <bit-hint>{{ "allowSsoDesc" | i18n }}</bit-hint>
        </bit-form-control>

        <bit-form-field>
          <bit-label>{{ "ssoIdentifier" | i18n }}</bit-label>
          <input
            bitInput
            type="text"
            formControlName="identifier"
            data-testid="cw-sso-identifier"
          />
          <bit-hint>{{ "ssoIdentifierHint" | i18n }}</bit-hint>
        </bit-form-field>

        <h2 bitTypography="h2" class="tw-mt-6">
          {{ "memberDecryptionOption" | i18n }}
        </h2>
        <bit-radio-group
          formControlName="memberDecryptionType"
          data-testid="cw-sso-decryption"
        >
          <bit-radio-button [value]="0">
            <bit-label>{{ "masterPass" | i18n }}</bit-label>
            <bit-hint>{{ "memberDecryptionPassDesc" | i18n }}</bit-hint>
          </bit-radio-button>
          <bit-radio-button [value]="2">
            <bit-label>{{ "trustedDevices" | i18n }}</bit-label>
            <bit-hint>{{ "cwTdeDesc" | i18n }}</bit-hint>
          </bit-radio-button>
          <bit-radio-button [value]="1">
            <bit-label>{{ "keyConnector" | i18n }}</bit-label>
            <bit-hint>{{ "cwKeyConnectorDesc" | i18n }}</bit-hint>
          </bit-radio-button>
        </bit-radio-group>
        @if (form.value.memberDecryptionType === 1) {
          <bit-callout type="warning">{{
            "keyConnectorWarning" | i18n
          }}</bit-callout>
          <div class="tw-flex tw-items-start tw-gap-2">
            <bit-form-field class="tw-grow">
              <bit-label>{{ "keyConnectorUrl" | i18n }}</bit-label>
              <input
                bitInput
                type="text"
                formControlName="keyConnectorUrl"
                data-testid="cw-sso-kc-url"
              />
            </bit-form-field>
            <button
              type="button"
              bitButton
              buttonType="secondary"
              class="tw-mt-6"
              (click)="testKeyConnector()"
            >
              {{ "keyConnectorTest" | i18n }}
            </button>
          </div>
        }

        <h2 bitTypography="h2" class="tw-mt-6">{{ "type" | i18n }}</h2>
        <bit-form-field>
          <bit-label>{{ "type" | i18n }}</bit-label>
          <bit-select formControlName="configType" data-testid="cw-sso-type">
            <bit-option [value]="1" label="OpenID Connect"></bit-option>
            <bit-option [value]="2" label="SAML 2.0"></bit-option>
          </bit-select>
        </bit-form-field>

        @if (form.value.configType === 1) {
          <h3 bitTypography="h3" class="tw-mt-4">
            {{ "openIdConnectConfig" | i18n }}
          </h3>
          @if (urls(); as u) {
            <bit-form-field>
              <bit-label>{{ "callbackPath" | i18n }}</bit-label>
              <input
                bitInput
                type="text"
                [value]="u.callbackPath"
                readonly
                data-testid="cw-sso-callback"
              />
              <button
                type="button"
                bitSuffix
                bitIconButton="bwi-clone"
                [appCopyClick]="u.callbackPath"
                [label]="'copyValue' | i18n"
              ></button>
            </bit-form-field>
            <bit-form-field>
              <bit-label>{{ "signedOutCallbackPath" | i18n }}</bit-label>
              <input
                bitInput
                type="text"
                [value]="u.signedOutCallbackPath"
                readonly
              />
              <button
                type="button"
                bitSuffix
                bitIconButton="bwi-clone"
                [appCopyClick]="u.signedOutCallbackPath"
                [label]="'copyValue' | i18n"
              ></button>
            </bit-form-field>
          }
          <bit-form-field>
            <bit-label>{{ "authority" | i18n }}</bit-label>
            <input
              bitInput
              type="text"
              formControlName="authority"
              data-testid="cw-sso-authority"
            />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "clientId" | i18n }}</bit-label>
            <input
              bitInput
              type="text"
              formControlName="clientId"
              data-testid="cw-sso-client-id"
            />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "clientSecret" | i18n }}</bit-label>
            <input
              bitInput
              type="password"
              formControlName="clientSecret"
              data-testid="cw-sso-client-secret"
            />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "metadataAddress" | i18n }}</bit-label>
            <input bitInput type="text" formControlName="metadataAddress" />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "oidcRedirectBehavior" | i18n }}</bit-label>
            <bit-select formControlName="redirectBehavior">
              <bit-option [value]="0" label="Redirect GET"></bit-option>
              <bit-option [value]="1" label="Form POST"></bit-option>
            </bit-select>
          </bit-form-field>
          <bit-form-control>
            <input
              type="checkbox"
              bitCheckbox
              formControlName="getClaimsFromUserInfoEndpoint"
            />
            <bit-label>{{ "getClaimsFromUserInfoEndpoint" | i18n }}</bit-label>
          </bit-form-control>
          <bit-form-control>
            <input
              type="checkbox"
              bitCheckbox
              formControlName="allowUnverifiedEmail"
            />
            <bit-label>{{ "cwAllowUnverifiedEmail" | i18n }}</bit-label>
            <bit-hint>{{ "cwAllowUnverifiedEmailHint" | i18n }}</bit-hint>
          </bit-form-control>
          <h4 bitTypography="h4" class="tw-mt-2">
            {{ "openIdOptionalCustomizations" | i18n }}
          </h4>
          <bit-form-field>
            <bit-label>{{ "cwAdditionalScopes" | i18n }}</bit-label>
            <input bitInput type="text" formControlName="additionalScopes" />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "additionalUserIdClaimTypes" | i18n }}</bit-label>
            <input
              bitInput
              type="text"
              formControlName="additionalUserIdClaimTypes"
            />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "additionalEmailClaimTypes" | i18n }}</bit-label>
            <input
              bitInput
              type="text"
              formControlName="additionalEmailClaimTypes"
            />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "additionalNameClaimTypes" | i18n }}</bit-label>
            <input
              bitInput
              type="text"
              formControlName="additionalNameClaimTypes"
            />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "acrValues" | i18n }}</bit-label>
            <input bitInput type="text" formControlName="acrValues" />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "expectedReturnAcrValue" | i18n }}</bit-label>
            <input
              bitInput
              type="text"
              formControlName="expectedReturnAcrValue"
            />
          </bit-form-field>
        }

        @if (form.value.configType === 2) {
          <h3 bitTypography="h3" class="tw-mt-4">
            {{ "samlSpConfig" | i18n }}
          </h3>
          <bit-form-control>
            <input
              type="checkbox"
              bitCheckbox
              formControlName="spUniqueEntityId"
            />
            <bit-label>{{ "spUniqueEntityId" | i18n }}</bit-label>
            <bit-hint>{{ "spUniqueEntityIdDesc" | i18n }}</bit-hint>
          </bit-form-control>
          @if (urls(); as u) {
            <bit-form-field>
              <bit-label>{{ "spEntityId" | i18n }}</bit-label>
              <input
                bitInput
                type="text"
                readonly
                data-testid="cw-sso-sp-entity"
                [value]="
                  form.value.spUniqueEntityId
                    ? u.spEntityId
                    : u.spEntityIdStatic
                "
              />
              <button
                type="button"
                bitSuffix
                bitIconButton="bwi-clone"
                [appCopyClick]="
                  form.value.spUniqueEntityId
                    ? u.spEntityId
                    : u.spEntityIdStatic
                "
                [label]="'copyValue' | i18n"
              ></button>
            </bit-form-field>
            <bit-form-field>
              <bit-label>{{ "spMetadataUrl" | i18n }}</bit-label>
              <input bitInput type="text" [value]="u.spMetadataUrl" readonly />
              <button
                type="button"
                bitSuffix
                bitIconButton="bwi-clone"
                [appCopyClick]="u.spMetadataUrl"
                [label]="'copyValue' | i18n"
              ></button>
            </bit-form-field>
            <bit-form-field>
              <bit-label>{{ "spAcsUrl" | i18n }}</bit-label>
              <input
                bitInput
                type="text"
                [value]="u.spAcsUrl"
                readonly
                data-testid="cw-sso-acs"
              />
              <button
                type="button"
                bitSuffix
                bitIconButton="bwi-clone"
                [appCopyClick]="u.spAcsUrl"
                [label]="'copyValue' | i18n"
              ></button>
            </bit-form-field>
          }
          <bit-form-field>
            <bit-label>{{ "spNameIdFormat" | i18n }}</bit-label>
            <bit-select formControlName="spNameIdFormat">
              @for (f of nameIdFormats; track f.value) {
                <bit-option [value]="f.value" [label]="f.label"></bit-option>
              }
            </bit-select>
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "spOutboundSigningAlgorithm" | i18n }}</bit-label>
            <bit-select formControlName="spOutboundSigningAlgorithm">
              @for (a of algorithms; track a.value) {
                <bit-option [value]="a.value" [label]="a.label"></bit-option>
              }
            </bit-select>
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "spSigningBehavior" | i18n }}</bit-label>
            <bit-select formControlName="spSigningBehavior">
              <bit-option
                [value]="0"
                [label]="'cwSignIfIdpWants' | i18n"
              ></bit-option>
              <bit-option
                [value]="1"
                [label]="'cwSignAlways' | i18n"
              ></bit-option>
              <bit-option
                [value]="3"
                [label]="'cwSignNever' | i18n"
              ></bit-option>
            </bit-select>
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "spMinIncomingSigningAlgorithm" | i18n }}</bit-label>
            <bit-select formControlName="spMinIncomingSigningAlgorithm">
              @for (a of algorithms; track a.value) {
                <bit-option [value]="a.value" [label]="a.label"></bit-option>
              }
            </bit-select>
          </bit-form-field>
          <bit-form-control>
            <input
              type="checkbox"
              bitCheckbox
              formControlName="spWantAssertionsSigned"
            />
            <bit-label>{{ "spWantAssertionsSigned" | i18n }}</bit-label>
          </bit-form-control>
          <bit-form-control>
            <input
              type="checkbox"
              bitCheckbox
              formControlName="spValidateCertificates"
            />
            <bit-label>{{ "spValidateCertificates" | i18n }}</bit-label>
            <bit-hint>{{ "cwValidateCertificatesHint" | i18n }}</bit-hint>
          </bit-form-control>

          <h3 bitTypography="h3" class="tw-mt-4">
            {{ "samlIdpConfig" | i18n }}
          </h3>
          <bit-form-field>
            <bit-label>{{ "idpEntityId" | i18n }}</bit-label>
            <input
              bitInput
              type="text"
              formControlName="idpEntityId"
              data-testid="cw-sso-idp-entity"
            />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "idpBindingType" | i18n }}</bit-label>
            <bit-select formControlName="idpBindingType">
              <bit-option [value]="1" label="Redirect"></bit-option>
              <bit-option [value]="2" label="HTTP POST"></bit-option>
            </bit-select>
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "idpSingleSignOnServiceUrl" | i18n }}</bit-label>
            <input
              bitInput
              type="text"
              formControlName="idpSingleSignOnServiceUrl"
              data-testid="cw-sso-idp-sso-url"
            />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "idpSingleLogoutServiceUrl" | i18n }}</bit-label>
            <input
              bitInput
              type="text"
              formControlName="idpSingleLogoutServiceUrl"
            />
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "idpX509PublicCert" | i18n }}</bit-label>
            <textarea
              bitInput
              rows="6"
              class="tw-font-mono"
              formControlName="idpX509PublicCert"
              data-testid="cw-sso-idp-cert"
            ></textarea>
          </bit-form-field>
          <bit-form-field>
            <bit-label>{{ "idpOutboundSigningAlgorithm" | i18n }}</bit-label>
            <bit-select formControlName="idpOutboundSigningAlgorithm">
              @for (a of algorithms; track a.value) {
                <bit-option [value]="a.value" [label]="a.label"></bit-option>
              }
            </bit-select>
          </bit-form-field>
          <bit-form-control>
            <input
              type="checkbox"
              bitCheckbox
              formControlName="idpAllowUnsolicitedAuthnResponse"
            />
            <bit-label>{{
              "idpAllowUnsolicitedAuthnResponse" | i18n
            }}</bit-label>
          </bit-form-control>
          <bit-form-control>
            <input
              type="checkbox"
              bitCheckbox
              formControlName="idpAllowOutboundLogoutRequests"
            />
            <bit-label>{{ "idpAllowOutboundLogoutRequests" | i18n }}</bit-label>
          </bit-form-control>
          <bit-form-control>
            <input
              type="checkbox"
              bitCheckbox
              formControlName="idpWantAuthnRequestsSigned"
            />
            <bit-label>{{ "idpSignAuthenticationRequests" | i18n }}</bit-label>
          </bit-form-control>
        }

        @if (testResult(); as t) {
          <bit-callout
            [type]="t.success ? 'success' : 'danger'"
            data-testid="cw-sso-test-result"
          >
            @if (t.success) {
              {{ "cwSsoTestOk" | i18n: t.issuer ?? "" }}
            } @else {
              <ul class="tw-mb-0">
                @for (p of t.problems; track p) {
                  <li>{{ p }}</li>
                }
              </ul>
            }
          </bit-callout>
        }

        <div class="tw-flex tw-gap-2 tw-mt-4">
          <button
            type="submit"
            bitButton
            bitFormButton
            buttonType="primary"
            data-testid="cw-sso-save"
          >
            {{ "save" | i18n }}
          </button>
          <button
            type="button"
            bitButton
            bitFormButton
            buttonType="secondary"
            [bitAction]="test"
            data-testid="cw-sso-test"
          >
            {{ "cwSsoTest" | i18n }}
          </button>
        </div>
      </form>
    </bit-container>
  `,
})
export class OrgSsoComponent implements OnInit {
  private readonly api = inject(CloudwardenSsoApiService);
  private readonly route = inject(ActivatedRoute);
  private readonly toast = inject(ToastService);
  private readonly i18n = inject(I18nService);

  protected readonly urls = signal<SsoUrls | null>(null);
  protected readonly loadError = signal<string | null>(null);
  protected readonly testResult = signal<SsoTestResult | null>(null);

  protected readonly algorithms = [
    { value: SIG.sha1, label: "rsa-sha1" },
    { value: SIG.sha256, label: "rsa-sha256" },
    { value: SIG.sha384, label: "rsa-sha384" },
    { value: SIG.sha512, label: "rsa-sha512" },
  ];
  protected readonly nameIdFormats = [
    { value: 0, label: "Not configured" },
    { value: 1, label: "Unspecified" },
    { value: 2, label: "Email address" },
    { value: 3, label: "X.509 subject name" },
    { value: 4, label: "Windows domain qualified name" },
    { value: 5, label: "Kerberos principal name" },
    { value: 6, label: "Entity identifier" },
    { value: 7, label: "Persistent" },
    { value: 8, label: "Transient" },
  ];

  protected readonly form = inject(FormBuilder).group({
    enabled: [false],
    identifier: ["", [Validators.maxLength(50)]],
    memberDecryptionType: [0],
    keyConnectorUrl: [""],
    configType: [1],
    authority: [""],
    clientId: [""],
    clientSecret: [""],
    metadataAddress: [""],
    redirectBehavior: [0],
    getClaimsFromUserInfoEndpoint: [false],
    allowUnverifiedEmail: [false],
    additionalScopes: [""],
    additionalUserIdClaimTypes: [""],
    additionalEmailClaimTypes: [""],
    additionalNameClaimTypes: [""],
    acrValues: [""],
    expectedReturnAcrValue: [""],
    spUniqueEntityId: [true],
    spNameIdFormat: [0],
    spOutboundSigningAlgorithm: [SIG.sha256],
    spSigningBehavior: [0],
    spMinIncomingSigningAlgorithm: [SIG.sha256],
    spWantAssertionsSigned: [true],
    spValidateCertificates: [false],
    idpEntityId: [""],
    idpBindingType: [1],
    idpSingleSignOnServiceUrl: [""],
    idpSingleLogoutServiceUrl: [""],
    idpX509PublicCert: [""],
    idpOutboundSigningAlgorithm: [SIG.sha256],
    idpAllowUnsolicitedAuthnResponse: [false],
    idpAllowOutboundLogoutRequests: [true],
    idpWantAuthnRequestsSigned: [false],
  });

  private get orgId(): string {
    return (
      this.route.pathFromRoot
        .map((r) => r.snapshot.paramMap.get("organizationId"))
        .find((id) => !!id) ?? ""
    );
  }

  async ngOnInit() {
    try {
      const sso = await this.api.getSso(this.orgId);
      this.urls.set(sso.urls);
      const d = sso.data ?? {};
      this.form.patchValue({
        enabled: sso.enabled,
        identifier: sso.identifier ?? "",
        memberDecryptionType: d.memberDecryptionType ?? 0,
        keyConnectorUrl: d.keyConnectorUrl ?? "",
        configType: d.configType || 1,
        authority: d.authority ?? "",
        clientId: d.clientId ?? "",
        clientSecret: d.clientSecret ?? "",
        metadataAddress: d.metadataAddress ?? "",
        redirectBehavior: d.redirectBehavior ?? 0,
        getClaimsFromUserInfoEndpoint: d.getClaimsFromUserInfoEndpoint ?? false,
        allowUnverifiedEmail: d.allowUnverifiedEmail ?? false,
        additionalScopes: d.additionalScopes ?? "",
        additionalUserIdClaimTypes: d.additionalUserIdClaimTypes ?? "",
        additionalEmailClaimTypes: d.additionalEmailClaimTypes ?? "",
        additionalNameClaimTypes: d.additionalNameClaimTypes ?? "",
        acrValues: d.acrValues ?? "",
        expectedReturnAcrValue: d.expectedReturnAcrValue ?? "",
        spUniqueEntityId: d.spUniqueEntityId ?? true,
        spNameIdFormat: d.spNameIdFormat ?? 0,
        spOutboundSigningAlgorithm: d.spOutboundSigningAlgorithm || SIG.sha256,
        spSigningBehavior: d.spSigningBehavior ?? 0,
        spMinIncomingSigningAlgorithm:
          d.spMinIncomingSigningAlgorithm || SIG.sha256,
        spWantAssertionsSigned: d.spWantAssertionsSigned ?? true,
        spValidateCertificates: d.spValidateCertificates ?? false,
        idpEntityId: d.idpEntityId ?? "",
        idpBindingType: d.idpBindingType || 1,
        idpSingleSignOnServiceUrl: d.idpSingleSignOnServiceUrl ?? "",
        idpSingleLogoutServiceUrl: d.idpSingleLogoutServiceUrl ?? "",
        idpX509PublicCert: d.idpX509PublicCert ?? "",
        idpOutboundSigningAlgorithm:
          d.idpOutboundSigningAlgorithm || SIG.sha256,
        idpAllowUnsolicitedAuthnResponse:
          d.idpAllowUnsolicitedAuthnResponse ?? false,
        idpAllowOutboundLogoutRequests: !(
          d.idpDisableOutboundLogoutRequests ?? false
        ),
        idpWantAuthnRequestsSigned: d.idpWantAuthnRequestsSigned ?? false,
      });
    } catch (e) {
      this.loadError.set((e as Error)?.message ?? String(e));
    }
  }

  /** The `SsoConfigApi` body for the current form. */
  private data(): SsoConfigData {
    const v = this.form.getRawValue();
    const text = (s: string | null | undefined) => (s ?? "").trim() || null;
    const common = {
      configType: v.configType,
      memberDecryptionType: v.memberDecryptionType,
      keyConnectorUrl:
        v.memberDecryptionType === 1 ? text(v.keyConnectorUrl) : null,
    };
    if (v.configType === 2) {
      return {
        ...common,
        spUniqueEntityId: v.spUniqueEntityId,
        spNameIdFormat: v.spNameIdFormat,
        spOutboundSigningAlgorithm: v.spOutboundSigningAlgorithm,
        spSigningBehavior: v.spSigningBehavior,
        spMinIncomingSigningAlgorithm: v.spMinIncomingSigningAlgorithm,
        spWantAssertionsSigned: v.spWantAssertionsSigned,
        spValidateCertificates: v.spValidateCertificates,
        idpEntityId: text(v.idpEntityId),
        idpBindingType: v.idpBindingType,
        idpSingleSignOnServiceUrl: text(v.idpSingleSignOnServiceUrl),
        idpSingleLogoutServiceUrl: text(v.idpSingleLogoutServiceUrl),
        idpX509PublicCert: text(v.idpX509PublicCert),
        idpOutboundSigningAlgorithm: v.idpOutboundSigningAlgorithm,
        idpAllowUnsolicitedAuthnResponse: v.idpAllowUnsolicitedAuthnResponse,
        idpDisableOutboundLogoutRequests: !v.idpAllowOutboundLogoutRequests,
        idpWantAuthnRequestsSigned: v.idpWantAuthnRequestsSigned,
      };
    }
    return {
      ...common,
      authority: text(v.authority),
      clientId: text(v.clientId),
      clientSecret: text(v.clientSecret),
      metadataAddress: text(v.metadataAddress),
      redirectBehavior: v.redirectBehavior,
      getClaimsFromUserInfoEndpoint: v.getClaimsFromUserInfoEndpoint,
      allowUnverifiedEmail: v.allowUnverifiedEmail,
      additionalScopes: text(v.additionalScopes),
      additionalUserIdClaimTypes: text(v.additionalUserIdClaimTypes),
      additionalEmailClaimTypes: text(v.additionalEmailClaimTypes),
      additionalNameClaimTypes: text(v.additionalNameClaimTypes),
      acrValues: text(v.acrValues),
      expectedReturnAcrValue: text(v.expectedReturnAcrValue),
    };
  }

  protected save = async () => {
    const v = this.form.getRawValue();
    try {
      await this.api.saveSso(this.orgId, {
        enabled: v.enabled ?? false,
        identifier: (v.identifier ?? "").trim() || null,
        data: this.data(),
      });
      this.toast.showToast({
        variant: "success",
        message: this.i18n.t("ssoSettingsSaved"),
      });
    } catch (e) {
      this.toast.showToast({ variant: "error", message: errorText(e) });
    }
  };

  protected test = async () => {
    try {
      this.testResult.set(await this.api.testSso(this.orgId, this.data()));
    } catch (e) {
      this.testResult.set({
        success: false,
        problems: [errorText(e)],
        issuer: null,
      });
    }
  };

  protected async testKeyConnector() {
    const ok = await this.api.keyConnectorAlive(
      this.form.value.keyConnectorUrl ?? "",
    );
    this.toast.showToast({
      variant: ok ? "success" : "error",
      message: this.i18n.t(
        ok ? "keyConnectorTestSuccess" : "keyConnectorTestFail",
      ),
    });
  }
}

/** The server's validation messages, flattened. */
function errorText(e: unknown): string {
  const err = e as {
    message?: string;
    validationErrors?: Record<string, string[]>;
  };
  const details = Object.values(err?.validationErrors ?? {}).flat();
  return [err?.message, ...details].filter(Boolean).join(" ");
}
