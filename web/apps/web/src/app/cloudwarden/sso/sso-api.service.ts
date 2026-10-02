// Cloudwarden: client for the organisation SSO settings and claimed domains (web/NOTICE.md).
// Written for Cloudwarden; the server contract is the official `organizations/{id}/sso` and
// `organizations/{id}/domain` endpoints plus Cloudwarden's `sso/test`.
import { Injectable, inject } from "@angular/core";

import { ApiService } from "@bitwarden/common/abstractions/api.service";

export interface SsoUrls {
  callbackPath: string;
  signedOutCallbackPath: string;
  spEntityId: string;
  spEntityIdStatic: string;
  spMetadataUrl: string;
  spAcsUrl: string;
}

/** `SsoConfigApi` as the server stores it. */
export interface SsoConfigData {
  configType?: number | null;
  memberDecryptionType?: number | null;
  keyConnectorUrl?: string | null;
  authority?: string | null;
  clientId?: string | null;
  clientSecret?: string | null;
  metadataAddress?: string | null;
  redirectBehavior?: number | null;
  getClaimsFromUserInfoEndpoint?: boolean | null;
  additionalScopes?: string | null;
  additionalUserIdClaimTypes?: string | null;
  additionalEmailClaimTypes?: string | null;
  additionalNameClaimTypes?: string | null;
  acrValues?: string | null;
  expectedReturnAcrValue?: string | null;
  spUniqueEntityId?: boolean | null;
  spNameIdFormat?: number | null;
  spOutboundSigningAlgorithm?: string | null;
  spSigningBehavior?: number | null;
  spMinIncomingSigningAlgorithm?: string | null;
  spWantAssertionsSigned?: boolean | null;
  spValidateCertificates?: boolean | null;
  idpEntityId?: string | null;
  idpBindingType?: number | null;
  idpSingleSignOnServiceUrl?: string | null;
  idpSingleLogoutServiceUrl?: string | null;
  idpX509PublicCert?: string | null;
  idpOutboundSigningAlgorithm?: string | null;
  idpAllowUnsolicitedAuthnResponse?: boolean | null;
  idpDisableOutboundLogoutRequests?: boolean | null;
  idpWantAuthnRequestsSigned?: boolean | null;
}

export interface OrganizationSso {
  enabled: boolean;
  identifier: string | null;
  data: SsoConfigData | null;
  urls: SsoUrls;
}

export interface SsoTestResult {
  success: boolean;
  problems: string[];
  issuer: string | null;
}

export interface OrganizationDomain {
  id: string;
  organizationId: string;
  txt: string;
  domainName: string;
  creationDate: string;
  nextRunDate: string;
  jobRunCount: number;
  verifiedDate: string | null;
  lastCheckedDate: string | null;
}

/** Reads a property whether the server sent it camelCase or PascalCase. */
function prop<T>(obj: Record<string, unknown>, name: string): T {
  const pascal = name.charAt(0).toUpperCase() + name.slice(1);
  return (obj[name] ?? obj[pascal]) as T;
}

@Injectable({ providedIn: "root" })
export class CloudwardenSsoApiService {
  private readonly apiService = inject(ApiService);

  async getSso(orgId: string): Promise<OrganizationSso> {
    const r = (await this.apiService.send(
      "GET",
      `/organizations/${orgId}/sso`,
      null,
      true,
      true,
    )) as Record<string, unknown>;
    return {
      enabled: prop<boolean>(r, "enabled") ?? false,
      identifier: prop<string | null>(r, "identifier") ?? null,
      data: prop<SsoConfigData | null>(r, "data") ?? null,
      urls: prop<SsoUrls>(r, "urls"),
    };
  }

  async saveSso(
    orgId: string,
    body: { enabled: boolean; identifier: string | null; data: SsoConfigData },
  ) {
    await this.apiService.send(
      "POST",
      `/organizations/${orgId}/sso`,
      body,
      true,
      true,
    );
  }

  async testSso(orgId: string, data: SsoConfigData): Promise<SsoTestResult> {
    return (await this.apiService.send(
      "POST",
      `/organizations/${orgId}/sso/test`,
      { data },
      true,
      true,
    )) as SsoTestResult;
  }

  async listDomains(orgId: string): Promise<OrganizationDomain[]> {
    const r = (await this.apiService.send(
      "GET",
      `/organizations/${orgId}/domain`,
      null,
      true,
      true,
    )) as {
      data: OrganizationDomain[];
    };
    return r.data ?? [];
  }

  async addDomain(
    orgId: string,
    domainName: string,
  ): Promise<OrganizationDomain> {
    return (await this.apiService.send(
      "POST",
      `/organizations/${orgId}/domain`,
      { domainName },
      true,
      true,
    )) as OrganizationDomain;
  }

  async verifyDomain(orgId: string, id: string): Promise<OrganizationDomain> {
    return (await this.apiService.send(
      "POST",
      `/organizations/${orgId}/domain/${id}/verify`,
      null,
      true,
      true,
    )) as OrganizationDomain;
  }

  async removeDomain(orgId: string, id: string): Promise<void> {
    await this.apiService.send(
      "DELETE",
      `/organizations/${orgId}/domain/${id}`,
      null,
      true,
      false,
    );
  }

  /** Checks a key connector answers (`GET {url}/alive`) from the administrator's browser. */
  async keyConnectorAlive(url: string): Promise<boolean> {
    try {
      const res = await fetch(
        new URL("alive", url.endsWith("/") ? url : `${url}/`),
        { cache: "no-store" },
      );
      return res.status === 200;
    } catch {
      return false;
    }
  }
}
