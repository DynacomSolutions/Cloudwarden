// Cloudwarden: client for the SCIM settings and event integrations API (web/NOTICE.md,
// docs/integrations.md). These screens are Cloudwarden's own; upstream's are not open source.
import { Injectable, inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { OrganizationApiKeyRequest } from "@bitwarden/common/admin-console/models/request/organization-api-key.request";

export type IntegrationType = "webhook" | "splunk" | "datadog" | "sentinel";

export interface ScimConfig {
  enabled: boolean;
  provider: number | null;
  scimUrl: string;
  hasApiKey: boolean;
  apiKeyRevisionDate: string | null;
}

export interface EventIntegration {
  id: string;
  type: IntegrationType;
  name: string;
  enabled: boolean;
  config: Record<string, string | boolean | null>;
  eventTypes: number[] | null;
  status: {
    failureCount: number;
    nextAttemptDate: string | null;
    lastError: string | null;
    lastSuccessDate: string | null;
  };
  /** Present only after creation or rotation of a webhook. */
  signingSecret?: string | null;
}

export interface IntegrationInput {
  type?: IntegrationType;
  name: string;
  enabled: boolean;
  config: Record<string, string | boolean | null>;
  secrets: Record<string, string | null>;
  eventTypes: number[] | null;
}

/** SCIM key type of the organisation API key endpoints. */
export const SCIM_KEY_TYPE = 2;

@Injectable({ providedIn: "root" })
export class OrgIntegrationsApiService {
  private readonly api = inject(ApiService);

  private send<T = any>(method: string, path: string, body: unknown = null): Promise<T> {
    return this.api.send(method as "GET", path, body, true, method !== "DELETE");
  }

  getScimConfig(orgId: string): Promise<ScimConfig> {
    return this.send("GET", `/organizations/${orgId}/scim-config`);
  }

  saveScimConfig(orgId: string, enabled: boolean, provider: number | null): Promise<ScimConfig> {
    return this.send("PUT", `/organizations/${orgId}/scim-config`, { enabled, provider });
  }

  async scimKey(orgId: string, request: OrganizationApiKeyRequest, rotate: boolean) {
    request.type = SCIM_KEY_TYPE;
    const r = await this.send<{ apiKey?: string; ApiKey?: string }>(
      "POST",
      `/organizations/${orgId}/${rotate ? "rotate-api-key" : "api-key"}`,
      request,
    );
    return (r.apiKey ?? r.ApiKey) as string;
  }

  async list(orgId: string): Promise<EventIntegration[]> {
    const r = await this.send<{ data: EventIntegration[] }>(
      "GET",
      `/organizations/${orgId}/event-integrations`,
    );
    return r.data;
  }

  create(orgId: string, input: IntegrationInput): Promise<EventIntegration> {
    return this.send("POST", `/organizations/${orgId}/event-integrations`, input);
  }

  update(orgId: string, id: string, input: IntegrationInput): Promise<EventIntegration> {
    return this.send("PUT", `/organizations/${orgId}/event-integrations/${id}`, input);
  }

  remove(orgId: string, id: string): Promise<void> {
    return this.send("DELETE", `/organizations/${orgId}/event-integrations/${id}`);
  }

  rotateSecret(orgId: string, id: string): Promise<EventIntegration> {
    return this.send("POST", `/organizations/${orgId}/event-integrations/${id}/rotate-secret`);
  }

  test(orgId: string, id: string): Promise<{ success: boolean; error: string | null }> {
    return this.send("POST", `/organizations/${orgId}/event-integrations/${id}/test`);
  }
}

/** Settings fields per type: `secret` fields are write-only and blank means "keep". */
export interface FieldSpec {
  key: string;
  labelKey: string;
  secret?: boolean;
  required?: boolean;
  placeholder?: string;
  options?: string[];
}

export const DATADOG_SITES = [
  "datadoghq.com",
  "us3.datadoghq.com",
  "us5.datadoghq.com",
  "datadoghq.eu",
  "ap1.datadoghq.com",
  "ap2.datadoghq.com",
  "ddog-gov.com",
];

export const FIELDS: Record<IntegrationType, FieldSpec[]> = {
  webhook: [
    { key: "url", labelKey: "cwIntUrl", required: true, placeholder: "https://hooks.example.com/cloudwarden" },
    { key: "headerName", labelKey: "cwIntHeaderName", placeholder: "Authorization" },
    { key: "headerValue", labelKey: "cwIntHeaderValue", secret: true },
  ],
  splunk: [
    { key: "url", labelKey: "cwIntSplunkUrl", required: true, placeholder: "https://splunk.example.com:8088" },
    { key: "token", labelKey: "cwIntSplunkToken", secret: true, required: true },
    { key: "index", labelKey: "cwIntSplunkIndex" },
    { key: "source", labelKey: "cwIntSplunkSource", placeholder: "cloudwarden" },
    { key: "sourcetype", labelKey: "cwIntSplunkSourcetype", placeholder: "_json" },
  ],
  datadog: [
    { key: "site", labelKey: "cwIntDatadogSite", required: true, options: DATADOG_SITES },
    { key: "apiKey", labelKey: "cwIntDatadogApiKey", secret: true, required: true },
    { key: "service", labelKey: "cwIntDatadogService", placeholder: "cloudwarden" },
    { key: "tags", labelKey: "cwIntDatadogTags", placeholder: "env:prod,team:security" },
  ],
  sentinel: [
    { key: "tenantId", labelKey: "cwIntSentinelTenant", required: true },
    { key: "clientId", labelKey: "cwIntSentinelClient", required: true },
    { key: "clientSecret", labelKey: "cwIntSentinelSecret", secret: true, required: true },
    {
      key: "endpoint",
      labelKey: "cwIntSentinelEndpoint",
      required: true,
      placeholder: "https://example-abcd.westeurope-1.ingest.monitor.azure.com",
    },
    { key: "ruleId", labelKey: "cwIntSentinelRule", required: true, placeholder: "dcr-..." },
    {
      key: "streamName",
      labelKey: "cwIntSentinelStream",
      required: true,
      placeholder: "Custom-CloudwardenEvents_CL",
    },
  ],
};

/** Splits form values into public settings and secrets, dropping empty optional settings. */
export function splitValues(type: IntegrationType, values: Record<string, string | null>) {
  const config: Record<string, string | null> = {};
  const secrets: Record<string, string | null> = {};
  for (const f of FIELDS[type]) {
    const v = (values[f.key] ?? "").trim();
    if (f.secret) {
      if (v) {
        secrets[f.key] = v;
      }
    } else {
      config[f.key] = v === "" ? null : v;
    }
  }
  return { config, secrets };
}

/** Parses "1000, 1100-1102" into event type numbers; empty means every type. */
export function parseEventTypes(text: string): number[] | null {
  const out = new Set<number>();
  for (const part of text.split(/[\s,]+/).filter(Boolean)) {
    const range = /^(\d{4})-(\d{4})$/.exec(part);
    if (range) {
      for (let n = Number(range[1]); n <= Number(range[2]) && out.size < 200; n++) {
        out.add(n);
      }
    } else if (/^\d{4}$/.test(part)) {
      out.add(Number(part));
    } else {
      throw new Error(part);
    }
  }
  return out.size ? [...out].sort((a, b) => a - b) : null;
}

/** The `:organizationId` of the nearest ancestor route. */
export function organizationIdFrom(route: ActivatedRoute): string {
  return (
    route.snapshot.pathFromRoot
      .map((r) => r.paramMap.get("organizationId"))
      .reverse()
      .find((id): id is string => !!id) ?? ""
  );
}
