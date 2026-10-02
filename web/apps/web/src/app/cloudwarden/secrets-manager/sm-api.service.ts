// Cloudwarden: client for the Secrets Manager API (docs/secrets-manager.md, web/NOTICE.md).
// Every name, key, value and note is an EncString under the organisation key: this service
// encrypts on the way out and decrypts on the way in, using the vault's own key and encrypt
// services and its authenticated ApiService.
import { Injectable, inject } from "@angular/core";
import { firstValueFrom } from "rxjs";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { OrganizationService } from "@bitwarden/common/admin-console/abstractions/organization/organization.service.abstraction";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { getUserId } from "@bitwarden/common/auth/services/account.service";
import { OrganizationId } from "@bitwarden/common/types/guid";
import { KeyService } from "@bitwarden/key-management";
// eslint-disable-next-line no-restricted-imports
import { EncString, EncryptService, SymmetricCryptoKey } from "@bitwarden/legacy-crypto";

import {
  AccessTokenRequest,
  buildAccessTokenRequest,
  formatAccessToken,
  newAccessTokenSeed,
} from "./sm-crypto";

export interface SmProject {
  id: string;
  name: string;
  creationDate: string;
  revisionDate: string;
  read: boolean;
  write: boolean;
}

export interface SmSecretListItem {
  id: string;
  key: string;
  projectId: string | null;
  projectName: string | null;
  revisionDate: string;
  read: boolean;
  write: boolean;
}

export interface SmSecret extends SmSecretListItem {
  value: string;
  note: string;
}

export interface SmMachineAccount {
  id: string;
  name: string;
  creationDate: string;
  revisionDate: string;
  accessToSecrets?: number;
}

export interface SmAccessToken {
  id: string;
  name: string;
  expireAt: string | null;
  creationDate: string;
}

export interface SmPeoplePolicy {
  kind: "user" | "group";
  id: string;
  name: string;
  read: boolean;
  write: boolean;
}

export interface SmGrantee {
  kind: "user" | "group" | "serviceAccount" | "project";
  id: string;
  name: string;
  email?: string | null;
}

export interface SmProjectGrant {
  projectId: string;
  projectName: string;
  read: boolean;
  write: boolean;
  /** False when the caller cannot change this grant (no write on the project). */
  editable: boolean;
}

export interface SmBulkResult {
  id: string;
  error: string | null;
}

type Ref = { id: string; name: string };
type Raw = Record<string, any>;

/** Shown when a value cannot be decrypted (wrong key or damaged data). */
export const SM_DECRYPT_ERROR = "[error: cannot decrypt]";

@Injectable({ providedIn: "root" })
export class SmApiService {
  private readonly api = inject(ApiService);
  private readonly accountService = inject(AccountService);
  private readonly keyService = inject(KeyService);
  private readonly encryptService = inject(EncryptService);
  private readonly organizationService = inject(OrganizationService);

  private send<T = any>(method: string, path: string, body: unknown = null): Promise<T> {
    return this.api.send(method as "GET", path, body, true, method !== "DELETE");
  }

  /** Owners and admins may keep secrets outside every project and manage all objects. */
  async isOrgAdmin(orgId: string): Promise<boolean> {
    const userId = await firstValueFrom(this.accountService.activeAccount$.pipe(getUserId));
    const orgs = await firstValueFrom(this.organizationService.organizations$(userId));
    return orgs.find((o) => o.id === orgId)?.isAdmin ?? false;
  }

  // ----- crypto -----

  async orgKey(orgId: string): Promise<SymmetricCryptoKey> {
    const userId = await firstValueFrom(this.accountService.activeAccount$.pipe(getUserId));
    const keys = await firstValueFrom(this.keyService.orgKeys$(userId));
    const key = keys?.[orgId as OrganizationId];
    if (!key) {
      throw new Error("The organisation key is not available. Sync your vault and try again.");
    }
    return key;
  }

  async encrypt(orgId: string, plain: string): Promise<string> {
    const enc = await this.encryptService.encryptString(plain, await this.orgKey(orgId));
    return enc.encryptedString as string;
  }

  async decrypt(orgId: string, value: string | null | undefined): Promise<string> {
    if (!value) {
      return "";
    }
    try {
      return await this.encryptService.decryptString(
        new EncString(value),
        await this.orgKey(orgId),
      );
    } catch {
      return SM_DECRYPT_ERROR;
    }
  }

  /** Encrypts with a raw key, for the access token payload. */
  private encryptRaw = async (plain: string, key: Uint8Array) =>
    (await this.encryptService.encryptString(plain, new SymmetricCryptoKey(key)))
      .encryptedString as string;

  // ----- projects -----

  private async project(orgId: string, p: Raw): Promise<SmProject> {
    return {
      id: p.id,
      name: await this.decrypt(orgId, p.name),
      creationDate: p.creationDate,
      revisionDate: p.revisionDate,
      read: p.read !== false,
      write: p.write !== false,
    };
  }

  async listProjects(orgId: string): Promise<SmProject[]> {
    const r = await this.send("GET", `/organizations/${orgId}/projects`);
    const out = await Promise.all((r.data as Raw[]).map((p) => this.project(orgId, p)));
    return out.sort((a, b) => a.name.localeCompare(b.name));
  }

  async getProject(orgId: string, id: string): Promise<SmProject> {
    return this.project(orgId, await this.send("GET", `/projects/${id}`));
  }

  async createProject(orgId: string, name: string): Promise<SmProject> {
    const r = await this.send("POST", `/organizations/${orgId}/projects`, {
      name: await this.encrypt(orgId, name),
    });
    return this.project(orgId, r);
  }

  async renameProject(orgId: string, id: string, name: string): Promise<SmProject> {
    const r = await this.send("PUT", `/projects/${id}`, {
      name: await this.encrypt(orgId, name),
    });
    return this.project(orgId, r);
  }

  async deleteProjects(ids: string[]): Promise<SmBulkResult[]> {
    return (await this.send("POST", "/projects/delete", ids)).data;
  }

  // ----- secrets -----

  private async names(orgId: string, refs: Ref[] | undefined) {
    const out = new Map<string, string>();
    for (const r of refs ?? []) {
      out.set(r.id, await this.decrypt(orgId, r.name));
    }
    return out;
  }

  async listSecrets(orgId: string, projectId?: string): Promise<SmSecretListItem[]> {
    const r = await this.send(
      "GET",
      projectId ? `/projects/${projectId}/secrets` : `/organizations/${orgId}/secrets`,
    );
    const projectNames = await this.names(orgId, r.projects);
    const out = await Promise.all(
      (r.secrets as Raw[]).map(async (s) => {
        const projectId = s.projects?.[0]?.id ?? null;
        return {
          id: s.id,
          key: await this.decrypt(orgId, s.key),
          projectId,
          projectName: projectId
            ? (projectNames.get(projectId) ?? (await this.decrypt(orgId, s.projects[0].name)))
            : null,
          revisionDate: s.revisionDate,
          read: s.read !== false,
          write: s.write !== false,
        } satisfies SmSecretListItem;
      }),
    );
    return out.sort((a, b) => a.key.localeCompare(b.key));
  }

  async getSecret(orgId: string, id: string): Promise<SmSecret> {
    const s = await this.send("GET", `/secrets/${id}`);
    const project = s.projects?.[0] ?? null;
    return {
      id: s.id,
      key: await this.decrypt(orgId, s.key),
      value: await this.decrypt(orgId, s.value),
      note: await this.decrypt(orgId, s.note),
      projectId: project?.id ?? null,
      projectName: project ? await this.decrypt(orgId, project.name) : null,
      revisionDate: s.revisionDate,
      read: s.read !== false,
      write: s.write !== false,
    };
  }

  private async secretBody(
    orgId: string,
    s: { key: string; value: string; note: string; projectId: string | null },
  ) {
    return {
      key: await this.encrypt(orgId, s.key),
      value: await this.encrypt(orgId, s.value),
      note: s.note ? await this.encrypt(orgId, s.note) : "",
      projectIds: s.projectId ? [s.projectId] : [],
    };
  }

  async createSecret(
    orgId: string,
    s: { key: string; value: string; note: string; projectId: string | null },
  ): Promise<{ id: string }> {
    return this.send("POST", `/organizations/${orgId}/secrets`, await this.secretBody(orgId, s));
  }

  async updateSecret(
    orgId: string,
    id: string,
    s: { key: string; value: string; note: string; projectId: string | null },
  ): Promise<{ id: string }> {
    return this.send("PUT", `/secrets/${id}`, {
      ...(await this.secretBody(orgId, s)),
      valueChanged: true,
    });
  }

  async deleteSecrets(ids: string[]): Promise<SmBulkResult[]> {
    return (await this.send("POST", "/secrets/delete", ids)).data;
  }

  // ----- machine accounts -----

  private async machineAccount(orgId: string, sa: Raw): Promise<SmMachineAccount> {
    return {
      id: sa.id,
      name: await this.decrypt(orgId, sa.name),
      creationDate: sa.creationDate,
      revisionDate: sa.revisionDate,
      accessToSecrets: sa.accessToSecrets,
    };
  }

  async listMachineAccounts(orgId: string): Promise<SmMachineAccount[]> {
    const r = await this.send(
      "GET",
      `/organizations/${orgId}/service-accounts?includeAccessToSecrets=true`,
    );
    const out = await Promise.all((r.data as Raw[]).map((sa) => this.machineAccount(orgId, sa)));
    return out.sort((a, b) => a.name.localeCompare(b.name));
  }

  async getMachineAccount(orgId: string, id: string): Promise<SmMachineAccount> {
    return this.machineAccount(orgId, await this.send("GET", `/service-accounts/${id}`));
  }

  async createMachineAccount(orgId: string, name: string): Promise<SmMachineAccount> {
    const r = await this.send("POST", `/organizations/${orgId}/service-accounts`, {
      name: await this.encrypt(orgId, name),
    });
    return this.machineAccount(orgId, r);
  }

  async renameMachineAccount(orgId: string, id: string, name: string) {
    const r = await this.send("PUT", `/service-accounts/${id}`, {
      name: await this.encrypt(orgId, name),
    });
    return this.machineAccount(orgId, r);
  }

  async deleteMachineAccounts(ids: string[]): Promise<SmBulkResult[]> {
    return (await this.send("POST", "/service-accounts/delete", ids)).data;
  }

  // ----- access tokens -----

  async listAccessTokens(orgId: string, saId: string): Promise<SmAccessToken[]> {
    const r = await this.send("GET", `/service-accounts/${saId}/access-tokens`);
    return Promise.all(
      (r.data as Raw[]).map(async (t) => ({
        id: t.id,
        name: await this.decrypt(orgId, t.name),
        expireAt: t.expireAt ?? null,
        creationDate: t.creationDate,
      })),
    );
  }

  /** Creates a token and returns the one-time token string `0.<id>.<secret>:<seed>`. */
  async createAccessToken(
    orgId: string,
    saId: string,
    name: string,
    expireAt: Date | null,
  ): Promise<{ token: string; id: string; request: AccessTokenRequest }> {
    const seed = newAccessTokenSeed();
    const orgKey = (await this.orgKey(orgId)).toEncoded();
    const request = await buildAccessTokenRequest({
      name,
      orgKey,
      seed,
      expireAt,
      encrypt: this.encryptRaw,
    });
    const r = await this.send("POST", `/service-accounts/${saId}/access-tokens`, request);
    return {
      token: formatAccessToken(r.id, r.clientSecret, seed),
      id: r.id,
      request,
    };
  }

  async revokeAccessTokens(saId: string, ids: string[]): Promise<void> {
    await this.api.send(
      "POST",
      `/service-accounts/${saId}/access-tokens/revoke`,
      { ids },
      true,
      false,
    );
  }

  // ----- access policies -----

  private peoplePolicies(r: Raw): SmPeoplePolicy[] {
    return [
      ...(r.userAccessPolicies ?? []).map((p: Raw) => ({
        kind: "user" as const,
        id: p.organizationUserId,
        name: p.organizationUserName ?? p.organizationUserId,
        read: p.read,
        write: p.write,
      })),
      ...(r.groupAccessPolicies ?? []).map((p: Raw) => ({
        kind: "group" as const,
        id: p.groupId,
        name: p.groupName ?? p.groupId,
        read: p.read,
        write: p.write,
      })),
    ];
  }

  private peopleBody(policies: SmPeoplePolicy[]) {
    const req = (kind: "user" | "group") =>
      policies
        .filter((p) => p.kind === kind)
        .map((p) => ({
          granteeId: p.id,
          read: p.read || p.write,
          write: p.write,
        }));
    return {
      userAccessPolicyRequests: req("user"),
      groupAccessPolicyRequests: req("group"),
    };
  }

  async getPeoplePolicies(target: "projects" | "service-accounts", id: string) {
    return this.peoplePolicies(await this.send("GET", `/${target}/${id}/access-policies/people`));
  }

  async putPeoplePolicies(
    target: "projects" | "service-accounts",
    id: string,
    policies: SmPeoplePolicy[],
  ) {
    return this.peoplePolicies(
      await this.send("PUT", `/${target}/${id}/access-policies/people`, this.peopleBody(policies)),
    );
  }

  async peopleGrantees(orgId: string): Promise<SmGrantee[]> {
    const r = await this.send(
      "GET",
      `/organizations/${orgId}/access-policies/people/potential-grantees`,
    );
    return (r.data as Raw[]).map((g) => ({
      kind: g.type,
      id: g.id,
      name: g.name ?? g.email ?? g.id,
      email: g.email,
    }));
  }

  async getProjectGrants(orgId: string, saId: string): Promise<SmProjectGrant[]> {
    const r = await this.send("GET", `/service-accounts/${saId}/granted-policies`);
    return Promise.all(
      (r.grantedProjectPolicies as Raw[]).map(async (g) => ({
        projectId: g.accessPolicy.grantedProjectId,
        projectName: await this.decrypt(orgId, g.accessPolicy.grantedProjectName),
        read: g.accessPolicy.read,
        write: g.accessPolicy.write,
        editable: g.hasPermission,
      })),
    );
  }

  /** Replaces the grants on projects the caller can write; others are kept by the server. */
  async putProjectGrants(orgId: string, saId: string, grants: SmProjectGrant[]) {
    await this.send("PUT", `/service-accounts/${saId}/granted-policies`, {
      projectGrantedPolicyRequests: grants
        .filter((g) => g.editable)
        .map((g) => ({
          grantedId: g.projectId,
          read: g.read || g.write,
          write: g.write,
        })),
    });
    return this.getProjectGrants(orgId, saId);
  }

  async getProjectMachineAccounts(orgId: string, projectId: string) {
    const r = await this.send("GET", `/projects/${projectId}/access-policies/service-accounts`);
    return Promise.all(
      (r.serviceAccountAccessPolicies as Raw[]).map(async (p) => ({
        id: p.serviceAccountId as string,
        name: await this.decrypt(orgId, p.serviceAccountName),
        read: p.read as boolean,
        write: p.write as boolean,
      })),
    );
  }
}
