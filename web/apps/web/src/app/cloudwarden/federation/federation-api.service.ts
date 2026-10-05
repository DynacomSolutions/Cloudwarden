// Cloudwarden: client for the federated organisations API (/api/cloudwarden/federation/*,
// docs/federation.md, web/NOTICE.md). Uses the vault's authenticated ApiService.
import { Injectable, inject } from "@angular/core";
import { ActivatedRoute } from "@angular/router";
import {
  Observable,
  catchError,
  from,
  map,
  of,
  shareReplay,
  switchMap,
} from "rxjs";

import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";

export interface FederationStatus {
  enabled: boolean;
  domain: string;
  isInstanceAdmin: boolean;
  peers: { id: string; domain: string }[];
}

export interface FederationPeer {
  id: string;
  instanceId: string;
  domain: string;
  fingerprint: string;
  protocolVersion: number;
  status: "pending" | "active" | "suspended";
  localApproved: boolean;
  remoteApproved: boolean;
  active: boolean;
  lastSeenDate: string | null;
  lastError: string | null;
  creationDate: string;
  /** Account that asked for this workspace from a collection dialog (awaiting an instance admin). */
  requestedByEmail?: string | null;
  /** Organisations sharing with this workspace (counts only, collection names are encrypted). */
  sharing?: {
    organizationId: string;
    organizationName: string;
    people: number;
    collections: number;
  }[];
}

export type WorkspaceState =
  "active" | "suspended" | "awaitingInstanceAdmin" | "awaitingRemote";

export interface ExternalWorkspace {
  id: string;
  domain: string;
  fingerprint: string;
  state: WorkspaceState;
  active: boolean;
}

export interface ExternalGrantee {
  id: string;
  userId: string | null;
  email: string;
  /** Membership status: 0 invited, 1 accepted (awaiting confirm), 2 confirmed. */
  status: number;
  peerId: string;
  peerDomain: string;
  peerState: WorkspaceState;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface ExternalAccessState {
  isInstanceAdmin: boolean;
  available: boolean;
  workspaces: ExternalWorkspace[];
  grantees: ExternalGrantee[];
}

export interface ExternalAccessFlags {
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface ShareResult {
  email: string;
  ok: boolean;
  result?: "invited" | "updated";
  id?: string;
  error?: string;
}

export interface FederationDescriptor {
  instanceId: string;
  domain: string;
  publicKey: string;
  fingerprint: string;
  version: number;
}

export interface FederationEvent {
  type: number;
  name: string;
  organizationId: string | null;
  userId: string | null;
  peer: string | null;
  date: string;
}

export interface FederatedMember {
  id: string;
  userId: string | null;
  email: string;
  type: number;
  status: number;
  peerId: string;
  peerDomain: string;
  peerStatus: string;
  collectionIds?: string[];
}

export interface FederatedInvitation {
  id: string;
  organizationId: string;
  organizationName: string;
  inviterEmail: string | null;
  peerDomain: string;
  peerActive: boolean;
  status: "pending" | "accepted" | "declined";
  creationDate: string;
}

export interface FederatedMembership {
  organizationId: string;
  name: string | null;
  status: number | null;
  peerDomain: string;
  peerStatus: string;
  syncedDate: string;
}

export interface FederatedInvite {
  email: string;
  peerId: string;
  type: number;
  accessAll: boolean;
  collections: {
    id: string;
    readOnly: boolean;
    hidePasswords: boolean;
    manage: boolean;
  }[];
}

const BASE = "/cloudwarden/federation";
const enc = encodeURIComponent;

/** Groups a fingerprint for reading aloud: upper-case hex in blocks of four. */
export function formatFingerprint(value: string): string {
  const hex = value.replace(/[^0-9a-f]/gi, "").toUpperCase();
  return (hex.match(/.{1,4}/g) ?? []).join(":");
}

/** True when two fingerprints are the same key, whatever separators or case were typed. */
export function sameFingerprint(a: string, b: string): boolean {
  const norm = (s: string) => s.replace(/[^0-9a-f]/gi, "").toUpperCase();
  return norm(a).length > 0 && norm(a) === norm(b);
}

export function organizationIdFrom(route: ActivatedRoute): string {
  return (
    route.snapshot.pathFromRoot
      .map((r) => r.paramMap.get("organizationId"))
      .reverse()
      .find((id): id is string => !!id) ?? ""
  );
}

@Injectable({ providedIn: "root" })
export class FederationApiService {
  private readonly apiService = inject(ApiService);
  private readonly accountService = inject(AccountService);

  /** Federation status, or null when the server has federation off (404) or on error. */
  readonly status$: Observable<FederationStatus | null> =
    this.accountService.activeAccount$.pipe(
      switchMap((account) =>
        account == null
          ? of(null)
          : from(this.status()).pipe(
              catchError(() => of(null as FederationStatus | null)),
            ),
      ),
      shareReplay({ bufferSize: 1, refCount: true }),
    );

  readonly enabled$: Observable<boolean> = this.status$.pipe(
    map((s) => s?.enabled === true),
  );

  status(): Promise<FederationStatus> {
    return this.apiService.send("GET", `${BASE}/status`, null, true, true);
  }

  // ----- instance admin -----

  identity(): Promise<FederationDescriptor> {
    return this.apiService.send(
      "GET",
      `${BASE}/admin/identity`,
      null,
      true,
      true,
    );
  }

  peers(): Promise<{ data: FederationPeer[] }> {
    return this.apiService.send("GET", `${BASE}/admin/peers`, null, true, true);
  }

  addPeer(domain: string): Promise<FederationPeer> {
    return this.apiService.send(
      "POST",
      `${BASE}/admin/peers`,
      { domain },
      true,
      true,
    );
  }

  approvePeer(id: string, fingerprint: string): Promise<FederationPeer> {
    return this.apiService.send(
      "POST",
      `${BASE}/admin/peers/${enc(id)}/approve`,
      { fingerprint },
      true,
      true,
    );
  }

  peerAction(
    id: string,
    action: "suspend" | "resume",
  ): Promise<FederationPeer> {
    return this.apiService.send(
      "POST",
      `${BASE}/admin/peers/${enc(id)}/${action}`,
      null,
      true,
      true,
    );
  }

  checkPeer(
    id: string,
  ): Promise<{ ok: boolean; latencyMs?: number; error?: string }> {
    return this.apiService.send(
      "POST",
      `${BASE}/admin/peers/${enc(id)}/check`,
      null,
      true,
      true,
    );
  }

  removePeer(id: string): Promise<void> {
    return this.apiService.send(
      "DELETE",
      `${BASE}/admin/peers/${enc(id)}`,
      null,
      true,
      false,
    );
  }

  events(): Promise<{ data: FederationEvent[] }> {
    return this.apiService.send(
      "GET",
      `${BASE}/admin/events`,
      null,
      true,
      true,
    );
  }

  // ----- organisation admin -----

  members(orgId: string): Promise<{ data: FederatedMember[] }> {
    return this.apiService.send(
      "GET",
      `${BASE}/organizations/${enc(orgId)}/members`,
      null,
      true,
      true,
    );
  }

  invite(orgId: string, body: FederatedInvite): Promise<{ id: string }> {
    return this.apiService.send(
      "POST",
      `${BASE}/organizations/${enc(orgId)}/members`,
      body,
      true,
      true,
    );
  }

  removeMember(orgId: string, id: string): Promise<void> {
    return this.apiService.send(
      "DELETE",
      `${BASE}/organizations/${enc(orgId)}/members/${enc(id)}`,
      null,
      true,
      false,
    );
  }

  // ----- collection Access dialog -----

  externalAccess(
    orgId: string,
    collectionId: string,
  ): Promise<ExternalAccessState> {
    return this.apiService.send(
      "GET",
      this.ext(orgId, collectionId),
      null,
      true,
      true,
    );
  }

  lookupWorkspace(
    orgId: string,
    collectionId: string,
    domain: string,
  ): Promise<{
    domain: string;
    fingerprint: string;
    workspace: ExternalWorkspace | null;
  }> {
    return this.apiService.send(
      "POST",
      `${this.ext(orgId, collectionId)}/workspaces/lookup`,
      { domain },
      true,
      true,
    );
  }

  addWorkspace(
    orgId: string,
    collectionId: string,
    domain: string,
    fingerprint: string,
  ): Promise<{ created: boolean; workspace: ExternalWorkspace }> {
    return this.apiService.send(
      "POST",
      `${this.ext(orgId, collectionId)}/workspaces`,
      { domain, fingerprint },
      true,
      true,
    );
  }

  share(
    orgId: string,
    collectionId: string,
    workspaceId: string,
    emails: string[],
    access: ExternalAccessFlags,
  ): Promise<{ data: ShareResult[] }> {
    return this.apiService.send(
      "POST",
      this.ext(orgId, collectionId),
      { workspaceId, emails, ...access },
      true,
      true,
    );
  }

  updateExternalAccess(
    orgId: string,
    collectionId: string,
    memberId: string,
    access: ExternalAccessFlags,
  ): Promise<void> {
    return this.apiService.send(
      "PUT",
      `${this.ext(orgId, collectionId)}/${enc(memberId)}`,
      access,
      true,
      false,
    );
  }

  removeExternalAccess(
    orgId: string,
    collectionId: string,
    memberId: string,
  ): Promise<{ removedMember: boolean }> {
    return this.apiService.send(
      "DELETE",
      `${this.ext(orgId, collectionId)}/${enc(memberId)}`,
      null,
      true,
      true,
    );
  }

  private ext(orgId: string, collectionId: string): string {
    return `${BASE}/organizations/${enc(orgId)}/collections/${enc(collectionId)}/external-access`;
  }

  // ----- invited user -----

  invitations(): Promise<{ data: FederatedInvitation[] }> {
    return this.apiService.send("GET", `${BASE}/invitations`, null, true, true);
  }

  respond(id: string, accept: boolean): Promise<void> {
    return this.apiService.send(
      "POST",
      `${BASE}/invitations/${enc(id)}/${accept ? "accept" : "decline"}`,
      null,
      true,
      false,
    );
  }

  memberships(): Promise<{ data: FederatedMembership[] }> {
    return this.apiService.send("GET", `${BASE}/memberships`, null, true, true);
  }
}
