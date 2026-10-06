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
  /** For instance admins: workspaces waiting for a decision (the admin nav badge). */
  pendingRequests?: number;
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
  /** True when this instance trusted the workspace without an admin step (an incoming request). */
  acceptedAutomatically?: boolean;
  /** Instance admin who approved the workspace here, when an admin did. */
  approvedByEmail?: string | null;
  /** Account that asked for this workspace from a collection dialog (awaiting an instance admin). */
  requestedByEmail?: string | null;
  /** What is queued behind this workspace request: organisation, collections, people, who asked. */
  queued?: {
    organizationId: string;
    organizationName: string;
    requestedByEmail: string;
    collections: number;
    people: number;
  }[];
  /** Organisations sharing with this workspace (counts only, collection names are encrypted). */
  sharing?: {
    organizationId: string;
    organizationName: string;
    people: number;
    collections: number;
  }[];
}

export interface TrustSettings {
  requireIncomingApproval: boolean;
  blockedDomains: { domain: string; date: string }[];
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

/** A share queued behind a workspace that awaits an instance admin (or that ended without it). */
export interface QueuedShare {
  id: string;
  email: string;
  peerId: string;
  peerDomain: string;
  status: "queued" | "declined" | "expired" | "dropped";
  /** Why a dropped share was not sent. */
  note: string | null;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface ExternalAccessState {
  isInstanceAdmin: boolean;
  /** May invite new external people (manage users, or the organisation allows collection managers). */
  canInvite: boolean;
  canChangeInviteSetting: boolean;
  collectionManagersMayInvite: boolean;
  available: boolean;
  workspaces: ExternalWorkspace[];
  grantees: ExternalGrantee[];
  queued: QueuedShare[];
}

export interface ExternalAccessFlags {
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface InviteSetting {
  collectionManagersMayInvite: boolean;
  canChange: boolean;
}

export interface ShareResult {
  email: string;
  ok: boolean;
  result?: "invited" | "updated" | "queued";
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

  /** The public descriptor of this instance (same origin), readable by any signed-in user. */
  async ownDescriptor(): Promise<FederationDescriptor> {
    const res = await fetch("/.well-known/cloudwarden-federation", {
      headers: { accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error(`descriptor ${res.status}`);
    }
    return (await res.json()) as FederationDescriptor;
  }

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

  /** `block` also refuses the workspace's pairing requests until an admin unblocks the domain. */
  trustSettings(): Promise<TrustSettings> {
    return this.apiService.send(
      "GET",
      `${BASE}/admin/settings`,
      null,
      true,
      true,
    );
  }

  setRequireIncomingApproval(value: boolean): Promise<unknown> {
    return this.apiService.send(
      "PUT",
      `${BASE}/admin/settings`,
      { requireIncomingApproval: value },
      true,
      true,
    );
  }

  blockDomain(domain: string): Promise<unknown> {
    return this.apiService.send(
      "POST",
      `${BASE}/admin/blocked`,
      { domain },
      true,
      true,
    );
  }

  unblockDomain(domain: string): Promise<unknown> {
    return this.apiService.send(
      "DELETE",
      `${BASE}/admin/blocked/${enc(domain)}`,
      null,
      true,
      true,
    );
  }

  removePeer(id: string, block = false): Promise<void> {
    return this.apiService.send(
      "DELETE",
      `${BASE}/admin/peers/${enc(id)}${block ? "?block=true" : ""}`,
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
    fingerprint: string | null;
    workspace: ExternalWorkspace | null;
    /** A domain this server knows but only an instance admin may see: no detail is returned. */
    awaitingAdmin?: boolean;
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
  ): Promise<{
    created: boolean;
    workspace: ExternalWorkspace | null;
    awaitingAdmin?: boolean;
  }> {
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

  updateQueuedShare(
    orgId: string,
    collectionId: string,
    id: string,
    access: ExternalAccessFlags,
  ): Promise<void> {
    return this.apiService.send(
      "PUT",
      `${this.ext(orgId, collectionId)}/queued/${enc(id)}`,
      access,
      true,
      false,
    );
  }

  removeQueuedShare(
    orgId: string,
    collectionId: string,
    id: string,
  ): Promise<void> {
    return this.apiService.send(
      "DELETE",
      `${this.ext(orgId, collectionId)}/queued/${enc(id)}`,
      null,
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

  inviteSetting(
    orgId: string,
  ): Promise<{ collectionManagersMayInvite: boolean; canChange: boolean }> {
    return this.apiService.send(
      "GET",
      `${BASE}/organizations/${enc(orgId)}/settings`,
      null,
      true,
      true,
    );
  }

  setInviteSetting(
    orgId: string,
    collectionManagersMayInvite: boolean,
  ): Promise<unknown> {
    return this.apiService.send(
      "PUT",
      `${BASE}/organizations/${enc(orgId)}/settings`,
      { collectionManagersMayInvite },
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
