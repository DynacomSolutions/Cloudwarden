// Cloudwarden: pure helpers of the collection Access dialog's "External workspace" section
// (docs/federation.md, "Sharing a collection"; web/NOTICE.md).
import { CollectionPermission } from "../../admin-console/organizations/shared/components/access-selector/access-selector.models";

import type {
  ExternalAccessFlags,
  QueuedShare,
  WorkspaceState,
} from "./federation-api.service";

/** The permission choices, in the order the local selector offers them. */
export const EXTERNAL_PERMISSIONS: {
  perm: CollectionPermission;
  labelId: string;
}[] = [
  { perm: CollectionPermission.ViewExceptPass, labelId: "viewItemsHidePass" },
  { perm: CollectionPermission.View, labelId: "viewItems" },
  { perm: CollectionPermission.EditExceptPass, labelId: "editItemsHidePass" },
  { perm: CollectionPermission.Edit, labelId: "editItems" },
  { perm: CollectionPermission.Manage, labelId: "manageCollection" },
];

/** Same mapping as the local access selector (`convertToSelectionView`). */
export function permissionToAccess(
  perm: CollectionPermission,
): ExternalAccessFlags {
  return {
    readOnly:
      perm === CollectionPermission.View ||
      perm === CollectionPermission.ViewExceptPass,
    hidePasswords:
      perm === CollectionPermission.ViewExceptPass ||
      perm === CollectionPermission.EditExceptPass,
    manage: perm === CollectionPermission.Manage,
  };
}

export function accessToPermission(
  a: ExternalAccessFlags,
): CollectionPermission {
  if (a.manage) {
    return CollectionPermission.Manage;
  }
  if (a.readOnly) {
    return a.hidePasswords
      ? CollectionPermission.ViewExceptPass
      : CollectionPermission.View;
  }
  return a.hidePasswords
    ? CollectionPermission.EditExceptPass
    : CollectionPermission.Edit;
}

/** Splits addresses typed or pasted separated by commas, semicolons, spaces or new lines. */
export function parseEmails(text: string): string[] {
  const seen = new Set<string>();
  for (const part of text.split(/[\s,;]+/)) {
    const email = part.trim().toLowerCase();
    if (email.length > 0) {
      seen.add(email);
    }
  }
  return [...seen];
}

export const isEmailLike = (value: string) => /^[^\s@]+@[^\s@]+$/.test(value);

/** i18n key for a grantee's state: the membership status, or the workspace when it is not usable. */
export function granteeStatusKey(
  status: number,
  peerState: WorkspaceState,
): string {
  if (peerState === "suspended") {
    return "cwFedSuspended";
  }
  if (status === 2) {
    return "cwExtActive";
  }
  return status === 1 ? "cwExtAccepted" : "cwExtInvited";
}

/** A workspace that still awaits approval takes shares into a queue; a suspended one does not. */
export const canQueueFor = (state: WorkspaceState): boolean =>
  state === "awaitingInstanceAdmin" || state === "awaitingRemote";

/** i18n key of the status of a queued share. */
export const queuedStatusKey = (status: QueuedShare["status"]): string =>
  ({
    queued: "cwExtQueued",
    declined: "cwExtQueuedDeclined",
    expired: "cwExtQueuedExpired",
    dropped: "cwExtQueuedDropped",
  })[status];

/** i18n key explaining a workspace that cannot be used yet, or null when it can. */
export function workspaceWaitKey(
  state: WorkspaceState,
  isInstanceAdmin: boolean,
): string | null {
  switch (state) {
    case "active":
      return null;
    case "suspended":
      return "cwExtWsSuspended";
    case "awaitingInstanceAdmin":
      return isInstanceAdmin ? "cwExtWsAwaitingYou" : "cwExtWsAwaitingAdmin";
    case "awaitingRemote":
      return "cwExtWsAwaitingRemote";
  }
}
