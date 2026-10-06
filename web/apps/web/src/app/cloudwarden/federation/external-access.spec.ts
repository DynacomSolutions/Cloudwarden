// Cloudwarden: helpers of the collection Access dialog's external workspace section.
import { CollectionPermission } from "../../admin-console/organizations/shared/components/access-selector/access-selector.models";

import {
  EXTERNAL_PERMISSIONS,
  accessToPermission,
  granteeStatusKey,
  canQueueFor,
  parseEmails,
  queuedStatusKey,
  permissionToAccess,
  workspaceWaitKey,
} from "./external-access";

describe("external access helpers", () => {
  it("offers the same five permissions as the local selector", () => {
    expect(EXTERNAL_PERMISSIONS.map((p) => p.perm)).toEqual([
      CollectionPermission.ViewExceptPass,
      CollectionPermission.View,
      CollectionPermission.EditExceptPass,
      CollectionPermission.Edit,
      CollectionPermission.Manage,
    ]);
  });

  it("maps every permission to the server flags and back", () => {
    expect(permissionToAccess(CollectionPermission.View)).toEqual({
      readOnly: true,
      hidePasswords: false,
      manage: false,
    });
    expect(permissionToAccess(CollectionPermission.ViewExceptPass)).toEqual({
      readOnly: true,
      hidePasswords: true,
      manage: false,
    });
    expect(permissionToAccess(CollectionPermission.Edit)).toEqual({
      readOnly: false,
      hidePasswords: false,
      manage: false,
    });
    expect(permissionToAccess(CollectionPermission.EditExceptPass)).toEqual({
      readOnly: false,
      hidePasswords: true,
      manage: false,
    });
    expect(permissionToAccess(CollectionPermission.Manage)).toEqual({
      readOnly: false,
      hidePasswords: false,
      manage: true,
    });
    for (const p of EXTERNAL_PERMISSIONS) {
      expect(accessToPermission(permissionToAccess(p.perm))).toBe(p.perm);
    }
  });

  it("splits, lower-cases and de-duplicates addresses", () => {
    expect(
      parseEmails(
        "A@example.org, b@example.org;\nA@example.org  c@example.org ",
      ),
    ).toEqual(["a@example.org", "b@example.org", "c@example.org"]);
    expect(parseEmails("  ")).toEqual([]);
  });

  it("explains a workspace that cannot be used yet, differently for instance admins", () => {
    expect(workspaceWaitKey("active", false)).toBeNull();
    expect(workspaceWaitKey("awaitingInstanceAdmin", false)).toBe(
      "cwExtWsAwaitingAdmin",
    );
    expect(workspaceWaitKey("awaitingInstanceAdmin", true)).toBe(
      "cwExtWsAwaitingYou",
    );
    expect(workspaceWaitKey("awaitingRemote", true)).toBe(
      "cwExtWsAwaitingRemote",
    );
    expect(workspaceWaitKey("suspended", true)).toBe("cwExtWsSuspended");
  });

  it("queues shares only for a workspace that still awaits approval", () => {
    expect(canQueueFor("awaitingInstanceAdmin")).toBe(true);
    expect(canQueueFor("awaitingRemote")).toBe(true);
    expect(canQueueFor("active")).toBe(false);
    expect(canQueueFor("suspended")).toBe(false);
    expect(queuedStatusKey("queued")).toBe("cwExtQueued");
    expect(queuedStatusKey("declined")).toBe("cwExtQueuedDeclined");
    expect(queuedStatusKey("expired")).toBe("cwExtQueuedExpired");
    expect(queuedStatusKey("dropped")).toBe("cwExtQueuedDropped");
  });

  it("names the status of a grantee", () => {
    expect(granteeStatusKey(0, "active")).toBe("cwExtInvited");
    expect(granteeStatusKey(1, "active")).toBe("cwExtAccepted");
    expect(granteeStatusKey(2, "active")).toBe("cwExtActive");
    expect(granteeStatusKey(2, "suspended")).toBe("cwFedSuspended");
  });
});
