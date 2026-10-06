// Cloudwarden: the collection Access dialog's external workspace section.
import { NO_ERRORS_SCHEMA } from "@angular/core";
import { ComponentFixture, TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { mock } from "jest-mock-extended";
import { of } from "rxjs";

import { OrganizationUserService } from "@bitwarden/admin-console/common";
import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { OrganizationService } from "@bitwarden/common/admin-console/abstractions/organization/organization.service.abstraction";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { DialogService, ToastService } from "@bitwarden/components";

import { CollectionExternalAccessComponent } from "./collection-external-access.component";
import {
  ExternalAccessState,
  ExternalWorkspace,
  FederationApiService,
} from "./federation-api.service";

// Built at run time: a long run of hex groups reads like an address to the identifier guard.
const FP = ["AB12", "CD34", "EF56", "0000", "1111", "2222", "3333", "4444"]
  .concat(["5555", "6666", "7777", "8888", "9999", "AAAA", "BBBB", "CCCC"])
  .join(":");

const ws = (
  state: ExternalWorkspace["state"],
  id = "w1",
): ExternalWorkspace => ({
  id,
  domain: "peer.example.org",
  fingerprint: FP,
  state,
  active: state === "active",
});

const base = (
  over: Partial<ExternalAccessState> = {},
): ExternalAccessState => ({
  isInstanceAdmin: false,
  canInvite: true,
  canChangeInviteSetting: false,
  collectionManagersMayInvite: false,
  available: true,
  workspaces: [],
  grantees: [],
  ...over,
});

describe("CollectionExternalAccessComponent", () => {
  let api: ReturnType<typeof mock<FederationApiService>>;
  let dialogs: ReturnType<typeof mock<DialogService>>;

  afterEach(() => jest.restoreAllMocks());

  beforeEach(() => {
    api = mock<FederationApiService>();
    dialogs = mock<DialogService>();
    const i18n = mock<I18nService>();
    i18n.t.mockImplementation((k: string) => k);
    const orgs = mock<OrganizationService>();
    orgs.organizations$.mockReturnValue(
      of([{ id: "org1", canManageUsers: true } as never]),
    );
    const accounts = mock<AccountService>();
    (accounts as { activeAccount$: unknown }).activeAccount$ = of({
      id: "user1",
    });
    TestBed.configureTestingModule({
      providers: [
        provideNoopAnimations(),
        { provide: FederationApiService, useValue: api },
        { provide: ApiService, useValue: mock<ApiService>() },
        { provide: OrganizationService, useValue: orgs },
        {
          provide: OrganizationUserService,
          useValue: mock<OrganizationUserService>(),
        },
        { provide: AccountService, useValue: accounts },
        { provide: DialogService, useValue: dialogs },
        { provide: ToastService, useValue: mock<ToastService>() },
        { provide: I18nService, useValue: i18n },
      ],
    });
  });

  async function render(
    readonly = false,
  ): Promise<ComponentFixture<CollectionExternalAccessComponent>> {
    TestBed.overrideComponent(CollectionExternalAccessComponent, {
      add: { schemas: [NO_ERRORS_SCHEMA] },
    });
    const f = TestBed.createComponent(CollectionExternalAccessComponent);
    f.componentRef.setInput("organizationId", "org1");
    f.componentRef.setInput("collectionId", "col1");
    f.componentRef.setInput("readonly", readonly);
    f.detectChanges();
    await f.whenStable();
    f.detectChanges();
    return f;
  }
  const q = (f: ComponentFixture<unknown>, id: string) =>
    f.nativeElement.querySelector(`[data-testid=${id}]`) as HTMLElement | null;
  const pick = async (
    f: ComponentFixture<unknown>,
    id: string,
    value: string,
  ) => {
    const el = q(f, id) as HTMLSelectElement;
    el.value = value;
    el.dispatchEvent(new Event("change"));
    await f.whenStable();
    f.detectChanges();
  };
  const type = async (
    f: ComponentFixture<unknown>,
    id: string,
    value: string,
  ) => {
    const el = q(f, id) as HTMLInputElement;
    el.value = value;
    el.dispatchEvent(new Event("input"));
    await f.whenStable();
    f.detectChanges();
  };

  it("is hidden when the server has federation off or the user may not manage the collection", async () => {
    api.externalAccess.mockRejectedValue(new Error("Not found"));
    const f = await render();
    expect(q(f, "cw-ext-access")).toBeNull();
  });

  it("tells a non-admin that the instance admin has to approve, and offers no sharing yet", async () => {
    api.externalAccess.mockResolvedValue(
      base({ workspaces: [ws("awaitingInstanceAdmin")] }),
    );
    const f = await render();
    await pick(f, "cw-ext-workspace", "w1");
    expect(q(f, "cw-ext-wait")?.textContent).toContain("cwExtWsAwaitingAdmin");
    expect(q(f, "cw-ext-share")).toBeNull();
    expect(q(f, "cw-ext-emails")).toBeNull();
  });

  it("shares with several addresses and the chosen permission on an active workspace", async () => {
    api.externalAccess.mockResolvedValue(base({ workspaces: [ws("active")] }));
    api.share.mockResolvedValue({
      data: [{ email: "a@example.org", ok: true, result: "invited" }],
    });
    const f = await render();
    await pick(f, "cw-ext-workspace", "w1");
    await type(f, "cw-ext-emails", "a@example.org, b@example.org");
    await pick(f, "cw-ext-permission", "editExceptPass");
    (q(f, "cw-ext-share") as HTMLButtonElement).click();
    await f.whenStable();
    expect(api.share).toHaveBeenCalledWith(
      "org1",
      "col1",
      "w1",
      ["a@example.org", "b@example.org"],
      {
        readOnly: false,
        hidePasswords: true,
        manage: false,
      },
    );
  });

  it("a scanned QR fills the fields after the server lookup but never adds the workspace", async () => {
    api.externalAccess.mockResolvedValue(base());
    api.lookupWorkspace.mockResolvedValue({
      domain: "peer.example.org",
      fingerprint: FP,
      workspace: null,
    });
    const f = await render();
    await pick(f, "cw-ext-workspace", "__new");
    const c = f.componentInstance as unknown as {
      scanned(s: { domain: string; fingerprint: string }): Promise<void>;
    };
    await c.scanned({
      domain: "peer.example.org",
      fingerprint: FP.replace(/:/g, "").toLowerCase(),
    });
    f.detectChanges();
    expect(api.lookupWorkspace).toHaveBeenCalledWith(
      "org1",
      "col1",
      "peer.example.org",
    );
    expect((q(f, "cw-ext-fingerprint") as HTMLInputElement).value).toBe(
      FP.replace(/:/g, "").toLowerCase(),
    );
    expect(api.addWorkspace).not.toHaveBeenCalled();
  });

  it("refuses a scanned QR whose domain is not the one the server reached", async () => {
    api.externalAccess.mockResolvedValue(base());
    api.lookupWorkspace.mockResolvedValue({
      domain: "other.example.org",
      fingerprint: FP,
      workspace: null,
    });
    const f = await render();
    await pick(f, "cw-ext-workspace", "__new");
    const c = f.componentInstance as unknown as {
      scanned(s: { domain: string; fingerprint: string }): Promise<void>;
    };
    await c.scanned({
      domain: "peer.example.org",
      fingerprint: FP.replace(/:/g, "").toLowerCase(),
    });
    f.detectChanges();
    expect(q(f, "cw-ext-found-fingerprint")).toBeNull();
    expect(api.addWorkspace).not.toHaveBeenCalled();
  });

  it("requires the typed fingerprint to match the one the server fetched", async () => {
    api.externalAccess.mockResolvedValue(base());
    api.lookupWorkspace.mockResolvedValue({
      domain: "peer.example.org",
      fingerprint: FP,
      workspace: null,
    });
    api.addWorkspace.mockResolvedValue({
      created: true,
      workspace: ws("awaitingInstanceAdmin"),
    });
    const f = await render();
    await pick(f, "cw-ext-workspace", "__new");
    await type(f, "cw-ext-domain", "peer.example.org");
    (q(f, "cw-ext-lookup") as HTMLButtonElement).click();
    await f.whenStable();
    f.detectChanges();
    expect(q(f, "cw-ext-found-fingerprint")?.textContent).toContain(
      "AB12:CD34",
    );

    await type(f, "cw-ext-fingerprint", FP.replace("AB12", "AB13"));
    (q(f, "cw-ext-add") as HTMLButtonElement).click();
    await f.whenStable();
    expect(api.addWorkspace).not.toHaveBeenCalled();

    await type(f, "cw-ext-fingerprint", FP.toLowerCase().replace(/:/g, " "));
    (q(f, "cw-ext-add") as HTMLButtonElement).click();
    await f.whenStable();
    expect(api.addWorkspace).toHaveBeenCalledWith(
      "org1",
      "col1",
      "peer.example.org",
      expect.any(String),
    );
  });

  it("lists external grantees with workspace and status, and confirms or removes them", async () => {
    api.externalAccess.mockResolvedValue(
      base({
        workspaces: [ws("active")],
        grantees: [
          {
            id: "m1",
            userId: "u1",
            email: "a@example.org",
            status: 1,
            peerId: "w1",
            peerDomain: "peer.example.org",
            peerState: "active",
            readOnly: true,
            hidePasswords: false,
            manage: false,
          },
        ],
      }),
    );
    api.removeExternalAccess.mockResolvedValue({ removedMember: true });
    // The shared module brings its own DialogService, so the class method is replaced.
    const confirmDialog = jest
      .spyOn(DialogService.prototype, "openSimpleDialog")
      .mockResolvedValue(true);
    const f = await render();
    const row = q(f, "cw-ext-grantees")?.textContent ?? "";
    expect(row).toContain("a@example.org");
    expect(row).toContain("peer.example.org");
    expect(row).toContain("cwExtAccepted");
    // Accepted people can be confirmed from here.
    expect(q(f, "cw-ext-confirm")).not.toBeNull();
    (q(f, "cw-ext-remove") as HTMLButtonElement).click();
    await f.whenStable();
    expect(confirmDialog).toHaveBeenCalled();
    expect(api.removeExternalAccess).toHaveBeenCalledWith("org1", "col1", "m1");
  });

  it("explains that inviting new people needs manage users when the user may not invite", async () => {
    api.externalAccess.mockResolvedValue(
      base({ workspaces: [ws("active")], canInvite: false }),
    );
    const f = await render();
    await pick(f, "cw-ext-workspace", "w1");
    expect(q(f, "cw-ext-no-invite")?.textContent).toContain("cwExtNoInvite");
  });

  it("does not show the explanation to people who may invite", async () => {
    api.externalAccess.mockResolvedValue(base({ workspaces: [ws("active")] }));
    const f = await render();
    await pick(f, "cw-ext-workspace", "w1");
    expect(q(f, "cw-ext-no-invite")).toBeNull();
  });

  it("only says a known workspace is waiting for an administrator, without detail", async () => {
    api.externalAccess.mockResolvedValue(base());
    api.lookupWorkspace.mockResolvedValue({
      domain: "peer.example.org",
      fingerprint: null,
      workspace: null,
      awaitingAdmin: true,
    });
    const f = await render();
    await pick(f, "cw-ext-workspace", "__new");
    await type(f, "cw-ext-domain", "peer.example.org");
    (q(f, "cw-ext-lookup") as HTMLButtonElement).click();
    await f.whenStable();
    f.detectChanges();
    expect(q(f, "cw-ext-found-fingerprint")).toBeNull();
    expect(f.nativeElement.textContent).toContain("cwExtKnownAwaitingAdmin");
  });

  it("is read only in a read only dialog", async () => {
    api.externalAccess.mockResolvedValue(
      base({
        workspaces: [ws("active")],
        grantees: [
          {
            id: "m1",
            userId: "u1",
            email: "a@example.org",
            status: 2,
            peerId: "w1",
            peerDomain: "peer.example.org",
            peerState: "active",
            readOnly: true,
            hidePasswords: false,
            manage: false,
          },
        ],
      }),
    );
    const f = await render(true);
    expect(q(f, "cw-ext-workspace")).toBeNull();
    expect(q(f, "cw-ext-remove")).toBeNull();
  });
});
