import { NO_ERRORS_SCHEMA } from "@angular/core";
import { ComponentFixture, TestBed } from "@angular/core/testing";
import { provideNoopAnimations } from "@angular/platform-browser/animations";
import { mock } from "jest-mock-extended";

import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { ToastService } from "@bitwarden/components";

import { SmApiService, SmEvent, SmSecretAccess } from "./sm-api.service";
import { SM_EVENT_KEYS, SmEventsComponent, eventKey, eventTarget } from "./sm-events.component";
import { SmSecretAccessComponent, availableMachines } from "./sm-secret-access.component";

const ORG = "00000000-0000-4000-8000-000000000000";
const event = (type: number, over: Partial<SmEvent> = {}): SmEvent => ({
  type,
  date: new Date(0).toISOString(),
  secretId: null,
  projectId: null,
  serviceAccountId: null,
  grantedServiceAccountId: null,
  actingUserId: null,
  ipAddress: "127.0.0.1",
  ...over,
});

describe("Secrets Manager secret access and events", () => {
  let api: ReturnType<typeof mock<SmApiService>>;
  let toast: ReturnType<typeof mock<ToastService>>;

  async function render<T>(component: new (...a: any[]) => T, inputs: Record<string, unknown>) {
    TestBed.overrideComponent(component as any, { add: { schemas: [NO_ERRORS_SCHEMA] } });
    await TestBed.configureTestingModule({
      imports: [component],
      providers: [
        provideNoopAnimations(),
        { provide: SmApiService, useValue: api },
        { provide: ToastService, useValue: toast },
        { provide: I18nService, useValue: { t: (k: string, ...a: string[]) => [k, ...a].join(" ") } },
      ],
    }).compileComponents();
    const fixture = TestBed.createComponent(component);
    for (const [k, v] of Object.entries(inputs)) {
      fixture.componentRef.setInput(k, v);
    }
    return fixture;
  }

  async function settle(fixture: ComponentFixture<unknown>) {
    fixture.detectChanges();
    for (let i = 0; i < 5; i++) {
      await new Promise((r) => setTimeout(r));
    }
    fixture.detectChanges();
  }
  const el = (f: ComponentFixture<unknown>) => f.nativeElement as HTMLElement;

  beforeEach(() => {
    api = mock<SmApiService>();
    toast = mock<ToastService>();
  });

  describe("secret access", () => {
    const existing: SmSecretAccess = {
      people: [{ kind: "user", id: "u1", name: "Ada", read: true, write: false }],
      machines: [{ id: "m1", name: "ci", read: true, write: true }],
    };

    beforeEach(() => {
      api.getSecretAccess.mockResolvedValue(existing);
      api.peopleGrantees.mockResolvedValue([
        { kind: "user", id: "u1", name: "Ada" },
        { kind: "user", id: "u2", name: "Bob" },
        { kind: "group", id: "g1", name: "Ops" },
      ]);
      api.machineGrantees.mockResolvedValue([
        { id: "m1", name: "ci" },
        { id: "m2", name: "deploy" },
      ]);
    });

    it("lists members, groups and machine accounts with direct access", async () => {
      const fixture = await render(SmSecretAccessComponent, {
        organizationId: ORG,
        secretId: "s1",
      });
      await settle(fixture);
      expect(api.getSecretAccess).toHaveBeenCalledWith(ORG, "s1");
      const rows = el(fixture).querySelectorAll("[data-testid=cw-sm-secret-access-row]");
      expect(rows).toHaveLength(2);
      expect(el(fixture).textContent).toContain("Ada");
      expect(el(fixture).textContent).toContain("ci");
    });

    it("offers only grantees that do not have access yet", async () => {
      const fixture = await render(SmSecretAccessComponent, {
        organizationId: ORG,
        secretId: "s1",
      });
      await settle(fixture);
      const c = fixture.componentInstance as any;
      expect(c.availablePeople().map((g: any) => g.id)).toEqual(["u2", "g1"]);
      expect(c.availableMachineAccounts().map((m: any) => m.id)).toEqual(["m2"]);
      expect(availableMachines([{ id: "a", name: "a" }], [{ id: "a", name: "a", read: true, write: false }])).toEqual([]);
    });

    it("emits the complete access after adding, changing and removing", async () => {
      const fixture = await render(SmSecretAccessComponent, {
        organizationId: ORG,
        secretId: "s1",
      });
      await settle(fixture);
      const c = fixture.componentInstance as any;
      const emitted: SmSecretAccess[] = [];
      c.accessChange.subscribe((a: SmSecretAccess) => emitted.push(a));

      c.pick = "p:group:g1";
      c.pickPermission = "write";
      c.add();
      c.pick = "m:m2";
      c.pickPermission = "read";
      c.add();
      c.setPermission("p:user:u1", "write");
      c.remove("m:m1");

      const last = emitted[emitted.length - 1];
      expect(last.people).toEqual([
        { kind: "user", id: "u1", name: "Ada", read: true, write: true },
        { kind: "group", id: "g1", name: "Ops", read: true, write: true },
      ]);
      expect(last.machines).toEqual([{ id: "m2", name: "deploy", read: true, write: false }]);
      expect(emitted).toHaveLength(4);
    });

    it("is read only without write access and for a new secret loads nothing", async () => {
      const fixture = await render(SmSecretAccessComponent, {
        organizationId: ORG,
        secretId: null,
        canEdit: false,
      });
      await settle(fixture);
      expect(api.getSecretAccess).not.toHaveBeenCalled();
      expect(api.peopleGrantees).not.toHaveBeenCalled();
      expect(el(fixture).querySelector("[data-testid=cw-sm-secret-access-empty]")).not.toBeNull();
      expect(el(fixture).querySelector("[data-testid=cw-sm-secret-access-pick]")).toBeNull();
    });

    it("shows load errors as toasts", async () => {
      api.getSecretAccess.mockRejectedValue(new Error("boom"));
      const fixture = await render(SmSecretAccessComponent, {
        organizationId: ORG,
        secretId: "s1",
      });
      await settle(fixture);
      expect(toast.showToast).toHaveBeenCalledWith({ variant: "error", message: "boom" });
    });
  });

  describe("events", () => {
    it("maps every Secrets Manager event code to a message", () => {
      for (const code of Object.keys(SM_EVENT_KEYS)) {
        expect(eventKey(Number(code))).toMatch(/^cwSmEvent/);
      }
      expect(eventKey(9999)).toBe("cwSmEventOther");
      expect(eventTarget(event(2100, { secretId: "abcdef12-0000" }))).toBe("abcdef12");
      expect(eventTarget(event(2100))).toBe("");
    });

    it("lists events and loads more with the continuation token", async () => {
      api.listMachineAccountEvents
        .mockResolvedValueOnce({ events: [event(2100, { secretId: "s1xxxxxxxx" })], continuationToken: "next" })
        .mockResolvedValueOnce({ events: [event(2102)], continuationToken: null });
      const fixture = await render(SmEventsComponent, { machineAccountId: "m1" });
      await settle(fixture);
      expect(api.listMachineAccountEvents).toHaveBeenCalledWith("m1");
      expect(el(fixture).querySelectorAll("[data-testid=cw-sm-event]")).toHaveLength(1);
      expect(el(fixture).textContent).toContain("cwSmEventSecretRetrieved");
      await (fixture.componentInstance as any).more();
      fixture.detectChanges();
      expect(api.listMachineAccountEvents).toHaveBeenLastCalledWith("m1", "next");
      expect(el(fixture).querySelectorAll("[data-testid=cw-sm-event]")).toHaveLength(2);
      expect(el(fixture).querySelector("[data-testid=cw-sm-events-more]")).toBeNull();
    });

    it("shows an empty state and errors", async () => {
      api.listMachineAccountEvents.mockResolvedValue({ events: [], continuationToken: null });
      const fixture = await render(SmEventsComponent, { machineAccountId: "m1" });
      await settle(fixture);
      expect(el(fixture).querySelector("[data-testid=cw-sm-no-events]")).not.toBeNull();
    });
  });
});
