import { TestBed } from "@angular/core/testing";
import { Router, UrlTree } from "@angular/router";
import { firstValueFrom, isObservable, Observable, of } from "rxjs";

import { InstanceAdminApiService } from "../instance-admin/instance-admin-api.service";

import { canCreateOrganizationsGuard } from "./can-create-organizations.guard";

describe("canCreateOrganizationsGuard", () => {
  const vaultTree = {} as UrlTree;
  const run = async (allowed: boolean) => {
    TestBed.configureTestingModule({
      providers: [
        {
          provide: InstanceAdminApiService,
          useValue: { canCreateOrganizations$: of(allowed) },
        },
        {
          provide: Router,
          useValue: { createUrlTree: jest.fn().mockReturnValue(vaultTree) },
        },
      ],
    });
    const result = TestBed.runInInjectionContext(() =>
      canCreateOrganizationsGuard({} as any, {} as any),
    );
    return isObservable(result)
      ? firstValueFrom(result as Observable<unknown>)
      : result;
  };

  it("lets owners and admins open the create page", async () => {
    expect(await run(true)).toBe(true);
  });

  it("sends everyone else to the vault", async () => {
    expect(await run(false)).toBe(vaultTree);
  });
});
