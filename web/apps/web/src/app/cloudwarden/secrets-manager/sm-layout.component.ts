// Cloudwarden: Secrets Manager layout with its own side navigation (web/NOTICE.md).
import { ChangeDetectionStrategy, Component, inject } from "@angular/core";
import { toSignal } from "@angular/core/rxjs-interop";
import { ActivatedRoute, RouterModule } from "@angular/router";
import { map } from "rxjs";

import { SecretsManagerLogo } from "@bitwarden/assets/svg";
import { I18nPipe } from "@bitwarden/ui-common";

import { WebLayoutModule } from "../../layouts/web-layout.module";

@Component({
  selector: "cw-sm-layout",
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterModule, I18nPipe, WebLayoutModule],
  template: `
    <app-layout>
      <app-side-nav>
        <bit-nav-logo
          [openIcon]="logo"
          [route]="['/sm', organizationId()]"
          [label]="'secretsManager' | i18n"
        ></bit-nav-logo>
        <bit-nav-item
          icon="bwi-collection"
          [text]="'projects' | i18n"
          [route]="['/sm', organizationId(), 'projects']"
        ></bit-nav-item>
        <bit-nav-item
          icon="bwi-key"
          [text]="'secrets' | i18n"
          [route]="['/sm', organizationId(), 'secrets']"
        ></bit-nav-item>
        <bit-nav-item
          icon="bwi-wrench"
          [text]="'machineAccounts' | i18n"
          [route]="['/sm', organizationId(), 'machine-accounts']"
        ></bit-nav-item>
      </app-side-nav>
      <router-outlet></router-outlet>
    </app-layout>
  `,
})
export class SmLayoutComponent {
  protected readonly logo = SecretsManagerLogo;
  protected readonly organizationId = toSignal(
    inject(ActivatedRoute).paramMap.pipe(map((p) => p.get("organizationId") ?? "")),
    { initialValue: "" },
  );
}
