CREATE TABLE `organization_twofactor` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`atype` integer NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`data` text NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `organization_twofactor_org_type_unique` ON `organization_twofactor` (`organization_uuid`,`atype`);