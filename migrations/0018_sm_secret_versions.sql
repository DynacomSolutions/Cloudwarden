CREATE TABLE `sm_secret_versions` (
	`uuid` text PRIMARY KEY NOT NULL,
	`secret_uuid` text NOT NULL,
	`value` text NOT NULL,
	`version_date` integer NOT NULL,
	`editor_service_account_uuid` text,
	`editor_organization_user_uuid` text,
	FOREIGN KEY (`secret_uuid`) REFERENCES `sm_secrets`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`editor_service_account_uuid`) REFERENCES `sm_service_accounts`(`uuid`) ON UPDATE no action ON DELETE set null,
	FOREIGN KEY (`editor_organization_user_uuid`) REFERENCES `users_organizations`(`uuid`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `sm_secret_versions_secret_idx` ON `sm_secret_versions` (`secret_uuid`,`version_date`);