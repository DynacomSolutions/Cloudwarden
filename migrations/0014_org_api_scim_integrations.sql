CREATE TABLE `org_integrations` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`atype` text NOT NULL,
	`name` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`config` text NOT NULL,
	`sealed_secrets` text NOT NULL,
	`event_types` text,
	`cursor` integer DEFAULT 0 NOT NULL,
	`failure_count` integer DEFAULT 0 NOT NULL,
	`next_attempt_at` integer DEFAULT 0 NOT NULL,
	`last_error` text,
	`last_success_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);

--> statement-breakpoint
CREATE INDEX `org_integrations_organization_idx` ON `org_integrations` (`organization_uuid`);
--> statement-breakpoint
CREATE TABLE `organization_api_keys` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`atype` integer NOT NULL,
	`sealed_key` text NOT NULL,
	`revision_date` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);

--> statement-breakpoint
CREATE UNIQUE INDEX `organization_api_keys_org_type_unique` ON `organization_api_keys` (`organization_uuid`,`atype`);
--> statement-breakpoint
CREATE TABLE `organization_scim` (
	`organization_uuid` text PRIMARY KEY NOT NULL,
	`enabled` integer DEFAULT false NOT NULL,
	`provider` integer,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);

--> statement-breakpoint
ALTER TABLE `events` ADD `system_user` integer;