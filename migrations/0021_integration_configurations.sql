CREATE TABLE `org_integration_configurations` (
	`uuid` text PRIMARY KEY NOT NULL,
	`integration_uuid` text NOT NULL,
	`event_type` integer,
	`filters` text,
	`template` text,
	`config` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`integration_uuid`) REFERENCES `org_integrations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `org_integration_configurations_integration_idx` ON `org_integration_configurations` (`integration_uuid`);