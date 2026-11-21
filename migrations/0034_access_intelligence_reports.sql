CREATE TABLE `organization_reports` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`content_encryption_key` text,
	`summary_data` text,
	`application_data` text,
	`metrics` text,
	`blob_key` text,
	`file_id` text,
	`file_name` text,
	`file_size` integer,
	`file_validated` integer DEFAULT false NOT NULL,
	`upload_started_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `organization_reports_org_created_idx` ON `organization_reports` (`organization_uuid`,`created_at`);--> statement-breakpoint
CREATE TABLE `password_health_report_applications` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`uri` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `password_health_report_applications_org_idx` ON `password_health_report_applications` (`organization_uuid`);