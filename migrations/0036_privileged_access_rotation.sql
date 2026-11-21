CREATE TABLE `pam_access_connectors` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`name` text NOT NULL,
	`status` integer DEFAULT 0 NOT NULL,
	`api_key_id` text NOT NULL,
	`client_secret_hash` text NOT NULL,
	`encrypted_payload` text NOT NULL,
	`key` text NOT NULL,
	`last_heartbeat_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `pam_access_connectors_org_idx` ON `pam_access_connectors` (`organization_uuid`);--> statement-breakpoint
CREATE UNIQUE INDEX `pam_access_connectors_api_key_unique` ON `pam_access_connectors` (`api_key_id`);--> statement-breakpoint
CREATE TABLE `pam_audit` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`kind` text NOT NULL,
	`actor_uuid` text,
	`ref_uuid` text,
	`detail` text,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `pam_audit_org_idx` ON `pam_audit` (`organization_uuid`,`created_at`);--> statement-breakpoint
CREATE TABLE `pam_connector_assignments` (
	`connector_uuid` text NOT NULL,
	`target_system_uuid` text NOT NULL,
	`created_at` integer NOT NULL,
	PRIMARY KEY(`connector_uuid`, `target_system_uuid`),
	FOREIGN KEY (`connector_uuid`) REFERENCES `pam_access_connectors`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`target_system_uuid`) REFERENCES `pam_target_systems`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `pam_connector_assignments_target_idx` ON `pam_connector_assignments` (`target_system_uuid`);--> statement-breakpoint
CREATE TABLE `pam_rotation_attempts` (
	`uuid` text PRIMARY KEY NOT NULL,
	`job_uuid` text NOT NULL,
	`connector_uuid` text,
	`cipher_updated` integer DEFAULT false NOT NULL,
	`status` integer DEFAULT 0 NOT NULL,
	`failure_reason` text,
	`sync_state` integer,
	`session_termination` integer,
	`created_at` integer NOT NULL,
	`resolved_at` integer,
	FOREIGN KEY (`job_uuid`) REFERENCES `pam_rotation_jobs`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`connector_uuid`) REFERENCES `pam_access_connectors`(`uuid`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE INDEX `pam_rotation_attempts_job_idx` ON `pam_rotation_attempts` (`job_uuid`);--> statement-breakpoint
CREATE TABLE `pam_rotation_configs` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`cipher_uuid` text NOT NULL,
	`target_system_uuid` text NOT NULL,
	`sealed_data` text NOT NULL,
	`wrapped_key` text NOT NULL,
	`schedule_cron` text,
	`rotate_on_access_end` integer DEFAULT false NOT NULL,
	`next_rotation_at` integer,
	`enabled` integer DEFAULT true NOT NULL,
	`last_rotation_at` integer,
	`awaiting_manual_rotation` integer DEFAULT false NOT NULL,
	`last_on_demand_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`target_system_uuid`) REFERENCES `pam_target_systems`(`uuid`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `pam_rotation_configs_cipher_unique` ON `pam_rotation_configs` (`cipher_uuid`);--> statement-breakpoint
CREATE INDEX `pam_rotation_configs_org_idx` ON `pam_rotation_configs` (`organization_uuid`);--> statement-breakpoint
CREATE INDEX `pam_rotation_configs_target_idx` ON `pam_rotation_configs` (`target_system_uuid`);--> statement-breakpoint
CREATE INDEX `pam_rotation_configs_due_idx` ON `pam_rotation_configs` (`next_rotation_at`);--> statement-breakpoint
CREATE TABLE `pam_rotation_jobs` (
	`uuid` text PRIMARY KEY NOT NULL,
	`config_uuid` text NOT NULL,
	`organization_uuid` text NOT NULL,
	`target_system_uuid` text NOT NULL,
	`source` integer NOT NULL,
	`status` integer DEFAULT 0 NOT NULL,
	`claimed_by_connector_uuid` text,
	`claimed_at` integer,
	`next_claimable_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`config_uuid`) REFERENCES `pam_rotation_configs`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`claimed_by_connector_uuid`) REFERENCES `pam_access_connectors`(`uuid`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `pam_rotation_jobs_open_unique` ON `pam_rotation_jobs` (`config_uuid`) WHERE "pam_rotation_jobs"."status" in (0, 1);--> statement-breakpoint
CREATE INDEX `pam_rotation_jobs_target_idx` ON `pam_rotation_jobs` (`target_system_uuid`,`status`);--> statement-breakpoint
CREATE INDEX `pam_rotation_jobs_org_idx` ON `pam_rotation_jobs` (`organization_uuid`);--> statement-breakpoint
CREATE TABLE `pam_target_systems` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`name` text NOT NULL,
	`method` integer NOT NULL,
	`status` integer DEFAULT 2 NOT NULL,
	`sealed_data` text,
	`wrapped_key` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `pam_target_systems_org_idx` ON `pam_target_systems` (`organization_uuid`);