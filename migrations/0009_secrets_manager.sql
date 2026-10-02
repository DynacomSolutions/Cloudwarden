CREATE TABLE `sm_access_policies` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`organization_user_uuid` text,
	`group_uuid` text,
	`service_account_uuid` text,
	`granted_project_uuid` text,
	`granted_secret_uuid` text,
	`granted_service_account_uuid` text,
	`read` integer DEFAULT false NOT NULL,
	`write` integer DEFAULT false NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_user_uuid`) REFERENCES `users_organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`group_uuid`) REFERENCES `groups`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`service_account_uuid`) REFERENCES `sm_service_accounts`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`granted_project_uuid`) REFERENCES `sm_projects`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`granted_secret_uuid`) REFERENCES `sm_secrets`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`granted_service_account_uuid`) REFERENCES `sm_service_accounts`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sm_access_policies_organization_idx` ON `sm_access_policies` (`organization_uuid`);--> statement-breakpoint
CREATE INDEX `sm_access_policies_project_idx` ON `sm_access_policies` (`granted_project_uuid`);--> statement-breakpoint
CREATE INDEX `sm_access_policies_secret_idx` ON `sm_access_policies` (`granted_secret_uuid`);--> statement-breakpoint
CREATE INDEX `sm_access_policies_granted_sa_idx` ON `sm_access_policies` (`granted_service_account_uuid`);--> statement-breakpoint
CREATE INDEX `sm_access_policies_sa_idx` ON `sm_access_policies` (`service_account_uuid`);--> statement-breakpoint
CREATE TABLE `sm_access_tokens` (
	`uuid` text PRIMARY KEY NOT NULL,
	`service_account_uuid` text NOT NULL,
	`name` text NOT NULL,
	`client_secret_hash` text NOT NULL,
	`encrypted_payload` text NOT NULL,
	`key` text NOT NULL,
	`expires_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`service_account_uuid`) REFERENCES `sm_service_accounts`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sm_access_tokens_service_account_idx` ON `sm_access_tokens` (`service_account_uuid`);--> statement-breakpoint
CREATE TABLE `sm_projects` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`name` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sm_projects_organization_idx` ON `sm_projects` (`organization_uuid`);--> statement-breakpoint
CREATE TABLE `sm_secrets` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`key` text NOT NULL,
	`value` text NOT NULL,
	`note` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sm_secrets_organization_idx` ON `sm_secrets` (`organization_uuid`);--> statement-breakpoint
CREATE TABLE `sm_secrets_projects` (
	`secret_uuid` text NOT NULL,
	`project_uuid` text NOT NULL,
	PRIMARY KEY(`secret_uuid`, `project_uuid`),
	FOREIGN KEY (`secret_uuid`) REFERENCES `sm_secrets`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`project_uuid`) REFERENCES `sm_projects`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sm_secrets_projects_project_idx` ON `sm_secrets_projects` (`project_uuid`);--> statement-breakpoint
CREATE TABLE `sm_service_accounts` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`name` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sm_service_accounts_organization_idx` ON `sm_service_accounts` (`organization_uuid`);--> statement-breakpoint
ALTER TABLE `events` ADD `secret_uuid` text;--> statement-breakpoint
ALTER TABLE `events` ADD `project_uuid` text;--> statement-breakpoint
ALTER TABLE `events` ADD `service_account_uuid` text;--> statement-breakpoint
ALTER TABLE `events` ADD `granted_service_account_uuid` text;--> statement-breakpoint
ALTER TABLE `organizations` ADD `secrets_revision_date` integer;--> statement-breakpoint
ALTER TABLE `users_organizations` ADD `access_secrets_manager` integer DEFAULT false NOT NULL;--> statement-breakpoint
-- Existing owners and admins get Secrets Manager access (TASKS #220); others are enabled by an admin.
UPDATE `users_organizations` SET `access_secrets_manager` = 1 WHERE `atype` IN (0, 1);