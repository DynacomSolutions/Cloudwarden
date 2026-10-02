CREATE TABLE `organization_domains` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`domain_name` text NOT NULL,
	`txt` text NOT NULL,
	`verified_at` integer,
	`last_checked_at` integer,
	`next_run_at` integer NOT NULL,
	`job_run_count` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `organization_domains_org_domain_unique` ON `organization_domains` (`organization_uuid`,`domain_name`);--> statement-breakpoint
CREATE INDEX `organization_domains_domain_idx` ON `organization_domains` (`domain_name`);--> statement-breakpoint
CREATE INDEX `organization_domains_next_run_idx` ON `organization_domains` (`next_run_at`);--> statement-breakpoint
CREATE TABLE `sso_codes` (
	`code_hash` text PRIMARY KEY NOT NULL,
	`user_uuid` text NOT NULL,
	`organization_uuid` text NOT NULL,
	`client_id` text NOT NULL,
	`redirect_uri` text NOT NULL,
	`code_challenge` text NOT NULL,
	`used_at` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sso_codes_created_idx` ON `sso_codes` (`created_at`);--> statement-breakpoint
CREATE TABLE `sso_configs` (
	`organization_uuid` text PRIMARY KEY NOT NULL,
	`enabled` integer DEFAULT false NOT NULL,
	`data` text NOT NULL,
	`sp_private_key` text,
	`sp_certificate` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `sso_flows` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`client_id` text NOT NULL,
	`redirect_uri` text NOT NULL,
	`code_challenge` text NOT NULL,
	`client_state` text NOT NULL,
	`binding_hash` text NOT NULL,
	`nonce` text,
	`idp_code_verifier` text,
	`saml_request_id` text,
	`link_user_uuid` text,
	`consumed_at` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sso_flows_created_idx` ON `sso_flows` (`created_at`);--> statement-breakpoint
CREATE TABLE `sso_replay` (
	`key` text PRIMARY KEY NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `sso_replay_expires_idx` ON `sso_replay` (`expires_at`);--> statement-breakpoint
CREATE TABLE `sso_users` (
	`organization_uuid` text NOT NULL,
	`user_uuid` text NOT NULL,
	`external_id` text NOT NULL,
	`created_at` integer NOT NULL,
	PRIMARY KEY(`organization_uuid`, `external_id`),
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sso_users_org_user_unique` ON `sso_users` (`organization_uuid`,`user_uuid`);--> statement-breakpoint
CREATE INDEX `sso_users_user_idx` ON `sso_users` (`user_uuid`);--> statement-breakpoint
ALTER TABLE `devices` ADD `encrypted_user_key` text;--> statement-breakpoint
ALTER TABLE `devices` ADD `encrypted_public_key` text;--> statement-breakpoint
ALTER TABLE `devices` ADD `encrypted_private_key` text;--> statement-breakpoint
ALTER TABLE `organizations` ADD `identifier` text;--> statement-breakpoint
CREATE UNIQUE INDEX `organizations_identifier_unique` ON `organizations` (lower("identifier"));--> statement-breakpoint
ALTER TABLE `users` ADD `uses_key_connector` integer DEFAULT false NOT NULL;