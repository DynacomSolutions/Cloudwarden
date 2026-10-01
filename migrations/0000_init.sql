CREATE TABLE `attachments` (
	`id` text PRIMARY KEY NOT NULL,
	`cipher_uuid` text NOT NULL,
	`file_name` text NOT NULL,
	`file_size` integer NOT NULL,
	`akey` text,
	`r2_key` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `attachments_cipher_idx` ON `attachments` (`cipher_uuid`);--> statement-breakpoint
CREATE TABLE `ciphers` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text,
	`organization_uuid` text,
	`atype` integer NOT NULL,
	`name` text NOT NULL,
	`notes` text,
	`fields` text,
	`data` text NOT NULL,
	`password_history` text,
	`reprompt` integer,
	`akey` text,
	`favorite` integer DEFAULT false NOT NULL,
	`deleted_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `ciphers_user_idx` ON `ciphers` (`user_uuid`);--> statement-breakpoint
CREATE INDEX `ciphers_organization_idx` ON `ciphers` (`organization_uuid`);--> statement-breakpoint
CREATE TABLE `ciphers_collections` (
	`cipher_uuid` text NOT NULL,
	`collection_uuid` text NOT NULL,
	PRIMARY KEY(`cipher_uuid`, `collection_uuid`),
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`collection_uuid`) REFERENCES `collections`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `ciphers_collections_collection_idx` ON `ciphers_collections` (`collection_uuid`);--> statement-breakpoint
CREATE TABLE `collections` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`name` text NOT NULL,
	`external_id` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `collections_organization_idx` ON `collections` (`organization_uuid`);--> statement-breakpoint
CREATE TABLE `devices` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text NOT NULL,
	`name` text NOT NULL,
	`type` integer NOT NULL,
	`push_token` text,
	`refresh_token` text NOT NULL,
	`twofactor_remember` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `devices_user_idx` ON `devices` (`user_uuid`);--> statement-breakpoint
CREATE TABLE `events` (
	`uuid` text PRIMARY KEY NOT NULL,
	`event_type` integer NOT NULL,
	`user_uuid` text,
	`organization_uuid` text,
	`cipher_uuid` text,
	`collection_uuid` text,
	`acting_user_uuid` text,
	`device_type` integer,
	`ip_address` text,
	`event_date` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `events_organization_idx` ON `events` (`organization_uuid`);--> statement-breakpoint
CREATE INDEX `events_user_idx` ON `events` (`user_uuid`);--> statement-breakpoint
CREATE INDEX `events_date_idx` ON `events` (`event_date`);--> statement-breakpoint
CREATE TABLE `folders` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text NOT NULL,
	`name` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `folders_user_idx` ON `folders` (`user_uuid`);--> statement-breakpoint
CREATE TABLE `folders_ciphers` (
	`cipher_uuid` text NOT NULL,
	`folder_uuid` text NOT NULL,
	PRIMARY KEY(`cipher_uuid`, `folder_uuid`),
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`folder_uuid`) REFERENCES `folders`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `folders_ciphers_folder_idx` ON `folders_ciphers` (`folder_uuid`);--> statement-breakpoint
CREATE TABLE `organizations` (
	`uuid` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`billing_email` text NOT NULL,
	`private_key` text,
	`public_key` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `sends` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text,
	`organization_uuid` text,
	`name` text NOT NULL,
	`notes` text,
	`atype` integer NOT NULL,
	`data` text NOT NULL,
	`akey` text NOT NULL,
	`password_hash` text,
	`password_salt` text,
	`password_iter` integer,
	`max_access_count` integer,
	`access_count` integer DEFAULT 0 NOT NULL,
	`disabled` integer DEFAULT false NOT NULL,
	`hide_email` integer,
	`r2_key` text,
	`expiration_date` integer,
	`deletion_date` integer NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `sends_user_idx` ON `sends` (`user_uuid`);--> statement-breakpoint
CREATE INDEX `sends_organization_idx` ON `sends` (`organization_uuid`);--> statement-breakpoint
CREATE INDEX `sends_deletion_date_idx` ON `sends` (`deletion_date`);--> statement-breakpoint
CREATE TABLE `twofactor` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text NOT NULL,
	`atype` integer NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`data` text NOT NULL,
	`last_used` integer DEFAULT 0 NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `twofactor_user_type_unique` ON `twofactor` (`user_uuid`,`atype`);--> statement-breakpoint
CREATE TABLE `users` (
	`uuid` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`name` text NOT NULL,
	`password_hash` text NOT NULL,
	`salt` text NOT NULL,
	`password_iterations` integer NOT NULL,
	`password_hint` text,
	`akey` text NOT NULL,
	`private_key` text,
	`public_key` text,
	`kdf_type` integer DEFAULT 0 NOT NULL,
	`kdf_iterations` integer DEFAULT 600000 NOT NULL,
	`kdf_memory` integer,
	`kdf_parallelism` integer,
	`security_stamp` text NOT NULL,
	`stamp_exception` text,
	`totp_recover` text,
	`equivalent_domains` text DEFAULT '[]' NOT NULL,
	`excluded_globals` text DEFAULT '[]' NOT NULL,
	`client_kdf_type` integer DEFAULT 0 NOT NULL,
	`client_kdf_iter` integer DEFAULT 600000 NOT NULL,
	`client_kdf_memory` integer,
	`client_kdf_parallelism` integer,
	`verified_at` integer,
	`last_verifying_at` integer,
	`login_verify_count` integer DEFAULT 0 NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_email_unique` ON `users` (`email`);--> statement-breakpoint
CREATE TABLE `users_collections` (
	`user_uuid` text NOT NULL,
	`collection_uuid` text NOT NULL,
	`read_only` integer DEFAULT false NOT NULL,
	`hide_passwords` integer DEFAULT false NOT NULL,
	`manage` integer DEFAULT false NOT NULL,
	PRIMARY KEY(`user_uuid`, `collection_uuid`),
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`collection_uuid`) REFERENCES `collections`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `users_collections_collection_idx` ON `users_collections` (`collection_uuid`);--> statement-breakpoint
CREATE TABLE `users_organizations` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text NOT NULL,
	`organization_uuid` text NOT NULL,
	`access_all` integer DEFAULT false NOT NULL,
	`akey` text NOT NULL,
	`status` integer NOT NULL,
	`atype` integer NOT NULL,
	`reset_password_key` text,
	`external_id` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_organizations_user_org_unique` ON `users_organizations` (`user_uuid`,`organization_uuid`);--> statement-breakpoint
CREATE INDEX `users_organizations_org_idx` ON `users_organizations` (`organization_uuid`);