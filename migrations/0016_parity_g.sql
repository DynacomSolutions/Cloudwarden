CREATE TABLE `notification_status` (
	`notification_uuid` text NOT NULL,
	`user_uuid` text NOT NULL,
	`read_at` integer,
	`deleted_at` integer,
	PRIMARY KEY(`notification_uuid`, `user_uuid`),
	FOREIGN KEY (`notification_uuid`) REFERENCES `notifications`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `notification_status_user_idx` ON `notification_status` (`user_uuid`);--> statement-breakpoint
CREATE TABLE `notifications` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text,
	`organization_uuid` text,
	`task_uuid` text,
	`priority` integer DEFAULT 0 NOT NULL,
	`title` text,
	`body` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`task_uuid`) REFERENCES `security_tasks`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `notifications_user_idx` ON `notifications` (`user_uuid`);--> statement-breakpoint
CREATE INDEX `notifications_organization_idx` ON `notifications` (`organization_uuid`);--> statement-breakpoint
CREATE TABLE `org_invite_links` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`code` text NOT NULL,
	`allowed_domains` text NOT NULL,
	`invite` text,
	`supports_confirmation` integer DEFAULT false NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `org_invite_links_organization_uuid_unique` ON `org_invite_links` (`organization_uuid`);--> statement-breakpoint
CREATE UNIQUE INDEX `org_invite_links_code_unique` ON `org_invite_links` (`code`);--> statement-breakpoint
CREATE TABLE `security_tasks` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`cipher_uuid` text,
	`type` integer DEFAULT 0 NOT NULL,
	`status` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `security_tasks_organization_idx` ON `security_tasks` (`organization_uuid`);--> statement-breakpoint
CREATE INDEX `security_tasks_cipher_idx` ON `security_tasks` (`cipher_uuid`);--> statement-breakpoint
ALTER TABLE `organizations` ADD `limit_collection_creation` integer DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE `organizations` ADD `limit_collection_deletion` integer DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE `organizations` ADD `limit_item_deletion` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `organizations` ADD `allow_admin_access_all_items` integer DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE `sm_secrets` ADD `deleted_at` integer;--> statement-breakpoint
ALTER TABLE `users` ADD `user_key_id` text;--> statement-breakpoint
ALTER TABLE `users` ADD `avatar_color` text;--> statement-breakpoint
ALTER TABLE `users_organizations` ADD `access_pam` integer DEFAULT false NOT NULL;