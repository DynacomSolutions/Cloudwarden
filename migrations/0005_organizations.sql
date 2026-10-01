CREATE TABLE `collections_groups` (
	`collection_uuid` text NOT NULL,
	`group_uuid` text NOT NULL,
	`read_only` integer DEFAULT false NOT NULL,
	`hide_passwords` integer DEFAULT false NOT NULL,
	`manage` integer DEFAULT false NOT NULL,
	PRIMARY KEY(`collection_uuid`, `group_uuid`),
	FOREIGN KEY (`collection_uuid`) REFERENCES `collections`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`group_uuid`) REFERENCES `groups`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `collections_groups_group_idx` ON `collections_groups` (`group_uuid`);--> statement-breakpoint
CREATE TABLE `emergency_access` (
	`uuid` text PRIMARY KEY NOT NULL,
	`grantor_uuid` text NOT NULL,
	`grantee_uuid` text,
	`email` text NOT NULL,
	`key_encrypted` text,
	`atype` integer NOT NULL,
	`status` integer NOT NULL,
	`wait_time_days` integer NOT NULL,
	`recovery_initiated_at` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`grantor_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`grantee_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `emergency_access_grantor_idx` ON `emergency_access` (`grantor_uuid`);--> statement-breakpoint
CREATE INDEX `emergency_access_grantee_idx` ON `emergency_access` (`grantee_uuid`);--> statement-breakpoint
CREATE TABLE `groups` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`name` text NOT NULL,
	`access_all` integer DEFAULT false NOT NULL,
	`external_id` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `groups_organization_idx` ON `groups` (`organization_uuid`);--> statement-breakpoint
CREATE TABLE `groups_users` (
	`group_uuid` text NOT NULL,
	`organization_user_uuid` text NOT NULL,
	PRIMARY KEY(`group_uuid`, `organization_user_uuid`),
	FOREIGN KEY (`group_uuid`) REFERENCES `groups`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_user_uuid`) REFERENCES `users_organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `groups_users_member_idx` ON `groups_users` (`organization_user_uuid`);--> statement-breakpoint
CREATE TABLE `policies` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`atype` integer NOT NULL,
	`enabled` integer DEFAULT false NOT NULL,
	`data` text,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `policies_org_type_unique` ON `policies` (`organization_uuid`,`atype`);--> statement-breakpoint
-- users_organizations is rebuilt before users_collections: dropping a parent table cascades to
-- child rows on D1, so the grants are copied only after the new member table is in place.
CREATE TABLE `__new_users_organizations` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text,
	`organization_uuid` text NOT NULL,
	`email` text,
	`permissions` text,
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
INSERT INTO `__new_users_organizations`("uuid", "user_uuid", "organization_uuid", "email", "permissions", "access_all", "akey", "status", "atype", "reset_password_key", "external_id", "created_at", "updated_at") SELECT "uuid", "user_uuid", "organization_uuid", (SELECT `email` FROM `users` WHERE `users`.`uuid` = `users_organizations`.`user_uuid`), NULL, "access_all", "akey", "status", "atype", "reset_password_key", "external_id", "created_at", "updated_at" FROM `users_organizations`;--> statement-breakpoint
DROP TABLE `users_organizations`;--> statement-breakpoint
ALTER TABLE `__new_users_organizations` RENAME TO `users_organizations`;--> statement-breakpoint
CREATE UNIQUE INDEX `users_organizations_user_org_unique` ON `users_organizations` (`user_uuid`,`organization_uuid`);--> statement-breakpoint
CREATE INDEX `users_organizations_org_idx` ON `users_organizations` (`organization_uuid`);--> statement-breakpoint
CREATE INDEX `users_organizations_email_idx` ON `users_organizations` (`email`);--> statement-breakpoint
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_users_collections` (
	`organization_user_uuid` text NOT NULL,
	`collection_uuid` text NOT NULL,
	`read_only` integer DEFAULT false NOT NULL,
	`hide_passwords` integer DEFAULT false NOT NULL,
	`manage` integer DEFAULT false NOT NULL,
	PRIMARY KEY(`organization_user_uuid`, `collection_uuid`),
	FOREIGN KEY (`organization_user_uuid`) REFERENCES `users_organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`collection_uuid`) REFERENCES `collections`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
INSERT INTO `__new_users_collections`("organization_user_uuid", "collection_uuid", "read_only", "hide_passwords", "manage") SELECT uo.`uuid`, uc.`collection_uuid`, uc.`read_only`, uc.`hide_passwords`, uc.`manage` FROM `users_collections` uc INNER JOIN `collections` c ON c.`uuid` = uc.`collection_uuid` INNER JOIN `users_organizations` uo ON uo.`user_uuid` = uc.`user_uuid` AND uo.`organization_uuid` = c.`organization_uuid`;--> statement-breakpoint
DROP TABLE `users_collections`;--> statement-breakpoint
ALTER TABLE `__new_users_collections` RENAME TO `users_collections`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `users_collections_collection_idx` ON `users_collections` (`collection_uuid`);--> statement-breakpoint
ALTER TABLE `events` ADD `group_uuid` text;--> statement-breakpoint
ALTER TABLE `events` ADD `policy_uuid` text;--> statement-breakpoint
ALTER TABLE `events` ADD `organization_user_uuid` text;