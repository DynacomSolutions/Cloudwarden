-- The devices table is empty before this release, so it is recreated to add a NOT NULL column.
DROP TABLE `devices`;--> statement-breakpoint
CREATE TABLE `devices` (
	`uuid` text PRIMARY KEY NOT NULL,
	`identifier` text NOT NULL,
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
CREATE UNIQUE INDEX `devices_user_identifier_unique` ON `devices` (`user_uuid`,`identifier`);--> statement-breakpoint
ALTER TABLE `users` ADD `api_key` text;--> statement-breakpoint
ALTER TABLE `users` ADD `email_new` text;--> statement-breakpoint
ALTER TABLE `users` ADD `email_new_token` text;--> statement-breakpoint
ALTER TABLE `users` ADD `email_new_expires_at` integer;