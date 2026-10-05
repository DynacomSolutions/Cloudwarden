CREATE TABLE `admin_setup_uses` (
	`token_hash` text PRIMARY KEY NOT NULL,
	`user_uuid` text NOT NULL,
	`used_at` integer NOT NULL
);
--> statement-breakpoint
ALTER TABLE `invitations` ADD `token_hash` text;--> statement-breakpoint
ALTER TABLE `invitations` ADD `token_expires_at` integer;