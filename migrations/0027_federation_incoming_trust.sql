CREATE TABLE `federation_blocked_domains` (
	`domain` text PRIMARY KEY NOT NULL,
	`created_at` integer NOT NULL,
	`created_by` text
);
--> statement-breakpoint
ALTER TABLE `federation_peers` ADD `accepted_automatically` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `federation_peers` ADD `approved_by` text;