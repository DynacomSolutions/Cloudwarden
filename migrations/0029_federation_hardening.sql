CREATE TABLE `federation_removed_domains` (
	`domain` text PRIMARY KEY NOT NULL,
	`removed_at` integer NOT NULL
);
--> statement-breakpoint
ALTER TABLE `federation_blocked_domains` ADD `kind` text DEFAULT 'domain' NOT NULL;--> statement-breakpoint
ALTER TABLE `federation_peers` ADD `incoming` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `federation_queued_shares` ADD `attempts` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
UPDATE `federation_peers` SET `incoming` = 1 WHERE `accepted_automatically` = 1;
