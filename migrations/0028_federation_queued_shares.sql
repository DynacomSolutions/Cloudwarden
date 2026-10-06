CREATE TABLE `federation_queued_shares` (
	`uuid` text PRIMARY KEY NOT NULL,
	`peer_uuid` text NOT NULL,
	`peer_domain` text NOT NULL,
	`organization_uuid` text NOT NULL,
	`collection_uuid` text NOT NULL,
	`email` text NOT NULL,
	`read_only` integer DEFAULT false NOT NULL,
	`hide_passwords` integer DEFAULT false NOT NULL,
	`manage` integer DEFAULT false NOT NULL,
	`requested_by` text NOT NULL,
	`status` text NOT NULL,
	`note` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`collection_uuid`) REFERENCES `collections`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`requested_by`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `federation_queued_shares_peer_idx` ON `federation_queued_shares` (`peer_uuid`);--> statement-breakpoint
CREATE INDEX `federation_queued_shares_collection_idx` ON `federation_queued_shares` (`collection_uuid`);--> statement-breakpoint
CREATE UNIQUE INDEX `federation_queued_shares_unique` ON `federation_queued_shares` (`peer_uuid`,`collection_uuid`,`email`);