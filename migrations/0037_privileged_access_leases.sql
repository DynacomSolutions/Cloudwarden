CREATE TABLE `pam_access_decisions` (
	`uuid` text PRIMARY KEY NOT NULL,
	`request_uuid` text NOT NULL,
	`decider_kind` integer NOT NULL,
	`decider_user_uuid` text,
	`verdict` integer NOT NULL,
	`comment` text,
	`decided_at` integer NOT NULL,
	FOREIGN KEY (`request_uuid`) REFERENCES `pam_access_requests`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`decider_user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `pam_access_decisions_request_unique` ON `pam_access_decisions` (`request_uuid`);--> statement-breakpoint
CREATE TABLE `pam_access_requests` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`cipher_uuid` text NOT NULL,
	`collection_uuid` text NOT NULL,
	`rule_uuid` text NOT NULL,
	`requester_uuid` text NOT NULL,
	`status` integer DEFAULT 0 NOT NULL,
	`reason` text,
	`window_start` integer,
	`window_end` integer,
	`duration_seconds` integer NOT NULL,
	`submitted_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`resolved_at` integer,
	`extension_of_lease_uuid` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`requester_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `pam_access_requests_org_idx` ON `pam_access_requests` (`organization_uuid`,`status`);--> statement-breakpoint
CREATE INDEX `pam_access_requests_requester_idx` ON `pam_access_requests` (`requester_uuid`);--> statement-breakpoint
CREATE UNIQUE INDEX `pam_access_requests_pending_unique` ON `pam_access_requests` (`requester_uuid`,`cipher_uuid`) WHERE "pam_access_requests"."status" = 0 and "pam_access_requests"."extension_of_lease_uuid" is null;--> statement-breakpoint
CREATE UNIQUE INDEX `pam_access_requests_pending_extension_unique` ON `pam_access_requests` (`extension_of_lease_uuid`) WHERE "pam_access_requests"."status" = 0 and "pam_access_requests"."extension_of_lease_uuid" is not null;--> statement-breakpoint
CREATE TABLE `pam_access_rules` (
	`uuid` text PRIMARY KEY NOT NULL,
	`organization_uuid` text NOT NULL,
	`name` text NOT NULL,
	`description` text,
	`enabled` integer DEFAULT true NOT NULL,
	`conditions` text,
	`single_active_lease` integer DEFAULT false NOT NULL,
	`default_lease_seconds` integer NOT NULL,
	`max_lease_seconds` integer NOT NULL,
	`allows_extensions` integer DEFAULT false NOT NULL,
	`max_extension_seconds` integer,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `pam_access_rules_org_idx` ON `pam_access_rules` (`organization_uuid`);--> statement-breakpoint
CREATE TABLE `pam_leases` (
	`uuid` text PRIMARY KEY NOT NULL,
	`request_uuid` text NOT NULL,
	`organization_uuid` text NOT NULL,
	`cipher_uuid` text NOT NULL,
	`collection_uuid` text NOT NULL,
	`requester_uuid` text NOT NULL,
	`status` integer DEFAULT 0 NOT NULL,
	`not_before` integer NOT NULL,
	`not_after` integer NOT NULL,
	`revoked_at` integer,
	`revoked_by_user_uuid` text,
	`revocation_reason` text,
	`last_extension_request_uuid` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`request_uuid`) REFERENCES `pam_access_requests`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`requester_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `pam_leases_request_unique` ON `pam_leases` (`request_uuid`);--> statement-breakpoint
CREATE INDEX `pam_leases_cipher_idx` ON `pam_leases` (`cipher_uuid`,`status`);--> statement-breakpoint
CREATE INDEX `pam_leases_requester_idx` ON `pam_leases` (`requester_uuid`);--> statement-breakpoint
CREATE INDEX `pam_leases_org_idx` ON `pam_leases` (`organization_uuid`,`status`);--> statement-breakpoint
CREATE TABLE `pam_rule_collections` (
	`rule_uuid` text NOT NULL,
	`collection_uuid` text NOT NULL,
	PRIMARY KEY(`rule_uuid`, `collection_uuid`),
	FOREIGN KEY (`rule_uuid`) REFERENCES `pam_access_rules`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`collection_uuid`) REFERENCES `collections`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `pam_rule_collections_collection_unique` ON `pam_rule_collections` (`collection_uuid`);