CREATE TABLE `federation_identity` (
	`id` text PRIMARY KEY NOT NULL,
	`instance_id` text NOT NULL,
	`public_key` text NOT NULL,
	`private_key_enc` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `federation_invitations` (
	`uuid` text PRIMARY KEY NOT NULL,
	`peer_uuid` text NOT NULL,
	`remote_member_uuid` text NOT NULL,
	`organization_uuid` text NOT NULL,
	`organization_name` text NOT NULL,
	`inviter_email` text,
	`user_uuid` text NOT NULL,
	`status` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`peer_uuid`) REFERENCES `federation_peers`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `federation_invitations_remote_unique` ON `federation_invitations` (`peer_uuid`,`remote_member_uuid`);--> statement-breakpoint
CREATE INDEX `federation_invitations_user_idx` ON `federation_invitations` (`user_uuid`);--> statement-breakpoint
CREATE TABLE `federation_item_folders` (
	`user_uuid` text NOT NULL,
	`cipher_uuid` text NOT NULL,
	`folder_uuid` text NOT NULL,
	PRIMARY KEY(`user_uuid`, `cipher_uuid`),
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`folder_uuid`) REFERENCES `folders`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `federation_members` (
	`organization_user_uuid` text PRIMARY KEY NOT NULL,
	`peer_uuid` text NOT NULL,
	`remote_email` text NOT NULL,
	`remote_user_uuid` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`organization_user_uuid`) REFERENCES `users_organizations`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`peer_uuid`) REFERENCES `federation_peers`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `federation_members_peer_idx` ON `federation_members` (`peer_uuid`);--> statement-breakpoint
CREATE TABLE `federation_nonces` (
	`peer_uuid` text NOT NULL,
	`nonce` text NOT NULL,
	`expires_at` integer NOT NULL,
	PRIMARY KEY(`peer_uuid`, `nonce`),
	FOREIGN KEY (`peer_uuid`) REFERENCES `federation_peers`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `federation_nonces_expires_idx` ON `federation_nonces` (`expires_at`);--> statement-breakpoint
CREATE TABLE `federation_peers` (
	`uuid` text PRIMARY KEY NOT NULL,
	`instance_id` text NOT NULL,
	`domain` text NOT NULL,
	`public_key` text NOT NULL,
	`fingerprint` text NOT NULL,
	`protocol_version` integer NOT NULL,
	`status` text NOT NULL,
	`local_approved` integer DEFAULT false NOT NULL,
	`remote_approved` integer DEFAULT false NOT NULL,
	`last_seen_at` integer,
	`last_error` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `federation_peers_instance_unique` ON `federation_peers` (`instance_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `federation_peers_domain_unique` ON `federation_peers` (`domain`);--> statement-breakpoint
CREATE TABLE `federation_replica_ciphers` (
	`user_uuid` text NOT NULL,
	`cipher_uuid` text NOT NULL,
	`organization_uuid` text NOT NULL,
	`json` text NOT NULL,
	`digest` text NOT NULL,
	`updated_at` integer NOT NULL,
	PRIMARY KEY(`user_uuid`, `cipher_uuid`),
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `federation_replica_ciphers_org_idx` ON `federation_replica_ciphers` (`user_uuid`,`organization_uuid`);--> statement-breakpoint
CREATE TABLE `federation_replica_orgs` (
	`user_uuid` text NOT NULL,
	`organization_uuid` text NOT NULL,
	`peer_uuid` text NOT NULL,
	`profile_json` text NOT NULL,
	`collections_json` text NOT NULL,
	`policies_json` text NOT NULL,
	`revision_date` integer NOT NULL,
	`synced_at` integer NOT NULL,
	PRIMARY KEY(`user_uuid`, `organization_uuid`),
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`peer_uuid`) REFERENCES `federation_peers`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `federation_replica_orgs_peer_idx` ON `federation_replica_orgs` (`peer_uuid`);--> statement-breakpoint
CREATE TABLE `federation_shadow_users` (
	`user_uuid` text PRIMARY KEY NOT NULL,
	`peer_uuid` text NOT NULL,
	`remote_email` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`peer_uuid`) REFERENCES `federation_peers`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `federation_shadow_users_peer_idx` ON `federation_shadow_users` (`peer_uuid`);