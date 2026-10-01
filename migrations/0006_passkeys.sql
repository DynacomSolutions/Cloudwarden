CREATE TABLE `webauthn_credentials` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text NOT NULL,
	`name` text NOT NULL,
	`credential_id` text NOT NULL,
	`alg` integer NOT NULL,
	`jwk` text NOT NULL,
	`sign_count` integer DEFAULT 0 NOT NULL,
	`transports` text DEFAULT '[]' NOT NULL,
	`supports_prf` integer DEFAULT false NOT NULL,
	`encrypted_user_key` text,
	`encrypted_public_key` text,
	`encrypted_private_key` text,
	`last_challenge_at` integer DEFAULT 0 NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `webauthn_credentials_credential_id_unique` ON `webauthn_credentials` (`credential_id`);--> statement-breakpoint
CREATE INDEX `webauthn_credentials_user_idx` ON `webauthn_credentials` (`user_uuid`);