CREATE TABLE `auth_requests` (
	`uuid` text PRIMARY KEY NOT NULL,
	`user_uuid` text,
	`type` integer NOT NULL,
	`request_device_identifier` text NOT NULL,
	`request_device_type` integer NOT NULL,
	`request_ip` text,
	`public_key` text NOT NULL,
	`access_code_hash` text NOT NULL,
	`approved` integer,
	`key` text,
	`master_password_hash` text,
	`response_device_uuid` text,
	`response_date` integer,
	`authenticated_at` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `auth_requests_user_idx` ON `auth_requests` (`user_uuid`);