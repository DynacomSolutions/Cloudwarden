CREATE TABLE `instance_settings` (
	`key` text PRIMARY KEY NOT NULL,
	`config` text NOT NULL,
	`sealed_secrets` text,
	`updated_at` integer NOT NULL,
	`updated_by` text
);
