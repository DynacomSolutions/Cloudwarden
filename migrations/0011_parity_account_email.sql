ALTER TABLE `emergency_access` ADD `recovery_notified_at` integer;--> statement-breakpoint
ALTER TABLE `users` ADD `verify_devices` integer DEFAULT true NOT NULL;--> statement-breakpoint
ALTER TABLE `users` ADD `otp_hash` text;--> statement-breakpoint
ALTER TABLE `users` ADD `otp_purpose` text;--> statement-breakpoint
ALTER TABLE `users` ADD `otp_expires_at` integer;--> statement-breakpoint
ALTER TABLE `users` ADD `otp_attempts` integer DEFAULT 0 NOT NULL;