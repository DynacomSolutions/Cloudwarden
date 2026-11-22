ALTER TABLE `users` ADD `account_keys_v2` text;--> statement-breakpoint
ALTER TABLE `users` ADD `v2_upgrade_token` text;--> statement-breakpoint
ALTER TABLE `users_organizations` ADD `v2_upgrade_token` text;