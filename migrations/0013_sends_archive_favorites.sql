CREATE TABLE `cipher_user_state` (
	`user_uuid` text NOT NULL,
	`cipher_uuid` text NOT NULL,
	`favorite` integer DEFAULT false NOT NULL,
	`archived_at` integer,
	PRIMARY KEY(`user_uuid`, `cipher_uuid`),
	FOREIGN KEY (`user_uuid`) REFERENCES `users`(`uuid`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`cipher_uuid`) REFERENCES `ciphers`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `cipher_user_state_cipher_idx` ON `cipher_user_state` (`cipher_uuid`);--> statement-breakpoint
CREATE TABLE `send_email_codes` (
	`send_uuid` text NOT NULL,
	`email` text NOT NULL,
	`code_hash` text NOT NULL,
	`expires_at` integer NOT NULL,
	`sent_at` integer NOT NULL,
	`attempts` integer DEFAULT 0 NOT NULL,
	PRIMARY KEY(`send_uuid`, `email`),
	FOREIGN KEY (`send_uuid`) REFERENCES `sends`(`uuid`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
ALTER TABLE `ciphers` ADD `archived_at` integer;--> statement-breakpoint
ALTER TABLE `sends` ADD `emails` text;--> statement-breakpoint
INSERT OR IGNORE INTO `cipher_user_state` (`user_uuid`, `cipher_uuid`, `favorite`)
SELECT `uo`.`user_uuid`, `c`.`uuid`, 1 FROM `ciphers` `c`
JOIN `users_organizations` `uo` ON `uo`.`organization_uuid` = `c`.`organization_uuid`
WHERE `c`.`organization_uuid` IS NOT NULL AND `c`.`favorite` = 1 AND `uo`.`user_uuid` IS NOT NULL;--> statement-breakpoint
UPDATE `ciphers` SET `favorite` = 0 WHERE `organization_uuid` IS NOT NULL;
