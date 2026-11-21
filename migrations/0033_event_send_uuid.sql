ALTER TABLE `events` ADD `send_uuid` text;--> statement-breakpoint
CREATE INDEX `events_send_idx` ON `events` (`send_uuid`);