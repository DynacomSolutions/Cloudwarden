ALTER TABLE `attachments` ADD `uploaded_at` integer;--> statement-breakpoint
ALTER TABLE `attachments` ADD `upload_started_at` integer;--> statement-breakpoint
ALTER TABLE `sends` ADD `uploaded_at` integer;--> statement-breakpoint
ALTER TABLE `sends` ADD `upload_started_at` integer;