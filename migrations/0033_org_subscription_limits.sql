CREATE TABLE `organization_subscriptions` (
	`organization_uuid` text PRIMARY KEY NOT NULL,
	`seats` integer,
	`max_autoscale_seats` integer,
	`storage_gb` integer,
	`sm_seats` integer,
	`sm_max_autoscale_seats` integer,
	`sm_service_accounts` integer,
	`sm_max_autoscale_service_accounts` integer,
	`updated_at` integer NOT NULL,
	FOREIGN KEY (`organization_uuid`) REFERENCES `organizations`(`uuid`) ON UPDATE no action ON DELETE cascade
);
