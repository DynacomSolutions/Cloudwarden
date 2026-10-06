-- Incoming pending requests recorded before the `incoming` flag existed count against the incoming
-- cap and expire like the others. Best effort: such a request has no local approval, carries the
-- remote one that came with it, and has neither a user who requested it nor an approving admin.
UPDATE `federation_peers` SET `incoming` = 1 WHERE `status` = 'pending' AND `local_approved` = 0 AND `remote_approved` = 1 AND `requested_by` IS NULL AND `approved_by` IS NULL;
