-- Migration: Rename legacy host node names to sn1/sn2
BEGIN;

-- Update node status entries
UPDATE bot_node_status
SET node_name = 'sn1'
WHERE node_name = 'panel.visionhost.com';

UPDATE bot_node_status
SET node_name = 'sn2'
WHERE node_name = 'wispbyte.com';

-- Update failover lock owner names
UPDATE bot_failover_lock
SET owner_node_name = 'sn1'
WHERE owner_node_name = 'panel.visionhost.com';

UPDATE bot_failover_lock
SET owner_node_name = 'sn2'
WHERE owner_node_name = 'wispbyte.com';

COMMIT;
