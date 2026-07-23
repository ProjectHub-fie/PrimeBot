-- Migration 0007: Seed sn3 row and enforce role names (sn1/sn2/sn3 only)
--
-- 1. Seed all three role rows so they always appear in status queries,
--    even before a node has ever started (inactive / never-heartbeated).
-- 2. Add CHECK constraints so the role columns only accept the canonical
--    role strings sn1, sn2, sn3 — not legacy aliases (primary, secondary,
--    tertiary, secoundary, etc.).  The application already normalizes via
--    normalizeNodeRole() before writing, so no existing rows will be rejected.

-- Ensure bot_node_status has rows for all three roles (inactive by default).
INSERT INTO bot_node_status (role, node_name, last_heartbeat, active)
VALUES
    ('sn1', 'panel.visionhost.com', NOW(), false),
    ('sn2', 'wispbyte.com',         NOW(), false),
    ('sn3', 'sn3-node',             NOW(), false)
ON CONFLICT (role) DO NOTHING;

-- Add CHECK constraint on bot_node_status.role (idempotent via DO block).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'bot_node_status'
          AND constraint_name = 'bot_node_status_role_check'
    ) THEN
        ALTER TABLE bot_node_status
            ADD CONSTRAINT bot_node_status_role_check
            CHECK (role IN ('sn1', 'sn2', 'sn3'));
    END IF;
END;
$$;

-- Add CHECK constraint on bot_failover_lock.owner_role (idempotent via DO block).
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.table_constraints
        WHERE table_name = 'bot_failover_lock'
          AND constraint_name = 'bot_failover_lock_owner_role_check'
    ) THEN
        ALTER TABLE bot_failover_lock
            ADD CONSTRAINT bot_failover_lock_owner_role_check
            CHECK (owner_role IN ('sn1', 'sn2', 'sn3'));
    END IF;
END;
$$;
