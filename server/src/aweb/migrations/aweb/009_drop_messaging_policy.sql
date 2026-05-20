-- 009_drop_messaging_policy.sql
-- inbound_mode is the canonical delivery-auth surface. Drop the legacy
-- messaging_policy column after 008 mapped safe historical values.

ALTER TABLE {{tables.agents}}
    DROP COLUMN IF EXISTS messaging_policy;
