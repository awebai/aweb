-- Team-vouched return routes are new; existing participants retain NULL proofs.
-- No backfill: previous versions could not admit local first contact remotely.
ALTER TABLE {{tables.conversation_participants}}
    ADD COLUMN route_team_id TEXT,
    ADD COLUMN route_certificate_id TEXT,
    ADD COLUMN route_certificate TEXT;
ALTER TABLE {{tables.chat_participants}}
    ADD COLUMN route_team_id TEXT,
    ADD COLUMN route_certificate_id TEXT,
    ADD COLUMN route_certificate TEXT;
