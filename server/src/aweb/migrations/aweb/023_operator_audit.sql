-- Add structured verified-actor metadata to the existing audit stream. Older
-- event writers and rows retain their nullable columns and original semantics.
ALTER TABLE {{tables.audit_log}}
    ADD COLUMN actor_did_key TEXT,
    ADD COLUMN actor_did_aw TEXT,
    ADD COLUMN actor_user_id TEXT,
    ADD COLUMN principal_type TEXT CHECK (principal_type IN ('u','k','c','m','p')),
    ADD COLUMN auth_mode TEXT CHECK (auth_mode IN ('team_auth_v1','team_auth_v2','session','api_key','identity_grant','internal')),
    ADD COLUMN outcome TEXT CHECK (outcome IN ('success','denied')),
    ADD COLUMN request_id UUID,
    ADD COLUMN actor_grant_id UUID;
