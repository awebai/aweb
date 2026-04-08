-- 003_team_visibility.sql
-- Add visibility metadata to teams so public/private is part of team identity.

ALTER TABLE {{tables.teams}}
    ADD COLUMN IF NOT EXISTS visibility TEXT NOT NULL DEFAULT 'private'
    CHECK (visibility IN ('public', 'private'));
