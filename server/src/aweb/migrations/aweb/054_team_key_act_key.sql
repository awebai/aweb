-- A measuring move keeps the previous act floor, not proof of the new key.
-- Existing pins need explicit re-attestation; never guess which key their old
-- timestamp proved. New admissions store their checked creation/current act.
ALTER TABLE {{tables.teams}} ADD COLUMN IF NOT EXISTS team_key_act_key TEXT;
