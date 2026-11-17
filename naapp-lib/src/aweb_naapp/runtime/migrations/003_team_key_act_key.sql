-- Bind a verified baseline to its actual key while retaining the high-water
-- act time across measuring moves. Existing unqualified pins are re-attested.
ALTER TABLE {{tables.team_key_pins}} ADD COLUMN IF NOT EXISTS team_key_act_key TEXT;
