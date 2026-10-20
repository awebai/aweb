-- Signed certificate deadlines are also registry membership boundaries.
ALTER TABLE {{tables.team_certificates}} ADD COLUMN expires_at TIMESTAMPTZ;
