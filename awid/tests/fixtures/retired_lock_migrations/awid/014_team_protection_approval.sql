-- Operator transitions retain the approval/cutover reference. Existing synthetic
-- or historical rows have no invented approval; .8 must inventory them.
ALTER TABLE {{tables.team_protection}}
    ADD COLUMN approval_ref TEXT NOT NULL DEFAULT '';
