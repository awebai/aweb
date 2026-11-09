-- Existing runtime labels are not ID-kind evidence. Revalidation through the
-- public verifier must precede release for existing active human members.
-- Raw labels remain display exclusions and owner-checked predecessor provenance.
ALTER TABLE {{tables.agents}} ADD COLUMN human_verified_key TEXT;
