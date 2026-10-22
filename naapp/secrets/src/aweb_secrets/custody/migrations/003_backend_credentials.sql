-- A private service-account binding, outside ordinary secret/grant records.
-- Staging only allocates native sealed versions; passkey confirmation alone
-- may set active_version in the complete dependency-invalidation transaction.
-- The reserved custody allocator survives ciphertext destruction and token
-- replacement. No provider token, plaintext fingerprint or item value is here.
CREATE TABLE IF NOT EXISTS {{tables.onepassword_credentials}} (
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    credential_id TEXT NOT NULL CHECK (credential_id = 'bkc_onepassword'),
    active_version INTEGER CHECK (active_version > 0),
    PRIMARY KEY (installation_id, team_id)
);
