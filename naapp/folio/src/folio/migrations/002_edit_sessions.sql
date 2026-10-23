ALTER TABLE {{tables.presentation_links}}
    ADD COLUMN consumed_at TIMESTAMPTZ,
    ADD COLUMN opener_sha256 BYTEA,
    ADD COLUMN creator_team_did_key TEXT;

CREATE UNIQUE INDEX idx_folio_edit_opener ON {{tables.presentation_links}} (opener_sha256)
    WHERE opener_sha256 IS NOT NULL;

CREATE TABLE {{tables.edit_sessions}} (
    credential_hash BYTEA PRIMARY KEY CHECK (octet_length(credential_hash) = 32),
    link_id TEXT NOT NULL REFERENCES {{tables.presentation_links}}(token) ON DELETE CASCADE,
    document_id UUID NOT NULL REFERENCES {{tables.documents}}(document_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_folio_edit_sessions_link ON {{tables.edit_sessions}} (link_id);
