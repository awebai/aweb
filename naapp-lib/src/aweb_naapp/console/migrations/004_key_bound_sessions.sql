-- Certificate transport bytes are evidence only. Session/holding/B3 authority
-- is checked independently; nothing here extends their original deadlines.
ALTER TABLE {{tables.console_sessions}}
    ADD COLUMN client_key TEXT,
    ADD COLUMN public_scope JSONB,
    ADD COLUMN holding_identity TEXT,
    ADD COLUMN member_certificate TEXT;
ALTER TABLE {{tables.console_handoffs}}
    ADD COLUMN team_id TEXT,
    ADD COLUMN b3_scope TEXT,
    ADD COLUMN subject TEXT,
    ADD COLUMN holding_identity TEXT,
    ADD COLUMN member_certificate TEXT,
    ADD COLUMN login_evidence_ref TEXT;
CREATE TABLE {{tables.console_session_nonces}} (
    token_sha256 BYTEA NOT NULL REFERENCES {{tables.console_sessions}} ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    PRIMARY KEY(token_sha256, nonce)
);
CREATE TABLE {{tables.console_holding_certificates}} (
    installation_id TEXT NOT NULL,
    role TEXT NOT NULL,
    principal TEXT NOT NULL,
    holding_identity TEXT NOT NULL,
    b3_scope TEXT NOT NULL,
    subject TEXT NOT NULL,
    member_certificate TEXT NOT NULL,
    PRIMARY KEY(installation_id, role, principal)
);
