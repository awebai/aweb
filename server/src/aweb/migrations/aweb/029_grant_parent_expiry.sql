-- The authenticated issuing certificate's deadline bounds its delegation.
ALTER TABLE {{tables.identity_session_grants}}
    ADD COLUMN issued_by_certificate_expires_at TIMESTAMPTZ,
    ADD COLUMN issued_by_certificate_version SMALLINT NOT NULL DEFAULT 1
        CHECK (issued_by_certificate_version IN (1, 2));
