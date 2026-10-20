-- The authenticated issuing certificate's deadline bounds its delegation.
ALTER TABLE {{tables.identity_session_grants}}
    ADD COLUMN issued_by_certificate_expires_at TIMESTAMPTZ;
