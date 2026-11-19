-- A human-role holder's authorization (human-role-holders.md, What the credential
-- audit retains). It names the principal and the credential its owner act binds,
-- and the notice contact when its role declares one. It has no enrolment or
-- approval contact. credential_ref is the opaque reference its key's receipts
-- carry, never derived from the key. A row is exactly one model.
ALTER TABLE {{tables.credential_authorizations}}
    ALTER COLUMN contact_sha256 DROP NOT NULL,
    ADD COLUMN principal TEXT,
    ADD COLUMN credential_sha256 TEXT,
    ADD COLUMN notice_contact_sha256 TEXT,
    ADD COLUMN credential_ref TEXT UNIQUE,
    ADD CONSTRAINT credential_authorization_model CHECK (
        (
            contact_sha256 IS NOT NULL
            AND principal IS NULL
            AND credential_sha256 IS NULL
            AND notice_contact_sha256 IS NULL
            AND credential_ref IS NULL
        ) OR (
            contact_sha256 IS NULL
            AND principal IS NOT NULL
            AND credential_sha256 IS NOT NULL
            AND credential_ref IS NOT NULL
        )
    );
