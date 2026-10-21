-- A pending contact takes effect only once its holder has proven it, through a
-- single-use proof sent to that contact and bound to its digest. A contact
-- given at designation is proven by the enrolment completed through it.
ALTER TABLE {{tables.passkey_approvers}}
    ADD COLUMN pending_contact_proven_at TIMESTAMPTZ,
    ADD CHECK (pending_contact_proven_at IS NULL OR pending_contact IS NOT NULL);

CREATE TABLE IF NOT EXISTS {{tables.passkey_contact_proofs}} (
    proof_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL REFERENCES {{tables.passkey_approvers}}(subject),
    contact_sha256 TEXT NOT NULL,
    verifier_sha256 TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    used_at TIMESTAMPTZ
);
