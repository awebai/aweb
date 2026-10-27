-- 010_id_certificates.sql
-- The identity tree (docs/id-certificates.md): registered identities with
-- their revocation, every registered ID-certificate revision with its
-- witnessed issuer key, and the namespace controller epochs that witness
-- which root key was in force when. Rows are never deleted: a superseded
-- head, a retired epoch and a revocation remain the evidence of past state.

-- One row per registered ID. kind and domain are fixed at first enrollment
-- (R2). The row is also the lock that serializes registration, re-parenting
-- and revocation of this ID.
CREATE TABLE IF NOT EXISTS {{tables.id_identities}} (
    id                  TEXT PRIMARY KEY,
    domain              TEXT NOT NULL,
    kind                TEXT NOT NULL CHECK (kind IN ('human', 'agent')),
    first_registered_at TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    effective_from      TIMESTAMPTZ,
    revoked_by          TEXT,
    -- The composite key lets every revision carry its identity's fixed
    -- domain and kind (R2) as a foreign key rather than by convention.
    CONSTRAINT uq_id_identities_id_domain_kind UNIQUE (id, domain, kind),
    CONSTRAINT chk_id_identities_revocation CHECK (
        (revoked_at IS NULL AND effective_from IS NULL AND revoked_by IS NULL)
        OR (revoked_at IS NOT NULL AND effective_from IS NOT NULL
            AND revoked_by IS NOT NULL AND effective_from <= revoked_at)
    )
);

-- Every registered revision, identified by its digest. signed_json is the
-- exact signed wrapper as registered; supporting_chain_json is the public
-- chain presented with it. issuer_key_seq names the witnessed parent key
-- version: a namespace epoch seq, or the parent did:aw log seq.
CREATE TABLE IF NOT EXISTS {{tables.id_certificates}} (
    certificate_id        TEXT PRIMARY KEY,
    id                    TEXT NOT NULL,
    domain                TEXT NOT NULL,
    parent_kind           TEXT NOT NULL CHECK (parent_kind IN ('namespace', 'identity')),
    parent_id             TEXT NOT NULL,
    kind                  TEXT NOT NULL CHECK (kind IN ('human', 'agent')),
    issuer_key            TEXT NOT NULL,
    signed_json           TEXT NOT NULL,
    supporting_chain_json TEXT NOT NULL,
    issuer_key_seq        INTEGER NOT NULL CHECK (issuer_key_seq > 0),
    invitation_id         UUID,
    registered_at         TIMESTAMPTZ NOT NULL,
    superseded_at         TIMESTAMPTZ,
    CONSTRAINT fk_id_certificates_identity FOREIGN KEY (id, domain, kind)
        REFERENCES {{tables.id_identities}}(id, domain, kind),
    CONSTRAINT chk_id_certificates_supersession CHECK (
        superseded_at IS NULL OR superseded_at > registered_at
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_id_certificates_current_head
    ON {{tables.id_certificates}} (id)
    WHERE superseded_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_id_certificates_invitation
    ON {{tables.id_certificates}} (invitation_id)
    WHERE invitation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_id_certificates_history
    ON {{tables.id_certificates}} (id, registered_at);

CREATE INDEX IF NOT EXISTS idx_id_certificates_parent
    ON {{tables.id_certificates}} (parent_id)
    WHERE superseded_at IS NULL;

-- Namespace controller epochs per domain, recorded on every controller
-- change instead of overwriting the only evidence of an old root key.
-- established_by records how AWID verified the controller; only an exact
-- _awid.<domain> TXT epoch is identity-tree evidence for that domain.
CREATE TABLE IF NOT EXISTS {{tables.id_namespace_epochs}} (
    domain         TEXT NOT NULL,
    seq            INTEGER NOT NULL CHECK (seq > 0),
    did_key        TEXT NOT NULL,
    established_by TEXT NOT NULL CHECK (
        established_by IN ('dns_exact', 'dns_inherited', 'parent_authorization', 'unverified')
    ),
    registered_at  TIMESTAMPTZ NOT NULL,
    retired_at     TIMESTAMPTZ,
    PRIMARY KEY (domain, seq),
    CONSTRAINT chk_id_namespace_epochs_retirement CHECK (
        retired_at IS NULL OR retired_at > registered_at
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_id_namespace_epochs_open
    ON {{tables.id_namespace_epochs}} (domain)
    WHERE retired_at IS NULL;
