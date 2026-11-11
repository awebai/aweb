-- One credential cap per policy key: an app role's (app_id, installation_id,
-- role), or a protected authority's (service_id, authority, human). Every
-- holding under the key counts its own active credentials against it. A key
-- with no row uses the deployment's configured cap. set_in is the top-level
-- transaction that wrote the row (txid_current(), unchanged by a savepoint),
-- and act_ref the SHA-256 of the signed act that set it.
CREATE TABLE {{tables.credential_caps}} (
    policy_key TEXT PRIMARY KEY,
    cap INTEGER NOT NULL CHECK (cap >= 1),
    policy_version BIGINT NOT NULL CHECK (policy_version >= 1),
    act_ref TEXT NOT NULL UNIQUE,
    set_in BIGINT NOT NULL DEFAULT txid_current(),
    set_at TIMESTAMPTZ NOT NULL
);
