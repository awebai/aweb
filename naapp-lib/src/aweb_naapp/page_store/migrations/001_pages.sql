-- Application-owned content. The deletion ledger is migrated in a different DB.
CREATE TABLE {{tables.pages}} (
    scope TEXT[] PRIMARY KEY,
    document JSONB NOT NULL,
    access JSONB NOT NULL,
    policy_version TEXT NOT NULL,
    deleted BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE {{tables.page_records}} (
    scope TEXT[] NOT NULL REFERENCES {{tables.pages}}(scope),
    collection TEXT NOT NULL,
    record_id TEXT NOT NULL,
    rev BIGINT NOT NULL CHECK (rev BETWEEN 1 AND 9007199254740991),
    record JSONB,
    PRIMARY KEY (scope, collection, record_id)
);
CREATE TABLE {{tables.page_layouts}} (
    scope TEXT[] NOT NULL REFERENCES {{tables.pages}}(scope),
    version BIGINT NOT NULL,
    layout JSONB NOT NULL,
    PRIMARY KEY(scope, version)
);
CREATE TABLE {{tables.page_schemas}} (
    scope TEXT[] NOT NULL REFERENCES {{tables.pages}}(scope),
    collection TEXT NOT NULL,
    version BIGINT NOT NULL,
    definition JSONB NOT NULL,
    PRIMARY KEY(scope, collection, version)
);
CREATE TABLE {{tables.page_audit}} (
    transaction_id UUID PRIMARY KEY,
    scope TEXT[] NOT NULL REFERENCES {{tables.pages}}(scope),
    old_rev BIGINT NOT NULL,
    new_rev BIGINT NOT NULL,
    evidence JSONB NOT NULL,
    changed JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE {{tables.page_receipts}} (
    transaction_id UUID PRIMARY KEY,
    scope TEXT[] NOT NULL REFERENCES {{tables.pages}}(scope),
    receipt JSONB NOT NULL
);
CREATE TABLE {{tables.page_cursors}} (
    token TEXT PRIMARY KEY,
    scope TEXT[] NOT NULL REFERENCES {{tables.pages}}(scope),
    principal TEXT NOT NULL,
    page_rev BIGINT NOT NULL,
    query_hash TEXT NOT NULL,
    row_offset BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
