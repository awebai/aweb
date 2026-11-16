CREATE TABLE configuration (
    organisation TEXT NOT NULL,
    nonce_secret BLOB NOT NULL CHECK(length(nonce_secret) = 32)
);
CREATE TABLE keys (
    reference TEXT PRIMARY KEY,
    scope TEXT NOT NULL CHECK(scope IN ('namespace', 'team')),
    team TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 0),
    did_key TEXT NOT NULL,
    seed BLOB NOT NULL CHECK(length(seed) = 32),
    UNIQUE(scope, team, generation)
);
CREATE TABLE signatures (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    operation TEXT NOT NULL,
    actor TEXT NOT NULL,
    approval TEXT,
    key TEXT NOT NULL,
    generation INTEGER NOT NULL,
    payload TEXT NOT NULL,
    signature TEXT NOT NULL,
    at INTEGER NOT NULL
);
CREATE TRIGGER signatures_no_delete BEFORE DELETE ON signatures
BEGIN SELECT RAISE(ABORT, 'append_only'); END;
CREATE TRIGGER signatures_no_update BEFORE UPDATE ON signatures
BEGIN SELECT RAISE(ABORT, 'append_only'); END;
PRAGMA user_version = 1;
