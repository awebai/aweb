CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    sha TEXT NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    reserved INTEGER NOT NULL,
    actual INTEGER,
    settled REAL,
    payload TEXT NOT NULL DEFAULT '{}'
);
