CREATE TABLE revision (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), value INTEGER NOT NULL);
INSERT INTO revision VALUES (1, 0);
CREATE TABLE enrollments (
    person TEXT PRIMARY KEY,
    identity_key TEXT NOT NULL,
    requester TEXT NOT NULL,
    intent TEXT NOT NULL,
    binding TEXT,
    confirmation TEXT,
    creation_receipt TEXT,
    evidence TEXT,
    chain TEXT,
    approval_receipt TEXT,
    active INTEGER NOT NULL DEFAULT 0 CHECK(active IN (0, 1))
);
CREATE TABLE consumed (
    nonce TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    requester TEXT NOT NULL,
    person TEXT NOT NULL REFERENCES enrollments(person)
);
PRAGMA user_version = 2;
