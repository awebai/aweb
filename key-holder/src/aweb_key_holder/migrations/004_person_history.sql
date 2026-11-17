ALTER TABLE enrollments ADD COLUMN retired_at INTEGER;
CREATE TABLE person_revisions (person TEXT PRIMARY KEY, value INTEGER NOT NULL CHECK(value >= 0));
-- Preserve outstanding fences when upgrading from the singleton revision.
INSERT INTO person_revisions SELECT person, (SELECT value FROM revision) FROM enrollments;
DROP TABLE revision;
PRAGMA user_version = 4;
