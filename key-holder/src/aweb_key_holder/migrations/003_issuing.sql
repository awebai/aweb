ALTER TABLE configuration ADD COLUMN human_issuance TEXT NOT NULL DEFAULT 'operator' CHECK(human_issuance IN ('operator','approved'));
PRAGMA user_version = 3;
