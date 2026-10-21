-- Never restore this database from a content backup. It is the erasure fence.
CREATE TABLE {{tables.page_deletions}} (
    scope TEXT[] PRIMARY KEY,
    job_id UUID NOT NULL UNIQUE,
    tombstone_rev BIGINT NOT NULL,
    requester TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('requested','access_revoked','purging','complete')),
    receipt JSONB NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
