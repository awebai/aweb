-- A pinned link keeps its already authorized/redacted projection, not a view
-- reconstructed from current records. The serving code inserts it once with
-- the link, never updates it, and rechecks current authority at every read.
-- Page/installation content purge deletes the link and cascades this content.
CREATE TABLE IF NOT EXISTS {{tables.capability_link_snapshots}} (
    link_id        TEXT PRIMARY KEY REFERENCES {{tables.capability_links}} (link_id) ON DELETE CASCADE,
    page_rev       BIGINT NOT NULL CHECK (page_rev >= 0),
    snapshot       JSONB NOT NULL,
    snapshot_sha256 BYTEA NOT NULL CHECK (octet_length(snapshot_sha256) = 32)
);

-- These references hold immutable asset versions against ordinary GC while
-- the link is live. Explicit owner deletion wins. Revoke/expiry release them;
-- page/link purge cascades them, and there are no asset URLs or grants here.
CREATE TABLE IF NOT EXISTS {{tables.capability_link_asset_refs}} (
    link_id         TEXT NOT NULL REFERENCES {{tables.capability_links}} (link_id) ON DELETE CASCADE,
    asset_id        TEXT NOT NULL,
    content_version TEXT NOT NULL,
    PRIMARY KEY (link_id, asset_id)
);

CREATE INDEX IF NOT EXISTS idx_capability_link_asset_refs_version
    ON {{tables.capability_link_asset_refs}} (asset_id, content_version);
