CREATE TABLE IF NOT EXISTS {{tables.teams}} (
    team_id TEXT PRIMARY KEY,
    team_did_key TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS {{tables.agents}} (
    team_id TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    did_key TEXT NOT NULL,
    did_aw TEXT,
    address TEXT,
    alias TEXT NOT NULL,
    latest_certificate_id TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (team_id, did_key, alias)
);

CREATE INDEX IF NOT EXISTS idx_folio_agents_team_alias
    ON {{tables.agents}}(team_id, alias);

CREATE TABLE IF NOT EXISTS {{tables.documents}} (
    document_id UUID PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    title TEXT NOT NULL,
    created_by_did_key TEXT NOT NULL,
    created_by_did_aw TEXT,
    created_by_alias TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (team_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_folio_documents_team_updated
    ON {{tables.documents}}(team_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS {{tables.document_versions}} (
    version_id UUID PRIMARY KEY,
    document_id UUID NOT NULL REFERENCES {{tables.documents}}(document_id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_by_did_key TEXT NOT NULL,
    created_by_did_aw TEXT,
    created_by_address TEXT,
    created_by_alias TEXT NOT NULL,
    certificate_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (document_id, version_number)
);

CREATE INDEX IF NOT EXISTS idx_folio_versions_document_number
    ON {{tables.document_versions}}(document_id, version_number DESC);

CREATE TABLE IF NOT EXISTS {{tables.subscriptions}} (
    team_id TEXT PRIMARY KEY REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'active', 'past_due')),
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT,
    current_period_end TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_event_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_folio_subscriptions_tier
    ON {{tables.subscriptions}}(tier);

CREATE TABLE IF NOT EXISTS {{tables.presentation_links}} (
    token TEXT PRIMARY KEY,
    document_id UUID NOT NULL REFERENCES {{tables.documents}}(document_id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by_did_key TEXT NOT NULL,
    created_by_did_aw TEXT,
    created_by_alias TEXT NOT NULL,
    certificate_id TEXT NOT NULL,
    FOREIGN KEY (document_id, version_number) REFERENCES {{tables.document_versions}}(document_id, version_number) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_folio_presentation_links_document
    ON {{tables.presentation_links}}(document_id, version_number);
CREATE INDEX IF NOT EXISTS idx_folio_presentation_links_expires
    ON {{tables.presentation_links}}(expires_at);

CREATE TABLE IF NOT EXISTS {{tables.assets}} (
    asset_id UUID PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    bytes BYTEA NOT NULL,
    content_type TEXT NOT NULL CHECK (content_type IN ('image/png', 'image/jpeg', 'image/gif', 'image/webp')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_folio_assets_team_created
    ON {{tables.assets}}(team_id, created_at DESC);

CREATE TABLE IF NOT EXISTS {{tables.themes}} (
    team_id TEXT PRIMARY KEY REFERENCES {{tables.teams}}(team_id) ON DELETE CASCADE,
    tokens JSONB NOT NULL DEFAULT '{}'::jsonb,
    logo_asset_id UUID REFERENCES {{tables.assets}}(asset_id) ON DELETE SET NULL,
    header TEXT,
    footer TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
