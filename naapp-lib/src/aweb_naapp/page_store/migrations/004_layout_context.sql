-- Preserve each immutable layout's schema/document cut. Current data may move
-- to a newer schema before an older layout is exported or imported.
CREATE TABLE {{tables.page_layout_context}} (
    scope TEXT[] NOT NULL REFERENCES {{tables.pages}}(scope),
    version BIGINT NOT NULL,
    snapshot JSONB NOT NULL,
    PRIMARY KEY(scope, version)
);
