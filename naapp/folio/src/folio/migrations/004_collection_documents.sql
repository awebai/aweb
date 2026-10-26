-- Discovery metadata only. PageStore owns schemas, rows, revisions and ACLs.
CREATE TABLE IF NOT EXISTS {{tables.collection_documents}} (
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    page_id TEXT NOT NULL,
    document_id UUID NOT NULL UNIQUE REFERENCES {{tables.documents}}(document_id) ON DELETE CASCADE,
    PRIMARY KEY (installation_id, team_id, app_id, collection_id),
    UNIQUE (installation_id, team_id, app_id, page_id)
);
