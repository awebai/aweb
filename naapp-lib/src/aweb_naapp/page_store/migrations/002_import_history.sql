-- Imported historical evidence is explicitly unverified, never active authority.
CREATE TABLE {{tables.page_import_history}} (
    scope TEXT[] PRIMARY KEY REFERENCES {{tables.pages}}(scope),
    history JSONB NOT NULL
);
