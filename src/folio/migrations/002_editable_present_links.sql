ALTER TABLE {{tables.document_versions}}
    ADD COLUMN IF NOT EXISTS created_by_editor_name TEXT;

ALTER TABLE {{tables.presentation_links}}
    ADD COLUMN IF NOT EXISTS editable BOOLEAN NOT NULL DEFAULT FALSE;
