-- Operational managed attachment bindings only. Filenames/keys/blobs are not
-- routed metadata: their storage and lifecycle belong to the embedding backend.
CREATE TABLE IF NOT EXISTS {{tables.message_attachments}} (
    attachment_id UUID PRIMARY KEY,
    message_kind TEXT NOT NULL CHECK (message_kind IN ('mail', 'chat')),
    message_id UUID NOT NULL,
    conversation_id UUID NOT NULL REFERENCES {{tables.conversations}}(conversation_id) ON DELETE CASCADE,
    size INTEGER NOT NULL CHECK (size > 0 AND size <= 5242880),
    descriptor_sha256 TEXT NOT NULL CHECK (descriptor_sha256 ~ '^[0-9a-f]{64}$'),
    envelope_sha256 TEXT NOT NULL CHECK (envelope_sha256 ~ '^[0-9a-f]{64}$'),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0 AND ordinal < 4),
    UNIQUE (message_kind, message_id, ordinal)
);
CREATE INDEX IF NOT EXISTS idx_message_attachments_message ON {{tables.message_attachments}} (message_kind, message_id);
