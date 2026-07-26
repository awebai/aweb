-- Exact per-recipient read state for chat messages.
--
-- This grows by at most one row per recipient that marks a message read
-- (N-1 rows per message in an N-party session). Retention or compaction is a
-- separate operational concern; unread state must not be inferred from a
-- timestamp or message ordering watermark.
ALTER TABLE {{tables.chat_messages}}
    ADD CONSTRAINT chat_messages_session_message_unique
    UNIQUE (session_id, message_id);

CREATE TABLE IF NOT EXISTS {{tables.chat_message_reads}} (
    session_id UUID NOT NULL,
    did TEXT NOT NULL,
    message_id UUID NOT NULL,
    agent_id UUID REFERENCES {{tables.agents}}(agent_id),
    read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (session_id, did, message_id),
    FOREIGN KEY (session_id, did)
        REFERENCES {{tables.chat_participants}}(session_id, did) ON DELETE CASCADE,
    FOREIGN KEY (session_id, message_id)
        REFERENCES {{tables.chat_messages}}(session_id, message_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_chat_message_reads_participant
    ON {{tables.chat_message_reads}} (session_id, did);

-- Preserve deployed read state when switching from range watermarks to exact
-- rows. Historical false positives cannot be reconstructed, but omitting this
-- backfill would redeliver every previously read incoming message.
INSERT INTO {{tables.chat_message_reads}} (
    session_id, did, message_id, agent_id, read_at
)
SELECT
    receipt.session_id,
    receipt.did,
    message.message_id,
    receipt.agent_id,
    COALESCE(receipt.last_read_at, NOW())
FROM {{tables.chat_read_receipts}} receipt
JOIN {{tables.chat_messages}} watermark
  ON watermark.message_id = receipt.last_read_message_id
 AND watermark.session_id = receipt.session_id
JOIN {{tables.chat_messages}} message
  ON message.session_id = receipt.session_id
 AND message.from_did <> receipt.did
 AND message.created_at <= watermark.created_at
ON CONFLICT (session_id, did, message_id) DO NOTHING;
