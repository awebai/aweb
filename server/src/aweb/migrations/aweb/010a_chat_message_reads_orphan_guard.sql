-- Compatibility shim for the published 011_chat_message_reads migration.
--
-- 011's historical-watermark backfill can encounter chat_read_receipts whose
-- participant was hard-deleted. Its participant FK correctly rejects those
-- rows, so install a temporary row filter before 011 runs. This file sorts
-- after the existing 010 migration and before the immutable published 011.
-- pgdbm commits each migration separately, so every committed boundary must be
-- safe to resume:
--   * after 010a, both read-table FKs exist and the filter is ready for 011;
--   * after 011, the filter has skipped orphan rows and both FKs still exist;
--   * 012 removes only temporary machinery in one transaction.
-- A temporary unique constraint lets the message FK exist before 011 creates
-- its published unique constraint. Migration 012 rewires that FK and removes
-- the temporary constraint, leaving the final table shape unchanged.
ALTER TABLE {{tables.chat_messages}}
    ADD CONSTRAINT aapc_chat_messages_session_message_unique
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

CREATE OR REPLACE FUNCTION aweb.aapc_skip_orphan_chat_message_read()
RETURNS TRIGGER AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM {{tables.chat_participants}} participant
        WHERE participant.session_id = NEW.session_id
          AND participant.did = NEW.did
    ) THEN
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_aapc_skip_orphan_chat_message_reads
    ON {{tables.chat_message_reads}};
CREATE TRIGGER trg_aapc_skip_orphan_chat_message_reads
    BEFORE INSERT ON {{tables.chat_message_reads}}
    FOR EACH ROW
    EXECUTE FUNCTION aweb.aapc_skip_orphan_chat_message_read();
