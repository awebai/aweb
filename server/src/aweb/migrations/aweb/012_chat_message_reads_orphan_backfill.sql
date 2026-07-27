-- Finish the compatibility shim around immutable published migration 011.
-- Remove the temporary insert filter, converge the table constraints, then
-- repeat the historical backfill idempotently with the participant guard made
-- explicit. This also covers databases that had already applied 011 before the
-- shim was shipped.
DROP TRIGGER IF EXISTS trg_aapc_skip_orphan_chat_message_reads
    ON {{tables.chat_message_reads}};
DROP FUNCTION IF EXISTS aweb.aapc_skip_orphan_chat_message_read();

-- On a pre-011 database the message FK currently references 010a's temporary
-- unique constraint; on an already-011 database it references 011's published
-- constraint. Recreate it transactionally against the published constraint so
-- the temporary unique constraint can be removed on both paths.
ALTER TABLE {{tables.chat_message_reads}}
    DROP CONSTRAINT chat_message_reads_session_id_message_id_fkey;
ALTER TABLE {{tables.chat_messages}}
    DROP CONSTRAINT aapc_chat_messages_session_message_unique;
ALTER TABLE {{tables.chat_message_reads}}
    ADD CONSTRAINT chat_message_reads_session_id_message_id_fkey
    FOREIGN KEY (session_id, message_id)
    REFERENCES {{tables.chat_messages}}(session_id, message_id)
    ON DELETE CASCADE;

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
WHERE EXISTS (
    SELECT 1
    FROM {{tables.chat_participants}} participant
    WHERE participant.session_id = receipt.session_id
      AND participant.did = receipt.did
)
ON CONFLICT (session_id, did, message_id) DO NOTHING;
