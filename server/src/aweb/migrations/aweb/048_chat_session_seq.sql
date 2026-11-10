-- 048_chat_session_seq.sql
-- One counter per chat session numbers its messages and read receipts.
--
-- chat_sessions.last_seq is the last number given out in the session. A
-- trigger takes the next number for every chat_messages insert and for every
-- chat_read_receipts insert or change, by updating the session row. That row
-- lock is held until the writer commits, so within a session a greater number
-- always commits later: a reader that has seen number n has seen every
-- committed number up to n, whatever created_at or last_read_at say. Numbers
-- increase within a session and are not consecutive: an upsert of a read
-- receipt can take two, and deleted rows leave gaps.
--
-- The triggers number every writer, including a server process that does not
-- know the columns, and replace any number a writer supplies.

-- The ALTER TABLEs below take ACCESS EXCLUSIVE on each table. Take it on all
-- three first, in the order writers reach them (session, message, receipt), so
-- no message or receipt is written between the backfill and the triggers and
-- this transaction never waits for a second table while holding the first in
-- a weaker mode.
--
-- ACCESS EXCLUSIVE blocks every read and write of the three tables until this
-- transaction commits: chat sends, read marks, history, pending and open
-- streams' polls wait for it. The transaction writes each row of the three
-- tables once and builds two indexes; with tens of thousands of rows that is
-- well under a second. A deployment with many millions of chat rows should
-- expect a pause in proportion.
LOCK TABLE {{tables.chat_sessions}}, {{tables.chat_messages}}, {{tables.chat_read_receipts}}
    IN ACCESS EXCLUSIVE MODE;

ALTER TABLE {{tables.chat_sessions}}
    ADD COLUMN last_seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE {{tables.chat_messages}}
    ADD COLUMN seq BIGINT;
ALTER TABLE {{tables.chat_read_receipts}}
    ADD COLUMN seq BIGINT;

-- Existing messages are numbered in the order readers have shown them.
UPDATE {{tables.chat_messages}} message
SET seq = numbered.seq
FROM (
    SELECT message_id,
           row_number() OVER (PARTITION BY session_id ORDER BY created_at, message_id) AS seq
    FROM {{tables.chat_messages}}
) numbered
WHERE numbered.message_id = message.message_id;

-- Existing read receipts follow their session's messages.
UPDATE {{tables.chat_read_receipts}} receipt
SET seq = numbered.seq
FROM (
    SELECT r.session_id, r.did,
           COALESCE((
               SELECT MAX(m.seq) FROM {{tables.chat_messages}} m WHERE m.session_id = r.session_id
           ), 0)
           + row_number() OVER (PARTITION BY r.session_id ORDER BY r.last_read_at NULLS FIRST, r.did) AS seq
    FROM {{tables.chat_read_receipts}} r
) numbered
WHERE numbered.session_id = receipt.session_id
  AND numbered.did = receipt.did;

UPDATE {{tables.chat_sessions}} chat_session
SET last_seq = numbered.last_seq
FROM (
    SELECT session_id, MAX(seq) AS last_seq
    FROM (
        SELECT session_id, seq FROM {{tables.chat_messages}}
        UNION ALL
        SELECT session_id, seq FROM {{tables.chat_read_receipts}}
    ) AS numbered_rows
    GROUP BY session_id
) numbered
WHERE numbered.session_id = chat_session.session_id;

ALTER TABLE {{tables.chat_messages}}
    ALTER COLUMN seq SET NOT NULL,
    ADD CONSTRAINT chat_messages_session_seq_unique UNIQUE (session_id, seq);
ALTER TABLE {{tables.chat_read_receipts}}
    ALTER COLUMN seq SET NOT NULL;
CREATE INDEX idx_chat_read_receipts_session_seq
    ON {{tables.chat_read_receipts}} (session_id, seq);

CREATE FUNCTION aweb.assign_chat_session_seq()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE {{tables.chat_sessions}}
    SET last_seq = last_seq + 1
    WHERE session_id = NEW.session_id
    RETURNING last_seq INTO NEW.seq;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'chat session % does not exist', NEW.session_id
            USING ERRCODE = '23503';
    END IF;
    RETURN NEW;
END
$$;

-- BEFORE triggers fire in name order, so this one runs ahead of
-- trg_chat_messages_require_ingress_receipt: every writer locks the session
-- row before the message's ingress receipt, the order federated delivery and
-- native ingress use. A refused insert rolls its number back.
CREATE TRIGGER trg_chat_messages_assign_seq
    BEFORE INSERT ON {{tables.chat_messages}}
    FOR EACH ROW
    EXECUTE FUNCTION aweb.assign_chat_session_seq();

CREATE TRIGGER trg_chat_read_receipts_assign_seq_insert
    BEFORE INSERT ON {{tables.chat_read_receipts}}
    FOR EACH ROW
    EXECUTE FUNCTION aweb.assign_chat_session_seq();

-- An update that changes what was read, or when, is a receipt to deliver and
-- takes a number; one that changes neither keeps its number.
CREATE TRIGGER trg_chat_read_receipts_assign_seq_update
    BEFORE UPDATE ON {{tables.chat_read_receipts}}
    FOR EACH ROW
    WHEN (
        NEW.last_read_message_id IS DISTINCT FROM OLD.last_read_message_id
        OR NEW.last_read_at IS DISTINCT FROM OLD.last_read_at
        OR NEW.seq IS DISTINCT FROM OLD.seq
    )
    EXECUTE FUNCTION aweb.assign_chat_session_seq();
