-- Revisions cover every task writer, including callers composing their own
-- transaction. Legacy aliases remain display data, never answer authority.
ALTER TABLE {{tables.tasks}}
    ADD COLUMN rev BIGINT NOT NULL DEFAULT 1 CHECK (rev > 0),
    ADD COLUMN question_rev BIGINT NOT NULL DEFAULT 1 CHECK (question_rev > 0),
    ADD COLUMN assignee_did TEXT,
    ADD COLUMN created_by_did TEXT,
    ADD COLUMN closed_by_did TEXT;

-- Freeze the authority of the current assignee at migration time. Historical
-- creator/closer aliases are not sufficient evidence to reconstruct their DIDs.
UPDATE {{tables.tasks}} AS t
SET assignee_did = COALESCE(NULLIF(a.did_aw, ''), a.did_key)
FROM {{tables.agents}} AS a
WHERE t.team_id = a.team_id AND t.assignee_alias = a.alias
  AND a.deleted_at IS NULL AND a.status = 'active';

CREATE OR REPLACE FUNCTION aweb.advance_task_revision()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.rev := OLD.rev + 1;
    NEW.question_rev := OLD.question_rev;
    IF OLD.status = 'closed' AND NEW.status <> 'closed' THEN
        NEW.question_rev := OLD.question_rev + 1;
        NEW.closed_at := NULL;
        NEW.closed_by_alias := NULL;
        NEW.closed_by_did := NULL;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_tasks_revision
    BEFORE UPDATE ON {{tables.tasks}}
    FOR EACH ROW EXECUTE FUNCTION aweb.advance_task_revision();

CREATE TABLE {{tables.task_answers}} (
    receipt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES {{tables.tasks}}(task_id),
    question_rev BIGINT NOT NULL CHECK (question_rev > 0),
    task_rev BIGINT NOT NULL CHECK (task_rev > 0),
    answer_key TEXT NOT NULL CHECK (length(answer_key) BETWEEN 1 AND 256),
    answer_sha256 TEXT NOT NULL CHECK (answer_sha256 ~ '^[0-9a-f]{64}$'),
    answered_by_did TEXT NOT NULL,
    certificate_id TEXT NOT NULL,
    answered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (task_id, answer_key),
    UNIQUE (task_id, question_rev)
);
