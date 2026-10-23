ALTER TABLE {{tables.tasks}}
    ADD COLUMN app_request JSONB,
    ADD COLUMN cancellation JSONB,
    ADD COLUMN picked_up BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE {{tables.task_answers}}
    ADD COLUMN choice TEXT,
    ADD COLUMN proposal_rev BIGINT,
    ADD COLUMN proposal_sha256 TEXT;

CREATE TABLE {{tables.task_app_requests}} (
    task_id UUID PRIMARY KEY REFERENCES {{tables.tasks}}(task_id),
    team_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    installation_generation BIGINT NOT NULL CHECK (installation_generation > 0),
    originator_did TEXT NOT NULL,
    external_request_id TEXT NOT NULL,
    task_body_sha256 TEXT NOT NULL CHECK (task_body_sha256 ~ '^[0-9a-f]{64}$'),
    task_authorization JSONB NOT NULL,
    receipt JSONB NOT NULL,
    UNIQUE (team_id, app_id, installation_id, originator_did, external_request_id)
);

CREATE OR REPLACE FUNCTION aweb.preserve_task_app_request()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.app_request IS DISTINCT FROM OLD.app_request THEN
        RAISE EXCEPTION 'app_request is immutable';
    END IF;
    IF OLD.status = 'closed' AND NEW.status <> 'closed' THEN
        NEW.picked_up := FALSE;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER trg_tasks_app_request_immutable
    BEFORE UPDATE ON {{tables.tasks}}
    FOR EACH ROW EXECUTE FUNCTION aweb.preserve_task_app_request();

-- Comments are part of the task revision, including embedded service writers.
CREATE OR REPLACE FUNCTION aweb.advance_task_comment_revision()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE aweb.tasks SET updated_at = NOW()
    WHERE task_id = COALESCE(NEW.task_id, OLD.task_id);
    RETURN NULL;
END;
$$;
CREATE TRIGGER trg_task_comments_revision
    AFTER INSERT OR UPDATE OR DELETE ON {{tables.task_comments}}
    FOR EACH ROW EXECUTE FUNCTION aweb.advance_task_comment_revision();
