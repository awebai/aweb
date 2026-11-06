-- One original run association on S3's UUID. Execution state remains ONLY in
-- dispatches; S12 retains the sole frozen plan and joint admission marker.
CREATE UNIQUE INDEX idx_run_plan_context_binding ON {{tables.run_approval_plans}}
    (installation_id,team_id,run_id,intent_id,dispatch_id,plan_digest);
CREATE TABLE {{tables.run_contexts}} (
    dispatch_id UUID PRIMARY KEY REFERENCES {{tables.dispatches}} (dispatch_id)
        DEFERRABLE INITIALLY DEFERRED,
    dispatch_ref TEXT NOT NULL UNIQUE CHECK (dispatch_ref ~ '^dsp_[A-Za-z0-9_-]{22,}$'),
    run_id TEXT NOT NULL UNIQUE,
    intent_id TEXT NOT NULL UNIQUE,
    app_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    install_generation BIGINT NOT NULL CHECK (install_generation >= 1),
    principal_did TEXT NOT NULL,
    member_did_key TEXT NOT NULL,
    certificate_id TEXT NOT NULL,
    team_did_key TEXT NOT NULL,
    attestation JSONB,
    request_id TEXT NOT NULL,
    request_sha256 BYTEA NOT NULL CHECK (octet_length(request_sha256)=32),
    request_mac TEXT NOT NULL CHECK (request_mac ~ '^[0-9a-f]{64}$'),
    params_mac TEXT CHECK (params_mac ~ '^[0-9a-f]{64}$'),
    job_id TEXT NOT NULL,
    job_digest TEXT NOT NULL CHECK (job_digest ~ '^[0-9a-f]{64}$'),
    runner_id TEXT NOT NULL REFERENCES {{tables.runners}} (runner_id),
    plan_digest TEXT NOT NULL CHECK (plan_digest ~ '^[0-9a-f]{64}$'),
    actor JSONB NOT NULL,
    payload JSONB NOT NULL,
    correlation JSONB NOT NULL,
    signed_trace_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (installation_id,principal_did,request_id),
    FOREIGN KEY (installation_id,team_id,run_id,intent_id,dispatch_id,plan_digest)
        REFERENCES {{tables.run_approval_plans}}
            (installation_id,team_id,run_id,intent_id,dispatch_id,plan_digest)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX idx_run_contexts_runner ON {{tables.run_contexts}} (runner_id,created_at,dispatch_id);
CREATE TRIGGER run_contexts_immutable BEFORE UPDATE OR DELETE ON {{tables.run_contexts}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();

-- Delivery evidence, not a queue or state machine. Exact signed/ciphertext
-- assignment bytes and private report hashes are written once with S3 effects.
CREATE TABLE {{tables.run_deliveries}} (
    dispatch_id UUID PRIMARY KEY REFERENCES {{tables.run_contexts}} (dispatch_id),
    assignment BYTEA,
    issued_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    report_sha256 BYTEA CHECK (octet_length(report_sha256)=32),
    CHECK ((assignment IS NULL AND issued_at IS NULL AND expires_at IS NULL)
        OR (assignment IS NOT NULL AND issued_at IS NOT NULL AND expires_at IS NOT NULL
            AND octet_length(assignment)<=1048576
            AND expires_at>issued_at AND expires_at<=issued_at+interval '300 seconds')),
    CHECK (assignment IS NOT NULL OR (started_at IS NULL AND report_sha256 IS NULL))
);
CREATE FUNCTION {{tables.secrets_run_delivery_once}}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.dispatch_id IS DISTINCT FROM NEW.dispatch_id
       OR (OLD.assignment IS NOT NULL AND
           (OLD.assignment,OLD.issued_at,OLD.expires_at) IS DISTINCT FROM
           (NEW.assignment,NEW.issued_at,NEW.expires_at))
       OR (OLD.started_at IS NOT NULL AND OLD.started_at IS DISTINCT FROM NEW.started_at)
       OR (OLD.report_sha256 IS NOT NULL AND OLD.report_sha256 IS DISTINCT FROM NEW.report_sha256)
    THEN RAISE EXCEPTION 'run delivery evidence is write-once'; END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER run_deliveries_write_once BEFORE UPDATE ON {{tables.run_deliveries}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_run_delivery_once}}();
CREATE TRIGGER run_deliveries_no_delete BEFORE DELETE ON {{tables.run_deliveries}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.secrets_refuse_change}}();
