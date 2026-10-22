-- Inert frozen-plan and ordered slot associations, not a run execution registry.
CREATE TABLE {{tables.run_approval_plans}} (
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    intent_id TEXT NOT NULL,
    dispatch_id UUID NOT NULL,
    plan_digest TEXT NOT NULL,
    canonical BYTEA NOT NULL,
    PRIMARY KEY (installation_id, team_id, run_id),
    UNIQUE (installation_id, team_id, intent_id),
    UNIQUE (installation_id, team_id, dispatch_id)
);
CREATE TABLE {{tables.run_slot_approvals}} (
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    secret_id TEXT NOT NULL,
    secret_version INTEGER NOT NULL,
    grant_id TEXT NOT NULL,
    policy_ref TEXT,
    approval_id TEXT UNIQUE,
    approval_ref TEXT UNIQUE,
    request TEXT,
    PRIMARY KEY (installation_id, team_id, run_id, ordinal),
    FOREIGN KEY (installation_id, team_id, run_id)
        REFERENCES {{tables.run_approval_plans}} (installation_id, team_id, run_id),
    CHECK ((approval_id IS NULL AND approval_ref IS NULL AND request IS NULL AND policy_ref IS NULL)
        OR (approval_id IS NOT NULL AND approval_ref IS NOT NULL AND request IS NOT NULL AND policy_ref IS NOT NULL))
);
CREATE INDEX idx_run_slot_approval_secret ON {{tables.run_slot_approvals}}
    (installation_id, team_id, secret_id);
CREATE TABLE {{tables.run_approval_admissions}} (
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (installation_id, team_id, run_id),
    FOREIGN KEY (installation_id, team_id, run_id)
        REFERENCES {{tables.run_approval_plans}} (installation_id, team_id, run_id)
);
CREATE FUNCTION {{tables.run_approval_refuse_change}}() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'run approval associations are immutable'; END; $$;
CREATE TRIGGER run_approval_plan_immutable BEFORE UPDATE OR DELETE ON {{tables.run_approval_plans}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.run_approval_refuse_change}}();
CREATE TRIGGER run_slot_approval_immutable BEFORE UPDATE OR DELETE ON {{tables.run_slot_approvals}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.run_approval_refuse_change}}();
CREATE TRIGGER run_approval_admission_immutable BEFORE UPDATE OR DELETE ON {{tables.run_approval_admissions}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.run_approval_refuse_change}}();
