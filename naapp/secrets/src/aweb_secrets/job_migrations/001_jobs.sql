-- Immutable definitions and exactly one installation-scoped current pointer.
CREATE TABLE IF NOT EXISTS {{tables.job_definitions}} (
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    record JSONB NOT NULL,
    PRIMARY KEY (installation_id, job_id, digest)
);
CREATE TABLE IF NOT EXISTS {{tables.current_jobs}} (
    installation_id TEXT NOT NULL,
    job_id TEXT NOT NULL,
    digest TEXT NOT NULL,
    PRIMARY KEY (installation_id, job_id),
    FOREIGN KEY (installation_id, job_id, digest)
        REFERENCES {{tables.job_definitions}} (installation_id, job_id, digest)
);

CREATE OR REPLACE FUNCTION {{tables.jobs_refuse_change}}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'a job definition is immutable';
END;
$$;
CREATE TRIGGER job_definitions_immutable
    BEFORE UPDATE ON {{tables.job_definitions}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.jobs_refuse_change}}();
