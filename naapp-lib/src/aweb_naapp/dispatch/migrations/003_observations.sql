-- Outcomes are facts, keyed to the actual send attempt. The old columns are
-- guarded read projections for existing callers, never a second write path.
CREATE TABLE {{tables.dispatch_observations}} (
    observation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    dispatch_id UUID NOT NULL REFERENCES {{tables.dispatches}}(dispatch_id),
    attempt INTEGER CHECK (attempt > 0),
    kind TEXT NOT NULL CHECK (kind IN ('outcome','late','settlement','snapshot')),
    state TEXT NOT NULL CHECK (state IN (
        'completed','not_sent','outcome_unknown',
        'reconciled_completed','reconciled_failed','reconciled_unknown',
        'received','refused','awaiting_approval','approval_denied','approval_expired',
        'cancelled','admitted','dispatching')),
    result JSONB,
    provenance TEXT NOT NULL CHECK (provenance IN ('live','legacy_snapshot')),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (provenance='legacy_snapshot' OR attempt IS NOT NULL),
    CHECK (kind<>'snapshot' OR provenance='legacy_snapshot'),
    CHECK (kind<>'outcome' OR state IN ('completed','not_sent','outcome_unknown')),
    CHECK (kind<>'settlement' OR state IN
        ('reconciled_completed','reconciled_failed','reconciled_unknown'))
);
CREATE UNIQUE INDEX dispatch_one_attempt_outcome
    ON {{tables.dispatch_observations}}(dispatch_id,attempt) WHERE kind='outcome';
CREATE UNIQUE INDEX dispatch_one_settlement
    ON {{tables.dispatch_observations}}(dispatch_id) WHERE kind='settlement';
CREATE UNIQUE INDEX dispatch_one_legacy_snapshot
    ON {{tables.dispatch_observations}}(dispatch_id) WHERE kind='snapshot';
CREATE INDEX dispatch_observations_by_dispatch_kind
    ON {{tables.dispatch_observations}}(dispatch_id,kind);

-- The previous mutable slot does not prove which attempt produced its value.
-- Preserve it explicitly as a snapshot, with no invented attempt association.
-- An application with stricter retention MUST purge its legacy data in the
-- recorded before_upgrade migration before this generic import runs.
INSERT INTO {{tables.dispatch_observations}}(dispatch_id,kind,state,result,provenance)
    SELECT dispatch_id,'snapshot',state,result,'legacy_snapshot'
    FROM {{tables.dispatches}};
INSERT INTO {{tables.dispatch_observations}}(dispatch_id,kind,state,result,provenance)
    SELECT d.dispatch_id,'late',d.state,e.value,'legacy_snapshot'
    FROM {{tables.dispatches}} d
    CROSS JOIN LATERAL jsonb_array_elements(d.late_results) WITH ORDINALITY e(value,ordinal)
    ORDER BY d.dispatch_id,e.ordinal;

CREATE FUNCTION {{tables.dispatch_observation_immutable}}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'dispatch observations are append-only';
END;
$$;
CREATE TRIGGER dispatch_observations_immutable
    BEFORE UPDATE OR DELETE ON {{tables.dispatch_observations}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.dispatch_observation_immutable}}();

CREATE FUNCTION {{tables.dispatch_result_projection}}() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.result IS NOT NULL OR NEW.late_results <> '[]'::jsonb THEN
            RAISE EXCEPTION 'dispatch results are read projections';
        END IF;
    ELSIF NEW.result IS DISTINCT FROM OLD.result
          OR NEW.late_results IS DISTINCT FROM OLD.late_results THEN
        RAISE EXCEPTION 'dispatch results are read projections';
    END IF;
    NEW.result := NULL;
    IF NEW.state IN ('completed','not_sent','outcome_unknown',
                    'reconciled_completed','reconciled_failed','reconciled_unknown') THEN
        SELECT o.result INTO NEW.result FROM {{tables.dispatch_observations}} o
        WHERE o.dispatch_id=NEW.dispatch_id AND o.state=NEW.state
          AND ((o.kind='outcome' AND o.attempt=NEW.attempts)
            OR o.kind='settlement' OR o.kind='snapshot')
        ORDER BY (o.kind<>'snapshot') DESC,o.observation_id DESC LIMIT 1;
    END IF;
    SELECT COALESCE(jsonb_agg(o.result ORDER BY o.observation_id),'[]'::jsonb)
        INTO NEW.late_results FROM {{tables.dispatch_observations}} o
        WHERE o.dispatch_id=NEW.dispatch_id AND o.kind='late';
    RETURN NEW;
END;
$$;
CREATE TRIGGER dispatch_result_projection BEFORE INSERT OR UPDATE ON {{tables.dispatches}}
    FOR EACH ROW EXECUTE FUNCTION {{tables.dispatch_result_projection}}();
-- Initial projection fill rewrites every existing dispatch once. There are no
-- deployed installations at this change; a deployed upgrade pays this full
-- table update before serving requests.
UPDATE {{tables.dispatches}} SET updated_at=updated_at;
