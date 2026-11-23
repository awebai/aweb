-- A completed response whose inspection expired has only value-free metadata.
CREATE OR REPLACE FUNCTION {{tables.secrets_broker_metadata}}(payload JSONB) RETURNS JSONB
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    answer JSONB := '{}'::jsonb;
    metadata JSONB;
    field TEXT;
    value JSONB;
BEGIN
    IF payload IS NULL OR payload='null'::jsonb THEN RETURN NULL; END IF;
    FOREACH field IN ARRAY ARRAY['request_id','request_ref','reconcile_ref',
                                'control_approval_id','control_approval_ref'] LOOP
        IF jsonb_typeof(payload->field)='string' THEN
            answer := answer || jsonb_build_object(field,payload->field);
        END IF;
    END LOOP;
    IF payload->>'state' IN ('completed','result_withheld','not_sent','outcome_unknown',
        'reconciled_completed','reconciled_failed','reconciled_unknown') THEN
        answer := answer || jsonb_build_object('state',payload->'state');
    END IF;
    IF payload->>'code' IN ('credential_shaped','content_encoded','content_type_not_allowed',
                            'response_scan_unavailable') THEN
        answer := answer || jsonb_build_object('code',payload->'code');
    END IF;
    IF payload->>'next'='resubmit' THEN
        answer := answer || jsonb_build_object('next','resubmit');
    END IF;
    IF jsonb_typeof(payload->'result')='object' THEN
        metadata := jsonb_build_object('body',NULL,'headers',NULL);
        FOREACH field IN ARRAY ARRAY['status','upstream_bytes','redaction_count'] LOOP
            value := payload->'result'->field;
            IF jsonb_typeof(value)='number' AND value::text ~ '^[0-9]+$' THEN
                metadata := metadata || jsonb_build_object(field,value);
            END IF;
        END LOOP;
        FOREACH field IN ARRAY ARRAY['truncated','undeclared_credential','upstream_truncated'] LOOP
            value := payload->'result'->field;
            IF jsonb_typeof(value)='boolean' THEN
                metadata := metadata || jsonb_build_object(field,value);
            END IF;
        END LOOP;
        FOREACH field IN ARRAY ARRAY['upstream_response_hmac','returned_hmac'] LOOP
            IF payload->'result'->>field ~ '^[A-Za-z0-9_-]{43}$' THEN
                metadata := metadata || jsonb_build_object(field,payload->'result'->field);
            END IF;
        END LOOP;
        IF payload->'result'->>'disposition' IN ('returned','withheld') THEN
            metadata := metadata || jsonb_build_object('disposition',payload->'result'->'disposition');
        END IF;
        answer := answer || jsonb_build_object('result',metadata);
    END IF;
    RETURN answer;
END;
$$;
