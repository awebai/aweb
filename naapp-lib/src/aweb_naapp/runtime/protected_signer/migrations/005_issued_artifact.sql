-- Concrete artifact issued once under the exact-act approval, atomically with
-- its verified signature and private retained delivery. The frozen request and
-- B2 digest remain the approved intent, never rewritten at execution.
ALTER TABLE {{tables.protected_signer_operations}} ADD COLUMN issued_artifact JSONB;
