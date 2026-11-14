-- The binding scope a request was prepared under, as its own column, so a
-- reader filters one scope in SQL and pages it by expiry then operation id
-- through one ordered index instead of decoding every stored request.
ALTER TABLE {{tables.protected_signer_operations}} ADD COLUMN scope JSONB;
UPDATE {{tables.protected_signer_operations}}
    SET scope = (convert_from(request, 'UTF8')::jsonb) -> 'scope';
ALTER TABLE {{tables.protected_signer_operations}} ALTER COLUMN scope SET NOT NULL;
CREATE INDEX protected_signer_operations_scope_order
    ON {{tables.protected_signer_operations}} (scope, expires_at DESC, operation_id DESC);
