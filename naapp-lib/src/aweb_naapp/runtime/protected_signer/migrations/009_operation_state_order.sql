-- One ordered access path per state class the owner page lists, so a page of
-- one class never inspects rows of another: open (waiting or expired
-- unsigned), signed but unconfirmed, and final. Each is a partial index whose
-- predicate the reader's query states exactly.
CREATE INDEX protected_signer_operations_open_order
    ON {{tables.protected_signer_operations}} (scope, expires_at DESC, operation_id DESC)
    WHERE approval_id IS NOT NULL AND result IS NULL AND refusal_code IS NULL AND signed_result IS NULL;
CREATE INDEX protected_signer_operations_unresolved_order
    ON {{tables.protected_signer_operations}} (scope, expires_at DESC, operation_id DESC)
    WHERE approval_id IS NOT NULL AND result IS NULL AND refusal_code IS NULL AND signed_result IS NOT NULL;
CREATE INDEX protected_signer_operations_final_order
    ON {{tables.protected_signer_operations}} (scope, expires_at DESC, operation_id DESC)
    WHERE approval_id IS NOT NULL AND (result IS NOT NULL OR refusal_code IS NOT NULL);
