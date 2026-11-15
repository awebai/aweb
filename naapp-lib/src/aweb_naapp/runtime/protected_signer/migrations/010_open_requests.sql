-- A requester's requests still waiting for a human, by deadline:
-- prepare counts them under the requester's lock to bound how many are open.
CREATE INDEX protected_signer_operations_open_by_requester
    ON {{tables.protected_signer_operations}} (requester, expires_at)
    WHERE approval_id IS NOT NULL AND result IS NULL AND refusal_code IS NULL AND signed_result IS NULL;
