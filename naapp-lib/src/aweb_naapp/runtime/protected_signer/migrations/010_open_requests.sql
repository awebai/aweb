-- Each requester's unfinished requests that need a human, by deadline:
-- prepare counts them under that requester's lock to bound how many are open.
-- An agent is counted by its principal; an owner's page request by the owner.
CREATE INDEX protected_signer_operations_open_by_requester
    ON {{tables.protected_signer_operations}} (requester, expires_at)
    WHERE approval_id IS NOT NULL AND result IS NULL AND refusal_code IS NULL AND signed_result IS NULL
        AND initiator_subject IS NULL;
CREATE INDEX protected_signer_operations_open_by_owner
    ON {{tables.protected_signer_operations}} (initiator_subject, initiator_scope, expires_at)
    WHERE approval_id IS NOT NULL AND result IS NULL AND refusal_code IS NULL AND signed_result IS NULL
        AND initiator_subject IS NOT NULL;
