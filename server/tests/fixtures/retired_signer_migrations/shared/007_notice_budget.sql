-- One requester's approval notices, bounded per signer authority: each
-- prepared operation that needs a human reserves its notices once, or records
-- that they were suppressed past the budget. Nothing here grants or refuses an
-- approval; the request waits for its approver either way.
CREATE TABLE {{tables.protected_signer_notice_reservations}} (
    operation_id TEXT PRIMARY KEY REFERENCES {{tables.protected_signer_operations}}(operation_id),
    service_id TEXT NOT NULL,
    authority_id TEXT NOT NULL,
    requester TEXT NOT NULL,
    notices INTEGER NOT NULL CHECK (notices >= 0),
    suppressed BOOLEAN NOT NULL,
    reserved_at TIMESTAMPTZ NOT NULL,
    CHECK (NOT suppressed OR notices = 0)
);
CREATE INDEX protected_signer_notice_window
    ON {{tables.protected_signer_notice_reservations}} (service_id, authority_id, requester, reserved_at);
