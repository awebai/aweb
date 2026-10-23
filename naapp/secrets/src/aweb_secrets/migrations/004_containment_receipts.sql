-- Value-free receipts make a signed containment request idempotent.
CREATE TABLE IF NOT EXISTS {{tables.containment_receipts}} (
    receipt_id TEXT PRIMARY KEY,
    installation_id TEXT NOT NULL,
    team_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    affected_secret_ids JSONB NOT NULL
);
