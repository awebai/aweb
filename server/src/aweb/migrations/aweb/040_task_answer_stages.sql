-- Stage evidence is private answer storage; receipt reads expose no signatures.
ALTER TABLE {{tables.task_answers}} ADD COLUMN stage_receipt JSONB;
CREATE TABLE {{tables.task_answer_stage_nonces}} (
    team_id TEXT NOT NULL,
    app_id TEXT NOT NULL,
    installation_id TEXT NOT NULL,
    nonce TEXT NOT NULL CHECK (nonce ~ '^[0-9a-f]{32}$'),
    receipt_id UUID NOT NULL UNIQUE REFERENCES {{tables.task_answers}}(receipt_id),
    PRIMARY KEY (team_id, app_id, installation_id, nonce)
);
