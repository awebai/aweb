-- A bounded root admission is not a B3 approval. The shared operation row
-- retains the same exact intent/digest, with no fabricated human evidence.
ALTER TABLE {{tables.protected_signer_operations}} ALTER COLUMN approval_id DROP NOT NULL;
-- One durable signature precedes external registration; only confirmed delivery
-- becomes result. An ambiguous send remains reconciliable, never re-signed.
ALTER TABLE {{tables.protected_signer_operations}} ADD COLUMN signed_result JSONB;
ALTER TABLE {{tables.protected_signer_operations}} ADD COLUMN delivery_claim TEXT;
