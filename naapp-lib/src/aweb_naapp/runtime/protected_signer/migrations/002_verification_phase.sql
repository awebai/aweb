-- Coordinates the original assertion/decision transaction without holding an
-- operation/authority lock across B3 verification or a second DB checkout.
ALTER TABLE {{tables.protected_signer_operations}} ADD COLUMN verification_claim TEXT;
ALTER TABLE {{tables.protected_signer_operations}} ADD COLUMN refusal_code TEXT;
