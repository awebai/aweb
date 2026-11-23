-- A read-only link's row is keyed by the verifier of its bearer token, never
-- the token: the hex SHA-256 of its UTF-8 bytes, as naapp-lib secret_verifier
-- computes it (folio.link_secrets). Rows minted before this migration are
-- converted in place. Editable rows keep their public link id.
UPDATE {{tables.presentation_links}}
SET token = encode(sha256(convert_to(token, 'UTF8')), 'hex')
WHERE editable IS FALSE;
