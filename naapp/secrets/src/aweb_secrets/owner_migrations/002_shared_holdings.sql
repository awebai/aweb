-- A one-time handback of the old scope map to the canonical human-role store.
-- Role timestamps, B3 subjects and credentials are deliberately not rewritten.
LOCK TABLE {{tables.owner_principals}} IN SHARE ROW EXCLUSIVE MODE;
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM {{tables.owner_principals}}
        WHERE principal_did NOT LIKE 'did:aw:_%'
           OR scope <> 'secrets.owner.' || left(encode(sha256(convert_to(
               installation_id || chr(10) || team_id || chr(10) || principal_did,
               'UTF8')), 'hex'), 40)
    ) THEN
        RAISE EXCEPTION 'owner cutover requires an explicit human-role act for legacy or inconsistent identity bindings';
    END IF;
END;
$$;
INSERT INTO {{tables.role_holdings}}
    (b3_scope, installation_id, team_id, role, principal_did, certificate)
SELECT scope, installation_id, team_id, 'secrets.owner', principal_did, NULL
FROM {{tables.owner_principals}};
