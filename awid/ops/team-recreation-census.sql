-- AWID database, schema awid. Read-only aggregate census; no domain, name,
-- key, certificate id or timestamp leaves SQL.
--
-- Question (aweb-acxc.101): has a team been deleted and created again under
-- the same domain and name, the case in which a certificate revoked before
-- the deletion could verify again?
--
-- Limit: before acxc.101, deleting a team or its namespace deleted the
-- team's certificate rows, so for a team deleted before that fix this
-- database cannot show whether it had certificates or revocations. A team
-- can be deleted only once every certificate is revoked, so any certificate
-- it had was revoked. A key rotated away before the deletion is not recorded
-- either: "same key" compares with the deleted row's last key only.
BEGIN READ ONLY;
WITH deleted AS (
    SELECT team_uuid, domain, name, team_did_key, deleted_at
    FROM awid.teams
    WHERE deleted_at IS NOT NULL
), recreated AS (
    SELECT d.team_uuid AS deleted_team,
           later.team_uuid AS later_team,
           later.deleted_at IS NULL AS later_is_live,
           later.team_did_key = d.team_did_key AS same_key
    FROM deleted d
    JOIN awid.teams later
      ON later.domain = d.domain
     AND later.name = d.name
     AND later.team_uuid <> d.team_uuid
     AND later.created_at >= d.deleted_at
)
SELECT
    (SELECT count(*) FROM deleted) AS deleted_teams,
    (SELECT count(*) FROM deleted d
      WHERE EXISTS (SELECT 1 FROM awid.team_certificates c WHERE c.team_uuid = d.team_uuid))
        AS deleted_teams_with_certificate_rows,
    (SELECT count(DISTINCT deleted_team) FROM recreated) AS deleted_teams_recreated,
    (SELECT count(DISTINCT deleted_team) FROM recreated WHERE same_key)
        AS deleted_teams_recreated_with_same_key,
    (SELECT count(DISTINCT later_team) FROM recreated WHERE same_key AND later_is_live)
        AS live_teams_recreated_with_same_key;
ROLLBACK;
