-- Keep revoked IDs as tombstones and link safe, atomic renewal replacements.
ALTER TABLE {{tables.team_certificates}}
    ADD COLUMN replaced_by_certificate_id TEXT,
    ADD CONSTRAINT certificate_replacement_same_team
        FOREIGN KEY (team_uuid, replaced_by_certificate_id)
        REFERENCES {{tables.team_certificates}} (team_uuid, certificate_id);
