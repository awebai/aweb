-- Explicit authority roles; released team-controller rows retain their default.
-- Nullable domain preserves existing internal team provisioning writers;
-- readers derive only those legacy team domains from the canonical team ID.
ALTER TABLE {{tables.protected_authorizer_bindings}}
    ADD COLUMN authority_kind TEXT NOT NULL DEFAULT 'team_controller'
        CHECK (authority_kind IN ('team_controller','namespace_controller','human_identity'));
ALTER TABLE {{tables.protected_authorizer_bindings}} ADD COLUMN authority_domain TEXT;
UPDATE {{tables.protected_authorizer_bindings}}
    SET authority_domain=split_part(team_id,':',2) WHERE authority_kind='team_controller';
ALTER TABLE {{tables.protected_authorizer_bindings}}
    DROP CONSTRAINT protected_authorizer_bindings_pkey;
ALTER TABLE {{tables.protected_authorizer_bindings}}
    ADD PRIMARY KEY (service_id,authority_kind,team_id,human_id,human_domain);
