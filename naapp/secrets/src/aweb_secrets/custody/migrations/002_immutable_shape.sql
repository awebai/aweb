-- Bind even an inert first-create draft to its value interpretation and
-- placement. A zero-version row pins a confirmed record without claiming any
-- value has been sealed; the same unique key serializes initial ingest/create.
ALTER TABLE {{tables.custody_secrets}}
    DROP CONSTRAINT custody_secrets_last_version_check;
ALTER TABLE {{tables.custody_secrets}}
    ADD CONSTRAINT custody_secrets_last_version_check CHECK (last_version >= 0),
    ADD COLUMN immutable_shape JSONB;

-- Existing parent records identify their current interpretation. Orphaned old
-- drafts have no recoverable shape; leave those NULL so they fail closed.
UPDATE {{tables.custody_secrets}} AS custody
SET immutable_shape = jsonb_build_object(
    'kind', secret.record->'kind',
    'backend', secret.record->'backend',
    'kind_params', CASE WHEN secret.record->>'kind' = 'oauth2-client-credentials'
                       THEN (secret.record->'kind_params') - 'scope'
                       ELSE secret.record->'kind_params' END
)
FROM {{tables.secrets}} AS secret
WHERE (custody.installation_id, custody.team_id, custody.secret_id) =
      (secret.installation_id, secret.team_id, secret.secret_id);
