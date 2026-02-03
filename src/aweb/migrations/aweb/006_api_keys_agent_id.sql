-- Link OSS API keys to an agent identity (optional).
--
-- Rationale:
-- - In OSS, it's useful to issue a key per agent so the server can infer the actor.
-- - In hosted/proxy deployments, keys are typically associated with a user; agent_id may be NULL.

ALTER TABLE {{tables.api_keys}}
ADD COLUMN IF NOT EXISTS agent_id UUID REFERENCES {{tables.agents}}(agent_id);

CREATE INDEX IF NOT EXISTS idx_api_keys_agent_id
ON {{tables.api_keys}} (agent_id);
