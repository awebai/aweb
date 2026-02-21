-- Rotation announcement storage and per-peer delivery tracking

CREATE TABLE IF NOT EXISTS {{tables.rotation_announcements}} (
    announcement_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    project_id UUID NOT NULL,
    old_did TEXT NOT NULL,
    new_did TEXT NOT NULL,
    rotation_timestamp TEXT NOT NULL,
    old_key_signature TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rotation_announcements_agent
  ON {{tables.rotation_announcements}} (agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS {{tables.rotation_peer_acks}} (
    announcement_id UUID NOT NULL REFERENCES {{tables.rotation_announcements}}(announcement_id),
    peer_agent_id UUID NOT NULL REFERENCES {{tables.agents}}(agent_id),
    notified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    PRIMARY KEY (announcement_id, peer_agent_id)
);
