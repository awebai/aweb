-- Team room v1: independent of recipient mail/chat; retained history belongs
-- to the team. Juan approved future-member history on 2026-10-30 (coordinator
-- relay 351408ad-b317-4af3-ab13-696e856892f9). No identity-path changes.
CREATE TABLE {{tables.team_rooms}} (
    room_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id TEXT NOT NULL UNIQUE REFERENCES {{tables.teams}} (team_id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE {{tables.room_messages}} (
    message_id UUID PRIMARY KEY,
    room_id UUID NOT NULL REFERENCES {{tables.team_rooms}} (room_id) ON DELETE CASCADE,
    sequence BIGSERIAL NOT NULL UNIQUE,
    from_did TEXT NOT NULL,
    from_stable_id TEXT,
    from_agent_id UUID REFERENCES {{tables.agents}} (agent_id) ON DELETE SET NULL,
    signed_payload TEXT NOT NULL,
    signature TEXT NOT NULL,
    signing_key_id TEXT NOT NULL,
    id_chain JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX room_messages_room_sequence ON {{tables.room_messages}} (room_id, sequence);
