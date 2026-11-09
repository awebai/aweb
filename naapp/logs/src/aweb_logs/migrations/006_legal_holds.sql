-- Each team's legal holds (audit-substrate.md §B6). An active hold (no
-- released_at) keeps retention and erasure from purging what it holds: every
-- event (hold_scope 'all') or one actor's (hold_scope 'actor', actor_ref its
-- did:aw or did:key). A hold id is set once; set_event_id and
-- released_event_id name the governance events that recorded the owner acts.
CREATE TABLE IF NOT EXISTS {{tables.legal_holds}} (
    team_id           TEXT NOT NULL,
    hold_id           TEXT NOT NULL,
    hold_scope        TEXT NOT NULL CHECK (hold_scope IN ('all', 'actor')),
    actor_ref         TEXT,
    set_event_id      UUID NOT NULL,
    set_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_event_id UUID,
    released_at       TIMESTAMPTZ,
    PRIMARY KEY (team_id, hold_id),
    CHECK ((hold_scope = 'actor') = (actor_ref IS NOT NULL)),
    CHECK ((released_at IS NULL) = (released_event_id IS NULL))
);
