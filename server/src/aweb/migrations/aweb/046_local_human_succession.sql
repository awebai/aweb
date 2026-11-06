-- Same-account custodial human succession, authorized by coordinator 1615e381
-- and narrowed by Athena 72129230 / coordinator badab27d (2026-11-04).
-- Trusted hosted code supplies the account/custody proof; no public writer.
CREATE TABLE {{tables.local_human_successions}} (
    predecessor_did TEXT PRIMARY KEY,
    predecessor_did_key TEXT NOT NULL,
    successor_did TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (predecessor_did <> successor_did),
    CHECK (predecessor_did_key LIKE 'did:key:%'),
    CHECK (successor_did LIKE 'did:aw:%')
);

-- Target and historical-attribution evidence applies only to these old mail
-- threads, never to first contact or another thread with the same successor.
CREATE TABLE {{tables.conversation_participant_successions}} (
    conversation_id UUID NOT NULL REFERENCES {{tables.conversations}}(conversation_id) ON DELETE CASCADE,
    predecessor_did TEXT NOT NULL REFERENCES {{tables.local_human_successions}}(predecessor_did),
    predecessor_alias TEXT NOT NULL,
    PRIMARY KEY (conversation_id, predecessor_did)
);
