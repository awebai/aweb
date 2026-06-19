-- Proposal minting (.14.6): a profile proposal carries the base it evolves from
-- (version + digest, from the agent's ref.json) so approve can reject-if-stale, plus
-- the proposed content (profile-payload.v1, in the existing content column) and
-- optional human-facing summary/rationale.

ALTER TABLE {{tables.proposals}}
    ADD COLUMN IF NOT EXISTS base_profile_version TEXT,
    ADD COLUMN IF NOT EXISTS base_profile_digest TEXT,
    ADD COLUMN IF NOT EXISTS summary TEXT,
    ADD COLUMN IF NOT EXISTS rationale TEXT;
