-- Approver sets: any one of an approval's candidates, frozen at mint, decides.
CREATE TABLE IF NOT EXISTS {{tables.approval_candidates}} (
    approval_id TEXT NOT NULL REFERENCES {{tables.approvals}}(approval_id),
    subject TEXT NOT NULL,
    scope TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    principal_did TEXT,
    position INTEGER NOT NULL,
    retired_at TIMESTAMPTZ,
    PRIMARY KEY (approval_id, subject),
    UNIQUE (approval_id, position)
);

CREATE INDEX IF NOT EXISTS idx_approval_candidates_active_subject
    ON {{tables.approval_candidates}}(subject) WHERE retired_at IS NULL;

-- The decider replaces the single designated approver.
ALTER TABLE {{tables.approvals}}
    DROP COLUMN approver_subject,
    DROP COLUMN approver_subject_type,
    ADD COLUMN decided_scope TEXT,
    ADD COLUMN decided_subject TEXT,
    ADD CHECK ((decided_subject IS NULL) = (decided_at IS NULL)),
    ADD CHECK ((decided_scope IS NULL) = (decided_at IS NULL)),
    ADD CHECK ((authenticator IS NULL) = (decided_at IS NULL)),
    ADD CHECK ((auth_evidence_ref IS NULL) = (decided_at IS NULL)),
    ADD FOREIGN KEY (approval_id, decided_subject)
        REFERENCES {{tables.approval_candidates}}(approval_id, subject);

CREATE INDEX IF NOT EXISTS idx_approvals_decided_subject
    ON {{tables.approvals}}(decided_subject) WHERE decided_subject IS NOT NULL;

-- One single-use link per candidate, each with its own verifier.
ALTER TABLE {{tables.approval_links}}
    DROP CONSTRAINT approval_links_approval_id_key,
    ADD COLUMN candidate_subject TEXT NOT NULL,
    ADD UNIQUE (approval_id, candidate_subject),
    ADD FOREIGN KEY (approval_id, candidate_subject)
        REFERENCES {{tables.approval_candidates}}(approval_id, subject);
