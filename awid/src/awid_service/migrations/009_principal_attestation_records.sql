-- 009_principal_attestation_records.sql
-- Team-key-signed records for principal attestation (docs/principal-attestation.md)
-- and the member person declaration (docs/member-person.md). Each row stores the
-- record's canonical JSON and signature exactly as published. Records go with
-- their certificate or team: deleting either deletes them.

CREATE TABLE IF NOT EXISTS {{tables.team_custodians}} (
    team_uuid       UUID NOT NULL REFERENCES {{tables.teams}}(team_uuid) ON DELETE CASCADE,
    custodian_id    TEXT NOT NULL,
    record_json     TEXT NOT NULL,
    signature       TEXT NOT NULL,
    team_did_key    TEXT NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (team_uuid, custodian_id)
);

CREATE TABLE IF NOT EXISTS {{tables.member_custody}} (
    team_uuid       UUID NOT NULL,
    certificate_id  TEXT NOT NULL,
    custodian_id    TEXT NOT NULL,
    record_json     TEXT NOT NULL,
    signature       TEXT NOT NULL,
    team_did_key    TEXT NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (team_uuid, certificate_id),
    FOREIGN KEY (team_uuid, certificate_id)
        REFERENCES {{tables.team_certificates}}(team_uuid, certificate_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS {{tables.member_person}} (
    team_uuid       UUID NOT NULL,
    certificate_id  TEXT NOT NULL,
    single_person   BOOLEAN NOT NULL,
    record_json     TEXT NOT NULL,
    signature       TEXT NOT NULL,
    team_did_key    TEXT NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (team_uuid, certificate_id),
    FOREIGN KEY (team_uuid, certificate_id)
        REFERENCES {{tables.team_certificates}}(team_uuid, certificate_id) ON DELETE CASCADE
);
