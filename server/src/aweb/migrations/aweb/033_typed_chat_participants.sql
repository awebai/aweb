-- P3 identity/storage foundation. Juan's full build authorization: 2026-10-21,
-- integrations 41221f08; decided pairwise subjects, no guest native principals.
-- The P5 gates intentionally refuse every bridged row until signed membership,
-- J9 consent, confidentiality labels and published consumer refusal are ready.
-- Only a later reviewed P5 migration may remove those gates.

ALTER TABLE {{tables.chat_participants}}
    ADD COLUMN participant_id UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN participant_kind TEXT NOT NULL DEFAULT 'native',
    ADD COLUMN bridge_did TEXT,
    ADD COLUMN guest_subject TEXT,
    ADD COLUMN guest_opted_out_at TIMESTAMPTZ,
    ADD CONSTRAINT chat_participants_native_did_unique UNIQUE (session_id, did);

-- Retain the native lookup/ON CONFLICT target and native exact-read FK. The
-- original FK depends on the old PK, so reattach it to the retained native
-- unique constraint in this same transaction; no committed boundary loses it.
ALTER TABLE {{tables.chat_message_reads}} DROP CONSTRAINT chat_message_reads_session_id_did_fkey;
ALTER TABLE {{tables.chat_participants}} DROP CONSTRAINT chat_participants_pkey;
ALTER TABLE {{tables.chat_participants}}
    ALTER COLUMN did DROP NOT NULL,
    ADD PRIMARY KEY (session_id, participant_id),
    ADD CONSTRAINT chat_participants_reference_shape CHECK (
        (participant_kind = 'native' AND did IS NOT NULL
         AND bridge_did IS NULL AND guest_subject IS NULL AND guest_opted_out_at IS NULL)
        OR
        (participant_kind = 'bridged' AND did IS NULL AND agent_id IS NULL
         AND address IS NULL AND delivery_origin IS NULL AND current_did_key IS NULL
         AND bridge_did IS NOT NULL AND bridge_did ~ '^did:aw:[A-Za-z0-9._:-]+$'
         AND guest_subject IS NOT NULL AND length(guest_subject) BETWEEN 1 AND 256
         AND guest_subject ~ '^[A-Za-z0-9._:-]+$'
         AND guest_subject NOT LIKE 'did:%')
    ),
    ADD CONSTRAINT chat_participants_p5_gate CHECK (participant_kind = 'native');

CREATE UNIQUE INDEX chat_participants_bridged_ref_unique
    ON {{tables.chat_participants}} (session_id, bridge_did, guest_subject)
    WHERE participant_kind = 'bridged';

ALTER TABLE {{tables.chat_message_reads}}
    ADD CONSTRAINT chat_message_reads_session_id_did_fkey
    FOREIGN KEY (session_id, did) REFERENCES {{tables.chat_participants}} (session_id, did)
    ON DELETE CASCADE;

ALTER TABLE {{tables.conversation_participants}}
    ADD COLUMN participant_id UUID NOT NULL DEFAULT gen_random_uuid(),
    ADD COLUMN participant_kind TEXT NOT NULL DEFAULT 'native',
    ADD COLUMN bridge_did TEXT,
    ADD COLUMN guest_subject TEXT,
    ADD COLUMN guest_opted_out_at TIMESTAMPTZ,
    ADD CONSTRAINT conversation_participants_native_did_unique UNIQUE (conversation_id, did);

ALTER TABLE {{tables.conversation_participants}} DROP CONSTRAINT conversation_participants_pkey;
ALTER TABLE {{tables.conversation_participants}}
    ALTER COLUMN did DROP NOT NULL,
    ADD PRIMARY KEY (conversation_id, participant_id),
    ADD CONSTRAINT conversation_participants_reference_shape CHECK (
        (participant_kind = 'native' AND did IS NOT NULL
         AND bridge_did IS NULL AND guest_subject IS NULL AND guest_opted_out_at IS NULL)
        OR
        (participant_kind = 'bridged' AND did IS NULL AND agent_id IS NULL
         AND address IS NULL AND delivery_origin IS NULL AND current_did_key IS NULL
         AND transport_hint IS NOT NULL AND transport_hint = 'chat' AND role = 'participant'
         AND bridge_did IS NOT NULL AND bridge_did ~ '^did:aw:[A-Za-z0-9._:-]+$'
         AND guest_subject IS NOT NULL AND length(guest_subject) BETWEEN 1 AND 256
         AND guest_subject ~ '^[A-Za-z0-9._:-]+$'
         AND guest_subject NOT LIKE 'did:%')
    ),
    ADD CONSTRAINT conversation_participants_p5_gate CHECK (participant_kind = 'native');

CREATE UNIQUE INDEX conversation_participants_bridged_ref_unique
    ON {{tables.conversation_participants}} (conversation_id, bridge_did, guest_subject)
    WHERE participant_kind = 'bridged';
