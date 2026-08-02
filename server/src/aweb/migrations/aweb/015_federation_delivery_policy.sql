-- Atomic federation delivery policy, receiver-wide replay history, and
-- identity-bound contacts. Existing address-only contacts intentionally remain
-- unbound until their owner explicitly accepts a current identity binding.

ALTER TABLE {{tables.contacts}}
    ADD COLUMN IF NOT EXISTS contact_did_aw TEXT,
    ADD COLUMN IF NOT EXISTS binding_controller_did TEXT,
    ADD COLUMN IF NOT EXISTS binding_accepted_at TIMESTAMPTZ;

ALTER TABLE {{tables.contacts}}
    ADD CONSTRAINT contacts_identity_binding_shape_valid
    CHECK (
        (reference_type <> 'identity' AND contact_did_aw IS NULL
         AND binding_controller_did IS NULL AND binding_accepted_at IS NULL)
        OR
        (reference_type = 'identity' AND (
            (contact_did_aw IS NULL AND binding_controller_did IS NULL
             AND binding_accepted_at IS NULL)
            OR (
                contact_did_aw IS NOT NULL
                AND binding_controller_did IS NOT NULL
                AND contact_did_aw LIKE 'did:aw:%'
                AND binding_controller_did LIKE 'did:key:z%'
                AND binding_accepted_at IS NOT NULL
            )
        ))
    );

CREATE INDEX IF NOT EXISTS idx_contacts_owner_address_did_active
    ON {{tables.contacts}} (owner_did, contact_address, contact_did_aw)
    WHERE reference_type = 'identity' AND status = 'active'
      AND contact_did_aw IS NOT NULL;

CREATE TABLE IF NOT EXISTS {{tables.message_ingress_receipts}} (
    message_id          UUID PRIMARY KEY,
    envelope_hash       TEXT CHECK (
        envelope_hash IS NULL OR envelope_hash ~ '^sha256:[0-9a-f]{64}$'
    ),
    canonical_metadata  JSONB NOT NULL DEFAULT '{}'::jsonb,
    storage_kind        TEXT NOT NULL CHECK (storage_kind IN ('mail', 'chat')),
    legacy_unreplayable BOOLEAN NOT NULL DEFAULT FALSE,
    established_result  JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (
        (legacy_unreplayable AND envelope_hash IS NULL)
        OR (NOT legacy_unreplayable AND envelope_hash IS NOT NULL)
    )
);

-- A historical UUID present in both stores is ambiguous replay authority.
-- Refuse activation rather than guessing or silently choosing one row.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM {{tables.messages}} m
        JOIN {{tables.chat_messages}} c ON c.message_id = m.message_id
    ) THEN
        RAISE EXCEPTION 'message_ingress_receipts backfill found a mail/chat message_id collision'
            USING ERRCODE = '23505';
    END IF;
END
$$;

INSERT INTO {{tables.message_ingress_receipts}} (
    message_id, storage_kind, legacy_unreplayable, created_at, updated_at
)
SELECT message_id, 'mail', TRUE, created_at, created_at
FROM {{tables.messages}}
ON CONFLICT (message_id) DO NOTHING;

INSERT INTO {{tables.message_ingress_receipts}} (
    message_id, storage_kind, legacy_unreplayable, created_at, updated_at
)
SELECT message_id, 'chat', TRUE, created_at, created_at
FROM {{tables.chat_messages}}
ON CONFLICT (message_id) DO NOTHING;

-- Every current and future local/federated write participates in receiver-wide
-- UUID authority in the same transaction as its message row. Federation Phase B
-- preclaims a reconstructable receipt; legacy/local paths receive a fail-closed
-- unreplayable receipt automatically.
CREATE OR REPLACE FUNCTION aweb.require_message_ingress_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_kind TEXT := TG_ARGV[0];
    existing_kind TEXT;
    existing_legacy BOOLEAN;
    existing_result JSONB;
BEGIN
    SELECT storage_kind, legacy_unreplayable, established_result
    INTO existing_kind, existing_legacy, existing_result
    FROM aweb.message_ingress_receipts
    WHERE message_id = NEW.message_id
    FOR UPDATE;

    IF existing_kind IS NULL THEN
        INSERT INTO aweb.message_ingress_receipts (
            message_id, storage_kind, legacy_unreplayable,
            created_at, updated_at
        ) VALUES (
            NEW.message_id, expected_kind, TRUE,
            COALESCE(NEW.created_at, clock_timestamp()),
            COALESCE(NEW.created_at, clock_timestamp())
        );
    ELSIF existing_kind <> expected_kind THEN
        RAISE EXCEPTION 'message_id already belongs to % storage', existing_kind
            USING ERRCODE = '23505';
    ELSIF existing_legacy OR existing_result IS NOT NULL THEN
        RAISE EXCEPTION 'message_id already claimed by % storage', existing_kind
            USING ERRCODE = '23505';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER trg_messages_require_ingress_receipt
    BEFORE INSERT ON {{tables.messages}}
    FOR EACH ROW
    EXECUTE FUNCTION aweb.require_message_ingress_receipt('mail');

CREATE TRIGGER trg_chat_messages_require_ingress_receipt
    BEFORE INSERT ON {{tables.chat_messages}}
    FOR EACH ROW
    EXECUTE FUNCTION aweb.require_message_ingress_receipt('chat');

CREATE TABLE IF NOT EXISTS {{tables.federation_mutation_outbox}} (
    outbox_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id      UUID NOT NULL REFERENCES {{tables.message_ingress_receipts}}(message_id)
                    ON DELETE RESTRICT,
    event_type      TEXT NOT NULL CHECK (
        event_type IN ('message.sent', 'chat.message_sent')
    ),
    payload_json    JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    delivered_at    TIMESTAMPTZ,
    attempt_count   INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error      TEXT
);

CREATE INDEX IF NOT EXISTS idx_federation_mutation_outbox_pending
    ON {{tables.federation_mutation_outbox}} (created_at, outbox_id)
    WHERE delivered_at IS NULL;
