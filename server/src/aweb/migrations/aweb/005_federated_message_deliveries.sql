-- Durable idempotency keys for inbound federated mail/chat delivery.

CREATE TABLE IF NOT EXISTS {{tables.federated_message_deliveries}} (
    message_type    TEXT NOT NULL
                    CHECK (message_type IN ('mail', 'chat')),
    sender_did_aw   TEXT NOT NULL,
    target_did_aw   TEXT NOT NULL,
    message_id      UUID NOT NULL,
    conversation_id UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (message_type, sender_did_aw, target_did_aw, message_id)
);
