-- Public native prepared-send embedding: message, ingress result and mutation
-- intent commit together. Keys are scoped to authenticated principals, never
-- platform accounts. Durable ID bindings survive route/preparation loss.
CREATE TABLE {{tables.human_channel_sends}} (
    message_id UUID PRIMARY KEY,
    issuer TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    accepted JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE {{tables.human_channel_ingress}} (
    issuer TEXT NOT NULL,
    namespace TEXT NOT NULL,
    ingress_key TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    result JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, namespace, ingress_key)
);
CREATE TABLE {{tables.human_channel_mutations}} (
    mutation_id UUID PRIMARY KEY,
    message_id UUID NOT NULL REFERENCES {{tables.human_channel_sends}}(message_id),
    event_type TEXT NOT NULL CHECK (event_type IN ('message.sent','chat.message_sent')),
    context JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ
);
CREATE INDEX ON {{tables.human_channel_mutations}} (created_at,mutation_id)
    WHERE published_at IS NULL;
