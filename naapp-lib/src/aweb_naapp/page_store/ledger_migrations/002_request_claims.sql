-- Request bytes/hash/receipt are owned by the shared idempotency primitive.
-- This index adds only page ownership and the content generation of admission.
CREATE TABLE {{tables.page_request_claims}} (
    key TEXT[] PRIMARY KEY REFERENCES {{tables.idempotency_keys}}(key),
    scope TEXT[] NOT NULL,
    content_generation UUID NOT NULL
);
CREATE INDEX page_request_claims_scope ON {{tables.page_request_claims}}(scope);
