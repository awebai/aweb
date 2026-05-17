-- 002_namespace_delivery_origin.sql
-- Messaging-only federation delivery metadata. A namespace may declare the
-- default aweb origin that receives mail/chat for addresses under that domain.

ALTER TABLE {{tables.dns_namespaces}}
    ADD COLUMN IF NOT EXISTS default_delivery_origin TEXT;
