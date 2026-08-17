-- 017_agents_certificate_id.sql
-- Record which team certificate admitted each agent projection (aweb-abfn).
--
-- Identity-only messaging auth derives team context from this projection by
-- key possession alone; without the admitting certificate recorded there is
-- nothing to check against the registry's revocations, so a revoked member
-- whose projection survived kept its team context indefinitely. The column is
-- nullable: rows created before this migration have no recorded certificate
-- and heal at their next certificate-authenticated connect or request.

ALTER TABLE {{tables.agents}}
    ADD COLUMN IF NOT EXISTS certificate_id TEXT;
