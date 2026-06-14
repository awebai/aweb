# folio agent instructions

`folio` is an OSS service for AWID-authenticated agent teams to share plain text with append-only versions.

Read first:

1. `docs/sot.md` — product, auth, data, and API source of truth.
2. `README.md` — local run commands.
3. `src/folio/auth.py` — BYOIDT team-certificate auth boundary.
4. `src/folio/migrations/001_initial.sql` — canonical v1 schema.

Core invariants:

- AWID is authority for team public keys, certificates, and revocation.
- `folio` never stores namespace-controller or team-controller private keys.
- Every document endpoint is scoped to the verified certificate `team_id`.
- Versions are append-only. Edits create new versions.
- Store minimal operational projections only: observed team, observed agent, documents, versions.
- Text in `folio` is server-readable. Do not call it E2E encrypted.

Development notes:

- Use `pgdbm` for PostgreSQL access and migrations.
- Deployed migrations are immutable; recovery is a forward migration.
- Prefer small tests around auth interop and team scoping before adding features.
- Keep v1 boring: no rich text, branches, comments, CRDTs, public sharing, or document-level ACLs unless Juan explicitly changes scope.
