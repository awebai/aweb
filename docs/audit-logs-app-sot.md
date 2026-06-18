---
title: "Audit ledger and logs app"
kicker: "Product SOT"
description: "How core audit facts, logs.aweb.ai, and self-hosted audit apps compose."
weight: 29
---

# Audit ledger and logs app

This is the source of truth for the signed audit/logs product boundary.

The product promise:

> Aweb keeps a tamper-evident signed audit trail of Aweb-mediated agent work and
> app access. Customers can view it in aweb.ai, export it, or self-host their own
> audit/logs app while using hosted Aweb core.

## 1. Boundary

Core owns audit **facts**. `logs.aweb.ai` owns audit **views, retention, export,
search, and compliance workflows**.

Audit facts are emitted at the Aweb authority boundary:

- team-auth request verification;
- app-emitted event verification;
- app/tool dispatch through gateway or `aw`;
- identity/team/certificate changes;
- app install/grant changes;
- messages, tasks, approvals, and app actions;
- `aw do` and secret-mediated execution.

Do not claim audit coverage for arbitrary filesystem edits, raw shell commands,
browser clicks, or model reasoning unless they go through an Aweb-controlled
tool.

## 2. Repo and OSS stance

`logs.aweb.ai` should be a separate app repo, not part of the core `aweb` repo.

The audit/logs app should have an OSS/self-hostable core because customers may
need to own their compliance archive, retention policy, and legal export path.
Hosted aweb.ai can run a managed version with commercial retention, search,
support, and compliance features.

The `aweb` repo should contain the core audit ledger contract, schemas,
verification helpers, conformance vectors, and reference fixtures. It should not
become the product repo for every first-party app.

## 3. Core audit ledger

Core needs a durable team audit ledger. The existing `aweb.audit_log` table is
not enough as-is: it is generic, not hash-chained, not signed, effectively
unused, and deleted during team GC.

Minimum event shape:

```text
event_id
team_id
team_seq
prev_event_hash
event_hash
created_at

event_type
actor_agent_id
actor_alias
actor_did_aw
actor_did_key
human_principal_id        optional
custodial_grant_id        optional

app_id                    optional
operation
target_type
target_ref

authority_mode            team_cert | app_emit_key | dashboard_jwt | oauth_connector | system
certificate_id            optional
app_emit_key_id           optional
approval_id               optional
granted_scopes_snapshot   optional

request_method            optional
request_path              optional
request_body_sha256       optional
signed_payload_hash       optional
signature_hash            optional
signing_key_id            optional

result_status             success | denied | failed
result_ref
summary_json              redacted
payload_hash              optional
server_signature
```

The ledger should store enough evidence to prove what Aweb verified and what
state change/result followed, without leaking secrets or encrypted plaintext.

## 4. Self-hosted audit app with hosted core

A customer should be able to self-host `logs.aweb.ai` while using hosted Aweb
core for identity, teams, app grants, tasks, and other apps.

Target architecture:

```text
hosted aweb core
  writes signed/hash-chained team audit events
  exposes scoped audit export/read API
  grants audit app access to that feed
self-hosted logs app
  pulls events
  verifies server signature and team hash chain
  stores local immutable/archive copy
  renders search, reports, and export
```

This is **not fully implemented today**. Existing app manifests, app origins,
app grants, and app emits make self-hosted apps plausible, but the audit export
contract is still missing.

## 5. Export/feed contract

V1 should prefer pull:

```http
GET /v1/audit/events?team_id=<team>&since_seq=<n>&limit=<n>
```

Authorization:

- direct team-auth for local/self-hosted clients; or
- hosted gateway/internal auth acting for an installed audit app; and
- an installed audit/logs app grant such as `audit:read`.

Response:

```json
{
  "team_id": "default:aweb.ai",
  "events": [
    {
      "team_seq": 42,
      "event_id": "uuid",
      "event_hash": "sha256:...",
      "prev_event_hash": "sha256:...",
      "server_signature": "...",
      "event": {}
    }
  ],
  "next_since_seq": 43,
  "checkpoint": {
    "team_seq": 42,
    "event_hash": "sha256:...",
    "created_at": "2026-06-18T00:00:00Z"
  }
}
```

Webhook push can come later, after pull verification and replay semantics are
stable.

## 6. Launch scope

Launch should prove:

- the workroom can render audit events for the demo path;
- audit events distinguish Aweb-mediated facts from agent-reported activity;
- audit records are redacted and safe for secrets/encrypted data;
- the architecture and tasks explicitly support future self-hosted
  `logs.aweb.ai` using hosted core.

Launch does not need:

- full self-hosted logs app implementation;
- webhook push;
- external timestamping/notarization;
- long-retention compliance archive;
- legal-grade exports beyond a credible event record.

## 7. Future hardening

Later work should add:

- periodic signed checkpoints;
- external timestamp anchoring;
- customer-controlled storage backends;
- WORM/archive integrations;
- SIEM export;
- data retention policies;
- per-app audit scopes;
- webhook push with retry/dedup;
- audit event verification CLI.
