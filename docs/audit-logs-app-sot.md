---
title: "Audit ledger and logs app"
kicker: "Product SOT"
description: "How the team audit ledger, the aw hook substrate, and logs.aweb.ai compose into the user's tamper-evident, verifiable record of what their agents did — emitted by agents, but owned and inspected only by the human."
weight: 29
---

# Audit ledger and logs app

This is the source of truth for the signed audit/logs product boundary. It builds
on `aw-hooks-sot` (the hook substrate) and pairs with `secrets-aw-do-sot` (the
enforcement that makes important actions un-skippable).

The product promise:

> `logs.aweb.ai` is the **user's own** tamper-evident, verifiable record of what
> their team of agents did. Agents **emit** to it, but cannot read, edit, or
> delete it — it is the user's record *of* the agents, not the agents' record of
> themselves. View it in aweb.ai, export it, or self-host it.

## 1. What "what their agents do" means — the boundary of agency

The auditable record is the set of **effectful, attributable actions that cross a
trust boundary** — into shared team state, to another agent, to an external
service, or to a resource the user cares about (data, money, secrets, deploys).
Each entry: which agent (signed identity), what action, on what target, when, in
what order, under what authorization, and the outcome.

Four categories the user actually cares about:

- **coordination** — membership, who is working on what, who said what to whom;
- **work effects** — what was produced/changed/deployed;
- **resource use** — money / secrets / data / external services touched, under
  what authority;
- **governance** — approvals, grants, identity/membership changes, denials.

Explicitly **out**: the agent's internal reasoning (that is the transcript,
available on demand, not the default audit) and purely-private local ops with no
shared effect. The line is clean: **audit = the crossing of agency boundaries.**
What an agent *thinks* is private; the moment it *acts on anything*, it is audited.

Be honest about the boundary: do not claim audit of arbitrary filesystem edits,
raw shell commands run outside `aw`, browser clicks, or model reasoning. Aweb can
show agent-*reported* activity, but that is not signed audit unless it crossed an
Aweb authority surface (a server mediation point) or a non-bypassable `aw` path.

## 2. The audit event lifecycle

One action produces one log entry, at the point of effect (see the no-duplicate
rule, `aw-hooks-sot` §3–4). There is **no core audit ledger** — the record lives
in `logs`, in its own db:

```text
1. action effected at one layer (aw for local-only; a server for server effects)
2. that layer builds the canonical, REDACTED event and PROVENANCE-signs it
     (effecting server signs with its key; aw signs with the agent cert)
3. it fires the relevant hook -> durable at-least-once delivery to logs.ingest
4. logs verifies the provenance signature, assigns team_seq, hash-chains, and
     stores in ITS OWN db; counter-signs checkpoints
```

`logs` owns the durable, ordered, verifiable record **end to end** — core stores
no audit events. An effecting naapp may keep its own operational record (e.g.
`secrets` records what it brokered, in its db), but the audit log is `logs`'.

### Two-layer integrity

- **Provenance signature** (the producer) — proves *who emitted* each event.
- **Hash chain** (the ledger / `logs`) — `team_seq` + `prev_event_hash` +
  `event_hash` prove *no event was dropped or reordered*.

A verifier checks both. `logs` counter-signs periodic checkpoints (a signed
chain-head root) so a whole range verifies in O(1) against a checkpoint, and so
the record can be externally anchored later.

## 3. Event shape (stored by `logs`)

The legacy core `aweb.audit_log` table is unused and **not part of this design** —
`logs` owns its store. The event `logs` stores and hash-chains in its own db:

```text
event_id                  stable, idempotency key
team_id
team_seq                  monotonic per team
trace_id                  correlates the sub-effects of one command
prev_event_hash
event_hash
created_at

event_type                e.g. membership.added | task.claimed | secret.used
actor_agent_id
actor_alias
actor_did_aw
actor_did_key
human_principal_id        optional (who authorized a connector/approval)
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
summary_json              redacted    (refs, never secret values or plaintext)
payload_hash              optional
server_signature
```

The ledger stores enough to prove what Aweb verified and what change/result
followed, without leaking secrets or encrypted plaintext.

## 4. logs.aweb.ai — the consumer

Tools (`aw logs <verb>`):

- `logs.ingest` — the hook/subscription sink (push from the effecting layer or
  pull from the export feed); verifies the provenance signature; appends to the
  chain; **not agent-callable**.
- `logs.query` (`logs:read`, owner / human-principal) — by actor / time / type /
  resource / mission.
- `logs.verify` — recompute the chain + provenance signatures over a range or
  against a checkpoint; returns "intact / broken at seq N". The *verifiable*
  promise.
- `logs.checkpoint` — emit/fetch a signed chain-head root.

Trust spine:

1. **Append-only — no edit/delete API at all.** Retention is a policy the *owner*
   sets, never an agent action.
2. **Owner-gated reads.** An agent cannot read others' events and cannot read the
   full log; it cannot scrub its own trail. The record belongs to the team
   owner / human principal.
3. **Redaction at the producer** — secrets appear as refs, never values.
4. **Completeness is structural** for mediated actions (the hook fires at the
   boundary) and **honest** about the raw-local boundary (§1).

`aw` surface: `aw logs query`, `aw logs verify`, `aw logs tail` — all owner /
human-principal gated. `tail` is the live oversight view (the monitoring sibling
of audit).

## 5. Repo and OSS stance

`logs.aweb.ai` is a **separate app repo**, not part of core `aweb`, with an
OSS/self-hostable core (customers may need to own their compliance archive). The
`aweb` repo holds only the cross-app contracts — the hook catalog, the event/
payload schema, verification helpers, and conformance vectors — **not** a core
audit store and not the product repo for every app.

A customer can self-host `logs.aweb.ai` while using hosted Aweb core. Because core
stores no audit, self-hosting is just **registering the self-hosted logs URL as
the hook target**: the hosted core's and naapps' mediation points fire their hooks
and deliver signed events directly to the customer's logs instance. Nothing is
pulled from a core audit store, because there is none.

```text
hosted aweb core / naapps
  fire hooks at the point of effect -> durable delivery of signed events to the
  registered logs target (hosted, or the customer's self-hosted URL)
self-hosted logs app
  receives, verifies the provenance signature, hash-chains, stores its immutable
  archive in its own db, renders search/reports/export
```

The only thing a self-hosted `logs` needs from outside its own scope is to be a
registered hook target. No core export feed, no core audit table.

## 6. Why this is the user's record, not the agents'

The composition with secrets is the point: `secrets.aweb.ai` makes important
actions only-doable-through-the-broker (the raw credential is removed from the
agent's reach), the broker fires the hook server-side, and `logs` records it —
signed, ordered, attributable, and **owned by the user**. The agent cannot avoid
emitting (no other path to act), cannot read others' entries, and cannot delete
its own. That is "logged regardless of agent preference," by construction.

## 7. Launch scope

Prove:

- the hook emits signed events for the demo-critical actions — membership, task
  lifecycle, mail/chat, approvals, **and `secret.used`** (the link to secrets);
- `logs` stores hash-chained signed events;
- `aw logs query` shows the team's activity and `aw logs verify` proves the chain
  intact — "inspect the visible signed record";
- audit distinguishes Aweb-mediated facts from agent-reported activity;
- records are redacted and safe for secrets/encrypted data;
- the architecture supports future self-hosted `logs.aweb.ai` on hosted core.

Do not block launch on: full self-hosted logs app, webhook push, external
timestamping/notarization, long-retention archive, per-app audit scopes, legal-
grade exports.

## 8. Future hardening

Periodic external timestamp anchoring; customer-controlled storage / WORM; SIEM
export; retention policy UI; per-app audit scopes; webhook push with retry/dedup;
richer leak-detection redaction; cross-server federation of the log.

## 9. Self-contained

`logs.aweb.ai` manages everything in its own db — the signed, hash-chained record,
checkpoints, queries, retention. It receives events solely via the **aw hook** (it
registers as a target); it pulls nothing from core and stores nothing in core. Its
one external touch is the same **identity layer** (awid) used to verify event
provenance signatures and to gate owner / human-principal reads — the shared naapp
trust root, not the aweb app server. Everything else is `logs`'.
