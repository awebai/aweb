---
title: "aw hooks: named extension points"
kicker: "Product SOT"
description: "Emacs-style named hooks in aw and at server mediation points: how naapps register callbacks via their manifest, how hooks fire exactly once at the point of effect, and the canonical payloads. This is the substrate logs.aweb.ai and policy apps consume."
weight: 27
---

# aw hooks: named extension points

This is the source of truth for the `aw` hook mechanism. It is the substrate the
`secrets.aweb.ai` and `logs.aweb.ai` SOTs depend on. `logs.aweb.ai` is the first
consumer; the mechanism is general.

The concept, in one line:

> `aw` and Aweb mediation points offer **named hooks**, the way Emacs does. A hook
> is a named extension point holding a list of **registered targets** (manifest
> tools / URIs). When the hook fires, each registered target is called with the
> hook's **canonical payload**. A naapp registers a target by declaring it in its
> manifest. `logs.aweb.ai` registers on the relevant hooks and is then called
> automatically — `aw`/the server never needs to know `logs` exists.

## 1. Why hooks, not the app-event channel

The existing app-event channel (`POST /v1/events/app`, folio `doc.changed`,
`app_event_subscriptions`) is a **wake** mechanism: an app emits a notification so
that interested **agents** are woken to react (`delivery_intent: wake/steer/
ambient`). It is opt-in and its consumers are agents.

Hooks are a different concern: a **guaranteed extension point** fired as a side
effect of an action existing, whose consumers are **apps** (logs, policy,
metrics), for the purpose of **recording or governing**, not waking. Do not
conflate them. They may share the signed-envelope transport underneath, but they
are separate streams with separate guarantees. An app event can be *one* input a
consumer also captures, but it is opt-in and cannot be relied on for completeness.

## 2. Registration (manifest `hooks`)

Any installed naapp's manifest declares the hooks it registers on. This is the
`add-hook` of the system.

Add a manifest field (distinct from the existing `events`/`event_emitters`, which
are wake-emission, not hook-registration):

```json
"hooks": [
  {
    "hook": "post-secret-use-hook",
    "tool": "logs.ingest",
    "scopes": ["logs:ingest"]
  },
  {
    "hook": "post-manifest-command-hook",
    "tool": "logs.ingest"
  }
]
```

- Registration is **owner-gated**: a hook target exists only because the team
  owner installed that app and its manifest registers it. **Agents cannot
  register hook targets.** This matters because a hook target receives the
  canonical payload — an arbitrary agent-registered target would be an
  exfiltration channel.
- A hook may have **many** registered targets (logs + a metrics app + a policy
  app); each is called.

## 3. The firing rule — fire at the point of effect, exactly once

This is the rule that prevents duplicate logs.

> A hook fires at the layer that **effects** the action — never at the layer that
> merely **requests** it — and fires there exactly once.

- An action a **server** effects (a broker call, a membership mutation, an app
  command) → the **server** fires the hook. `aw` does **not** — it only
  dispatched.
- An action effected **purely locally** (no server) → **`aw`** fires.

These two classes are **disjoint** (an action either reaches a server or it does
not), so no single action ever fires from two places. The client/server split is
a **partition**, not redundant double-firing:

- `aw do STRIPE_KEY ...` → the charge happens on the secrets server → the secrets
  server fires `post-secret-use-hook` once. `aw` does not fire. Non-bypassable and
  single-entry.
- `aw <local inspect>` → effected in `aw` → `aw` fires `post-command-hook` once.
  Cooperative (bypassable, see §7) and single-entry.

### Trust consequence

`aw`-fired (client) hooks are **bypassable**: the agent controls its own `aw`
(patched binary, or calling a URI directly without `aw`). They are the right layer
for the cooperative/local/general case. The **audit guarantee** — "logged
regardless of agent preference" — comes from the **server-side** firing at
mediation points **plus** secrets-gating: an important action can only be done
through the server broker (the agent holds no raw credential), the server fires the
hook, and the agent cannot skip it. The guarantee lives in server-side firing +
secrets-gating; client hooks are the extensible layer on top.

## 4. No repeated logs — correlation and idempotency

Point-of-effect single-firing prevents the same action firing twice. Two backstops
cover the rest:

- **One command, several effects is normal, not duplication.** `aw team add`
  mints a cert (server effect), materializes a home (local effect), maybe fetches
  a profile (library server effect) — three distinct auditable effects, three
  entries. Thread a **`trace_id`** (one per user command) so consumers can *group*
  them under the command, rather than collapse them.
- **Every event carries a stable `event_id` (idempotency key)** derived from the
  action, so retries and at-least-once delivery **dedupe**. Consumers are
  idempotent on `event_id`.

Consumers (logs) subscribe to the **hook stream only**, never *also* to the
wake/app-event stream — subscribing to both is the other way to double-log.

## 5. The hook catalog (v1)

Each named hook has exactly one firing site and a canonical, redacted payload.
Common payload fields: `event_id`, `trace_id`, `team_id`, `actor` (agent id +
`did`), `fired_at`, `result_status`. Hook-specific fields below.

| Hook | Firing site | Canonical payload (beyond common) |
|------|-------------|-----------------------------------|
| `post-command-hook` | `aw` (client) — local-only commands | `command`, `args` (redacted), `cwd`, `result_ref` |
| `post-manifest-command-hook` | the naapp **server** serving the tool | `app_id`, `tool`, `params` (redacted), `request_hash`, `result_ref` |
| `post-secret-use-hook` | `secrets` **server** (the broker) | `secret_ref` (**never value**), `action`, `target_host`/`operation`, `request_hash`, `approval_id`, `result_status` |
| `post-mutation-hook` | core **server** | `mutation_type` (membership / task / mail / chat / grant / approval), `target_ref`, `authority_mode`, before/after refs |
| `pre-command-hook` | `aw` / server — **future, blocking** | proposed `command`/`tool` + `params`; target returns allow/deny (governance) |

The catalog is versioned; adding a hook or changing a payload is a contract
change (and, where it crosses the conformance suite, a coordinated landing).

## 6. Observing vs blocking

- **v1 hooks observe** (`post-*`): fire-and-forget, cannot change or abort the
  action. `logs` is an observing consumer.
- **Blocking hooks** (`pre-*`) that return allow/deny — a policy/guard app like a
  git pre-commit — are a **future governance axis**, not launch. Decide their
  semantics (fail-open vs fail-closed on a slow/absent guard) when introduced.

## 7. Reliability and the failure mode

The audit record lives in the consuming naapp (`logs`), in its own db — **there is
no core audit ledger.** Reliability is a property of **delivery**, not core storage:

- Firing the hook **durably enqueues** the canonical, provenance-signed event for
  **at-least-once delivery** to each registered target (a delivery outbox at the
  firing layer, drained on ack, retry + dedup on `event_id`). The outbox is
  transient delivery infrastructure, not an audit store.
- If `logs` is down, the outbox retries until delivered; nothing is lost without
  core holding a copy.
- For audit-critical hooks (`post-secret-use-hook`), the **effecting naapp**
  (`secrets`) records the use in **its own** db as part of brokering and enqueues
  delivery to `logs`; if it cannot durably enqueue, it fails closed (the action
  does not silently happen undelivered). The durable record is the naapp's own db
  plus `logs`' chain — never a core ledger.

## 8. aw-core changes required

Concrete work in `aw` and at the server mediation points:

1. **Manifest schema:** add the `hooks` registration field (§2) to the app
   manifest contract and its conformance vectors.
2. **Hook registry in `aw`:** on plugin/app install, collect each app's hook
   registrations into a per-team registry (which targets are on which hook).
3. **Client firing:** for local-only commands, `aw` constructs the canonical
   payload, signs it with the agent cert, writes it to the audit ledger feed, and
   calls each registered target.
4. **Server firing:** core and each naapp server fire their owned hooks (§5) at
   the point of effect, write the ledger event, and deliver to registered targets.
   `secrets` fires `post-secret-use-hook`; core fires `post-mutation-hook`.
5. **`trace_id` plumbing:** `aw` mints a `trace_id` per user command and passes it
   through to server calls so multi-effect commands correlate.
6. **`event_id`/idempotency:** stable per-effect id; dedup at consumers and at
   the ledger.
7. **Catalog + payload schemas** (§5) as a versioned contract with fixtures.

## 9. Launch scope

- The `hooks` manifest field + registry in `aw`.
- `post-secret-use-hook` fired server-side by `secrets` (the audit-critical one).
- `post-mutation-hook` fired server-side by core for the demo-critical mutations
  (membership, task lifecycle, mail/chat, approvals).
- `post-command-hook` fired client-side by `aw` for local commands (cooperative).
- `logs.aweb.ai` registered on these and receiving canonical payloads.
- `trace_id` correlation + `event_id` idempotency.

Defer: blocking `pre-*` hooks, the full general catalog, non-audit consumers
(metrics/policy apps), and rich delivery (the pull/replay feed beyond what `logs`
needs).
