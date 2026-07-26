# The OAS–aweb seam: Principal, Instance, Session

Status: design agreed, implementation in progress
Date: 2026-07-25
Owner: alice (`aweb-oas.aweb.ai/alice`), team `aweb-oas:aweb.ai`
Epic: `aweb-oas-aaaa`

Binds OAS to aweb identity, messaging, and tasks. Remote host dispatch is out
of scope.

**This document has one author.** Propose changes on the epic task and the owner
makes them. This is not ceremony: two people editing one normative document in
parallel is how it started contradicting itself once already, and how a
correction landing in main can silently revert another correction still on a
branch. The rule was previously enforced by remembering to tell each new agent,
which failed the first time an agent arrived who had not been told — so it is
written here instead, where anyone about to edit will see it.

Every claim about external behaviour in this document was verified against
running code at a stated version, and cites the source so a reader can re-check
rather than trust. Versions: OAS 0.18.1, aw CLI 1.32.10, Claude Code 2.1.219.

**On the form of citations.** Line numbers into files under active development
go stale on the next merge that inserts a line above them — this document
already shipped two citations to `identity_home_policy.go:35` that pointed
somewhere else within hours, because a merge added two entries above the one
being cited. So: cite a **stable identifier** (a symbol, a map key, an exported
name) wherever one exists, and reserve line numbers for places where nothing
stable can be named. For another repository, pin the commit as well — `ac` line
numbers are meaningless here without the `c5650ecf` pin, since it moves
independently of this one. A citation that cannot survive a merge is a claim
with a short half-life, not evidence.

## The invariant

> A principal's lifetime and cleanup ownership are an explicit recorded
> decision, never incidental to execution and never inferred afterwards.

OAS may **create** a principal or **attach** an existing one — both are
legitimate. What is never legitimate is either happening as a side effect, or
cleanup authority being deduced later from what happens to be on disk. The
decision is made and recorded **at binding time**; retire consumes that record
and does nothing it does not authorise.

## The three entities

| Entity | Owner | Lifetime | Holds |
|---|---|---|---|
| **Principal** | aweb | **Declared** — disposable or durable | Address, `did:aw` stable id, credentials, durable mutable state |
| **Instance** | OAS | Until explicit retire | Home, worktree, task context |
| **Session** | OAS | One model process | Nothing durable |

A principal's lifetime is a property of the **binding that created or attached
it**, not of the kind of thing it is. The same identity machinery serves a
worker that dies this afternoon and a resident that outlives the repository.

- a **disposable worker** is an instance whose principal was provisioned *as
  disposable*, and is therefore cleanup-owned by that instance;
- a **resident** is a durable principal with zero or one active instances. It
  may have been provisioned durably by an instance that no longer exists, or
  attached from elsewhere; in neither case does an instance own its cleanup.

Provisioning and cleanup ownership are therefore independent: creating a
principal does not imply owning it.

Note the vocabulary collision: aweb already uses "workspace" for its registered
identity record, so the OAS-side object is called **Instance** here.

### Why not simply mark an OAS instance as persistent

That was the first design and it was rejected. It bolts a flag onto OAS to
exempt it from its own default, so safety depends on someone remembering to set
it. Under attach semantics, retiring a resident's instance is safe *by
construction* — the capability has no cleanup authority over a principal it did
not provision, so there is nothing to exempt.

A second design made aweb launch residents itself. That was rejected too: it
gives aweb a second orchestrator, duplicating tmux, worktree, and runtime
knowledge that OAS already owns.

The test that settles this class of question: *can the aweb side be implemented
without knowing tmux, Claude flags, worktrees, process liveness, or OAS instance
directories?* If yes, it is a policy layer delegating execution. If no, it is a
second orchestrator and should be rejected.

## Verb boundary

- **`aw` supplies and custodies the primitives** — create, verify, rotate,
  migrate an identity, and hold its credentials. It has no OAS knowledge, ever.
- **The capability decides and records** — it explicitly provisions a principal
  (disposable or durable) or attaches an existing one, and records that
  decision with its cleanup ownership.
- **OAS executes** — it creates, runs and destroys instances and sessions, and
  invokes the capability's hooks. The capability never touches tmux, worktrees,
  runtime flags, or instance directories.

The layering is what matters: `aw` holds capability without policy, the
capability holds policy without orchestration, and OAS orchestrates without
identity knowledge. Bootstrap follows from it — a principal can be created
ahead of time with `aw` and attached later, or provisioned by the capability at
bind time, and the record says which happened.

## Filesystem layout

Committed, in the one owning repo — public, reviewed, no keys:

```
<repo>/oas/agents/<soul>/principals/<name>.yaml   # the v1 fields below
<repo>/oas/agents/<soul>/soul/                    # the durable expert
```

The v1 declaration is exactly: `schema_version` (`1`), `address`, `stable_id`
(the `did:aw`), `team_id`, `soul`, and an optional `soul_version`. Unknown
fields are rejected, so a stray secret cannot ride along.

There is deliberately **no policy block**. Cleanup ownership is a property of
the *binding mode* — including whether a provision was durable or disposable —
not of a principal, so a policy field here would be speculative. The same
declaration can be attached by one instance and describe a principal another
instance provisioned durably. `schema_version` exists to allow additive evolution when a
field is actually needed; speculative fields in a published contract are worse
than adding one later.

`team_id` must be written in canonical form — lowercase, DNS-style
`team-name:namespace`. This is deliberately **stricter than**
`awid/src/awid/team_ids.py:parse_team_id`, which accepts any non-empty
`name:domain` and then lowercases it and strips a trailing dot. A declaration is
a trust anchor, and silently canonicalizing a trust anchor is its own hazard, so
a non-canonical id is rejected rather than normalized. The cost of that choice is
real and worth stating: a team id the identity system accepts cannot be declared
until it is written canonically, and the failure appears at attach time. The
validation error therefore names the expected canonical form.

Host-local, gitignored, resolved explicitly and never inferred from cwd:

```
<host-data-root>/aweb/principals/<team-name>/<team-namespace>/<principal-id>/
  credentials/     # .aw material — protected, separate backup and security class
  state/           # durable mutable state — a different security class from credentials
```

`<principal-id>` is the method-specific segment of the `did:aw` — the only
identifier that survives key rotation.

The team id is carried **structurally, as two directory levels**, rather than
encoded into one. An earlier revision mapped the colon to `__`, matching the
team-certificate filename convention (`aweb-oas__aweb.ai.pem`). That encoding is
lossy: `a__b:c` and `a:b__c` both produce `a__b__c`, so two distinct teams would
share one credential store. Consistency with an existing convention was the
wrong criterion when the convention is lossy and the new use — a credential path
rather than a filename — is more dangerous. Splitting on the colon makes the
collision unrepresentable, because the validator already forbids `:` and `/`
inside each half.

Two defences are required regardless of encoding:

- reject **backslash** in `team_id` and `address`; a pattern excluding `/` but
  not `\` permits traversal outside the principal root on Windows;
- assert **containment** — the resolved principal, credentials, and state paths
  must each lie inside the resolved home root. Keep this permanently. It is the
  defence that survives the *next* encoding change rather than the current one.

These resolver-time checks are point-in-time diagnostics, not durable proof:
the filesystem can change after resolution. The consumer must repeat the
symlink and containment checks at the credential point of use.

OAS-owned and disposable:

```
<repo>/oas/agents/<soul>/instances/<instance-name>/   # home, worktree, task context
```

Principal state lives outside the instance for a reason that is structural, not
aesthetic: **`oas retire` deletes the instance home.** Anything durable stored
there is destroyed by an ordinary, correct retire.

## Why the committed declaration exists

Not as a lookup — the registry already resolves addresses, and `aw id resolve`
maps a `did:aw` to its current `did:key`. It exists as a **trust anchor**: the
registry reports what an identity *currently is*; the declaration records what it
is *expected to be*. Same reasoning as pinning a dependency hash rather than
trusting the index.

**Pin the `did:aw` stable id, never the `did:key`.** The `did:key` is the current
signing key and rotates legitimately (`aw id rotate-key`), so pinning it would
break on every rotation and train people to ignore mismatches. The `did:aw`
survives rotation, while an address re-minted after a delete receives a *new*
`did:aw` — so pinning the stable id is what makes re-mint detectable at all,
and tolerates rotation. Detectable is not detected: see below for what actually
performs the comparison.

### What the pin affords, and what v1 attach actually checks

The pin makes stronger checks *possible*; it does not perform them. What it
buys depends entirely on **what the declared `did:aw` is compared against.**

**Compared against a registry resolution of the address**, the pin detects
delete-and-re-mint — a re-minted address receives a *new* `did:aw`, so the
resolved stable id stops matching the declaration — and it tolerates legitimate
key rotation, since `did:aw` survives rotation.

**Compared against local credentials**, which is what v1 attach does via
`aw --identity-home <credentials> whoami`, it establishes only that the
credentials at that path agree with the declaration. It **cannot** detect
delete-and-re-mint: stale local credentials still carry the old `did:aw` and
still match a stale declaration, because nothing has resolved the address.

So v1 attach performs no registry resolution, walks no DID log, and invokes no
`aw id verify`. It is not a weaker form of registry verification — it is a
different check, and it must not be described as identity verification.

The stronger properties require resolving the address at attach time and
comparing the returned stable id; resisting a *compromised* registry requires
verifying rotation history rather than trusting the response. `aw id verify`
exists and a DID-log verifier exists in both Go and TS backed by shared signed
vectors, but verifier parity is not runtime parity: this codebase has shipped a
byte-identical verifier behind a resolver that did not walk the log. Adding
either is a deliberate decision with its own cost, not an assumed default.

Do not compensate for any of this by pinning the rotatable `did:key`.

## Identity binding

Declared explicitly, never inferred. Three modes, defined once here and
described in full under *Binding modes* below:

- **`provision-disposable`** — mint for this instance; `cleanup_owner = instance`
- **`provision-durable`** — create to outlive it; `cleanup_owner = external`
- **`attach-existing`** — bind an existing principal; `cleanup_owner = external`

There is no `none` mode. Selecting `messaging: none` in the deployment config
already expresses that, and a second way to say the same thing is a second thing
to keep consistent.

Inferring cleanup ownership from the presence of a `.aw` directory is rejected.
That inference is the bug class that destroys durable identities.

The attach-only walking skeleton is implemented by the
`aweb.identity-attach` messaging capability under
`oas/.agents/capabilities/owned/aweb-identity-attach`. Its ID is deliberately distinct from
upstream OAS's destructive per-instance `oas.aweb` lifecycle. The messaging
layer must select this capability explicitly, so capability discovery order
cannot substitute one retire policy for the other:

```yaml
capabilities:
  layers:
    messaging:
      capability: aweb.identity-attach
      global:
        enabled: true
        settings:
          identity_binding:
            schema_version: 1
            mode: attach
            principal: <declaration-basename>
```

At the production `spawn` hook, it validates the selected declaration, resolves
and rechecks the host store, and confirms that the credentials selected by
`aw --identity-home <credentials> whoami --json` agree with the declaration's
address and stable ID. This is **not registry verification**: attach does not
resolve the registry record, walk the DID log, call `aw id verify`, or verify
rotation history. Independent proof observations may do those things, but must
not attribute them to this hook.

OAS persists the resulting non-secret reference at
`instance.json.capabilityMeta["aweb.identity-attach"].identity_binding`,
including `cleanup_owner: external`. It does not create an instance `.aw`
directory or a second binding file.

At the production `retire` hook, only a persisted v1 attach binding with
external cleanup ownership produces an explicit `preserve_principal` receipt.
The hook invokes no `aw` or principal filesystem cleanup operation. Missing or
malformed metadata grants no cleanup authority. Modes other than `attach` are
rejected in this slice rather than falling through to the pre-existing
per-instance mint behavior.

The v1 input is config-scoped `OAS_SETTINGS`, so it attaches every instance of
the targeted soul to the same principal; it is not a per-instance override.
Concurrent use remains unfenced until the admission lease lands. That limitation
is accepted for this walking skeleton and is not solved by attach cleanup.

### Tasks layer binding

The owned `aweb.tasks` capability under
`oas/.agents/capabilities/owned/aweb-tasks` binds OAS's exclusive `tasks`
layer to aweb. It is intentionally separate from the
`aweb.identity-attach` messaging capability because one manifest may own only
one fundamental layer. When selected, aweb is authoritative for the shared
task queue, work discovery, ownership, status, and roster; task-like and
roster features from the messaging layer or another integration stay off.
Conversation still belongs to the messaging layer.

```yaml
capabilities:
  layers:
    tasks:
      capability: aweb.tasks
      global:
        enabled: true
```

The capability contributes the `aweb-coordination` skill and an instruction
block naming `aw task`, `aw work`, and `aw workspace status`. The skill copy is
guarded byte-for-byte against the canonical repository skill so this new
distribution cannot silently drift.

Binding does not bypass attached-principal admission. All runnable `aw task`
commands and `aw work ready|active|blocked` are admitted only after a
production-binary regression routes their authenticated requests through the
selected external identity home, verifies the external principal's signature,
and proves zero traffic reaches a complete divergent instance shadow. With no
external identity home, the pre-existing command path is unchanged.

Provisioning recovers by **reconciliation, not replay**. An earlier revision of
this document specified a write-ahead journal keyed by a stable idempotency key,
with replay producing no duplicate. No production path delivers that: neither
invite accept carries an idempotency key, the hosted helper creates
`max_uses: 1`, and AC checks the use count before any reconciliation, so
replaying a consumed token returns 409 rather than a second copy of the answer.
The requirement is instead that a crash never leaves a resource nobody owns and
nobody can find, and that recovery determines **from remote state** whether the
operation completed and adopts the result if it did.

Two bounds on that, both established by scope review rather than by failure. No
capability-side state can mean *launched* — OAS exposes a pre-launch hook and no
post-launch acknowledgement — so the honest boundary is *provisioning completed
and binding handed to OAS*. And on the hosted path the **earliest** crash point
is not currently recoverable at all: the create-invite call carries no operation
marker, AC generates both id and token server-side, and list-invites never
returns the full token, so a lost response leaves a grant we cannot identify,
recover or safely revoke (`aaaa.40`). Attach journals no cleanup authority, and
its rollback must be provably non-destructive.

## Single-runner control

Two levels, named honestly, because conflating them would put a false claim in
the documentation:

**v1, admission lease.** When explicitly acquired, prevents a different
per-session key from acquiring admission while the lease is live. It does
**not automatically prevent concurrent starts today**: OAS has no session
start/end hook, so no runtime caller acquires or releases it yet. `aw lock` is already a server-side TTL lease with `SELECT FOR UPDATE`
(`server/src/aweb/routes/reservations.py:186-204`), but its conflict test
compares `holder_agent_id`, so a copied identity does not conflict with itself.
The holder must therefore be a per-session key that the server holds and checks;
`metadata_json` is stored but never enforced, so this cannot be built by
convention on today's primitive. The lease belongs to the **session**, not the
instance — an idle instance holding a lease makes TTL semantics dishonest.
No silent preemption: a supervisor may not acquire at a higher generation while
an unexpired lease exists. Normal recovery waits for TTL; earlier takeover is an
explicit, audited administrative operation.

**v2, true fencing.** Acquire issues a short-lived session credential bound to
principal, session id, and generation, and the channel and mutating endpoints
**reject** a stale generation. Only this makes "a resurrected process is fenced
out" a true statement rather than a comforting one.

### Stated limitation

An exact copy of a principal's signing key still authenticates as that
principal. aweb has self-custody with a single key, no per-device credentials,
and no per-device revocation. Migration therefore relies on procedure plus
admission control, not on revocation. This ships in the documentation, not only
in a ticket.

## What already prevents concurrent runners

Two layers exist before any of the above:

1. **Git.** `.gitignore:13` is `.aw/`, and no instance state is tracked. A clone
   cannot impersonate a principal because it has no key.
2. **The server.** `idx_workspaces_active_alias` is UNIQUE on `(team_id, alias)`
   where `deleted_at IS NULL` (`001_initial.sql:335`). A second clone cannot
   enroll a duplicate alias.

This is why a persistent agent's home **stays gitignored**. Committing it would
replicate the signing key to every clone, letting each authenticate as the same
`agent_id` — defeating both the unique index and the lease at once. What gets
committed is the declaration and the public stable id, never the credentials.

The realistic residual hazard is not a stray clone but **manual host migration**,
which is a documented procedure: quiesce sessions, release the lease, snapshot
and checksum `state/`, move credentials separately, verify the expected
`did:aw`, then start. Never rsync a live home.

## Relevant OAS behaviour

- Hook events are exactly `soul-scaffold`, `spawn`, `retire` (`lib/core.mjs:271`).
- Hook failure is always advisory; the docstring states failures never block
  (`core.mjs:894`). A spawn whose identity binding failed is currently a
  successful spawn.
- Spawn *is* session start; there is no resume command, and the window
  deliberately drops to a shell when the agent exits (`core.mjs:1522`), so
  sessions 2..N are started by a human in that shell.
- Liveness is "a tmux window with this name exists" (`core.mjs:1541`; the desktop
  app repeats it at `packages/desktop/server/model.mjs:137` while collecting
  `pane_current_command` on the same call). An exited agent therefore still reads
  as running.
- Per-run intent can reach a hook today, because `runLifecycleHooks` spreads
  `process.env` (`core.mjs:877`). This is an experiment seam, not a public
  contract; an explicit binding is preferred.

### Upstream contributions

Classified by which component has authority to enforce the invariant, whether
the contract is vendor-neutral, and whether implementing it outside core would
duplicate or bypass core lifecycle.

| Item | Where | Rationale |
|---|---|---|
| `--` separator before the appended prompt | OAS core, now | Their command construction; any capability contributing a variadic flag breaks identically |
| Liveness from process state | OAS core, now | Every OAS user sees a wrong roster today, with no aweb involved |
| Critical hooks (opt-in, default advisory) | OAS core, now | Only core can decide whether to launch after a hook fails; a capability cannot implement it without duplicating or sabotaging the launcher |
| Session start/end/resume | OAS core, later | Conceptually theirs, aweb-driven; propose with operating evidence rather than leading with it |
| Lifecycle receipts | Capability first | Upstream only once the journal and cleanup shape survives real use |
| Identity, provisioning, leases, fencing, tasks, GC | aweb | Vendor depth |

Honesty requirement for the critical-hooks proposal: describe it as a
vendor-neutral optional hook policy, default advisory, motivated initially by an
identity integration. We are the first and currently only consumer, and claiming
broad demand would be false.

### The launch-command defect

Claude Code 2.1.219 declares both channel options as variadic —
`--channels <servers...>` and `--dangerously-load-development-channels
<servers...>` — verified by byte-search of the binary; neither appears in
`--help`, so a `--help` probe proves nothing either way. OAS appends the quoted
task prompt directly after capability-contributed arguments with no `--`
(`core.mjs:1461`), so the prompt is consumed as another channel argument.

Channel behaviour is selected by a **live injection test**, not by reading
flags: `--channels` warns that the plugin is not on the approved allowlist and
continues, so it starts unattended but connection is unproven; an installed and
enabled plugin may load the channel with no flag at all, which would be the
smaller fix.

## Binding modes and where lifecycle policy lives

OAS is **not** a local-and-ephemeral-only system, and this seam must not assume
it is. The four lifetimes are distinct and none of them implies another:

| | Lifetime |
|---|---|
| **Principal** | durable, possibly global; outlives every process |
| **Soul and its reviewed learning** | durable, committed, reviewed |
| **Instance** | replaceable |
| **Session** | transient |

The capability therefore supports three explicit binding modes, and the mode is
always declared, never defaulted into:

- **provision-disposable** — mint an identity for this instance; the instance
  owns cleanup; retire deletes it.
- **provision-durable** — create an identity intended to outlive the instance;
  the instance does **not** own cleanup; retire preserves it.
- **attach-existing** — bind an already-provisioned principal; cleanup owner is
  external; retire preserves it.

At binding time the capability records **what it created, that resource's
lifecycle, and who owns cleanup**. Retire consumes that record and may delete
only identities that are both **disposable** and **OAS-owned**. This is the
invariant stated at the top of this document — lifetime and cleanup ownership
are an explicit recorded decision, never incidental and never inferred — applied
to creation as well as to attachment.

**The layers are separate, and the earlier text conflated them.** `aaaa.4` is
the decision layer: it produces a *judgement* — preserve, or cleanup authorized
— and it creates and deletes nothing. `aaaa.33` is the execution layer that acts
on that judgement. So no single component both records a created resource and
deletes it, and any description saying otherwise describes a shape we
deliberately abandoned.

**A judgement is only as strong as what backs it, and it must say which.** A
receipt is never self-authorizing and corroboration is always required — that
much is universal. What corroboration *buys* is not. Nothing stored where the
model can write is an authority anchor, whatever cryptography is layered over
it: hook and model share a UID, so a locally verified record establishes
*internal consistency*, not provenance. Where the authority a destructive step
needs is **absent from the machine**, refusing to act without it is a real
security boundary — and there, corroboration must come from the remote authority
itself, since it is the party that holds the authority. Where the authority is
**locally exercisable**, corroboration prevents accident and confused-deputy
mistakes and cannot prevent intent. The judgement must therefore carry its
assurance level, so a caller cannot mistake the second for the first; where
remote corroboration is required and unavailable, the judgement is **preserve**.

Making attach a *peer* of provision rather than an exception is deliberate: an
exception has a default that someone must remember, and a peer does not.

### Policy belongs in the capability, not in the protocol

An earlier draft of this document proposed restricting the aweb spawn grant
server-side so it could not mint durable identities. That was **wrong, and is
withdrawn.** aweb legitimately supports creating durable identities; that is a
feature used by real flows, and constraining the protocol because one consumer
might misuse it is the wrong layer.

The distinction is between **authority** and **policy**. The existing invite
already carries sufficient authority. What was missing was policy — and policy
belongs in the trusted capability that decides what to create, expressed through
the recorded lifecycle above.

No change to aweb or AC is required for this seam. The finding that a spawn
invite *can* mint a durable global principal is retained as context for writing
that policy (`aweb-oas-aaaa.27`, P3, non-blocking); it would only become a
protocol question if a concrete **non-OAS** abuse case established one.

### The two invite mechanisms are not equivalent

Anything reasoning about grant strength must distinguish them:

**Hosted (AC)** — verified in `ac/backend/src/aweb_cloud/services/spawn.py`, in
the **`ac` repository** at commit `c5650ecf` (line numbers below are meaningless
without that pin, since `ac` moves independently of this repo): `max_uses`
defaults to **1** and must be ≥ 1 (`:200-205`); expiry defaults to **24h**
(`DEFAULT_EXPIRES_IN_SECONDS`, `:20`), minimum 60s and maximum 30 days
(`MAX_EXPIRES_IN_SECONDS`, `:21`, enforced at `:207-216`). Revocation is a real
operation, not just a column: `UPDATE … SET revoked_at = NOW()` guarded by
`revoked_at IS NULL` (`:372-379`), and consumption rejects a revoked or expired
token with 410 and an exhausted one with 409 (`:420-423`). Race-safety is the
whole sequence, not the `SELECT` alone: the row is read `FOR UPDATE` inside the
transaction (`:408-414`), the limit is checked against it (`:422`), and the
counter is incremented in the same transaction (`:530-537`).

**Local controller / BYOIDT** — verified in `cli/go/awconfig/team_invites.go`:
the `TeamInvite` record (`:15-24`) has exactly `invite_id`, `domain`,
`team_name`, `ephemeral`, `secret`, `registry_url`, `aweb_url`, `created_at` —
**no expiry field and no use counter** at all. It is single-use only by
convention: the consumer deletes the local pending file
(`cli/go/cmd/aw/id_team.go:1389`), and that deletion's failure is a *warning*,
not an error. There is no server-side enforcement of either property.

So a policy that relies on max-uses or expiry holds on the hosted path and does
**not** hold on the local path. Do not reason about "the invite" as one thing.

### Alias policy

Alias derivation and uniqueness are a **capability** concern. The server's
UNIQUE `(team_id, alias)` index — `idx_workspaces_active_alias`,
`server/src/aweb/migrations/aweb/001_initial.sql:335-337` — is a **backstop**,
not the mechanism: it rejects a duplicate cleanly, so the failure is
availability rather than collision, but it cannot make names unique *by
construction*. Note also that the index is partial on `WHERE deleted_at IS NULL`
(`:337`), so a soft-deleted workspace frees its alias.

### Acquisition stays separate from onboarding

`oas install` is deterministic acquisition and lock restore. It must not issue
or accept invitations, mutate remote membership, or wait for interactive login.
Onboarding belongs in an explicit, trusted, idempotent setup step.

## What "done" means: two customer journeys

A UX review by `atext.aweb.ai/developer-frontend`, conducted against the running
code rather than this document, returned a verdict worth stating at the top:
**this is a strong internal safety substrate and it is not yet a customer path,
and it must not be presented as one.** The decisive evidence was not the number
of caveats but that *OAS reports a configuration healthy and launches an
instance when the selected capability cannot produce a bound identity* — doctor
shows empty settings without error, provisioning failures become warnings, and
hook failure is advisory, so the model launches unbound while every surface says
healthy.

The components below are means. **Done is these two journeys**, and neither
part of the system is customer-ready until its journey passes end to end:

1. **The ordinary worker** (`aaaa.44`). An organization publishes a config; a
   developer clones, runs `oas install`, runs `oas doctor` and gets either
   *Ready* or **exactly one** setup action, spawns a worker, sees its aweb
   address, exchanges a real message, retires it, and no disposable state
   remains. **No identity jargon and no YAML editing anywhere in that path.**
2. **The resident** (`aaaa.45`). A durable principal is created or selected
   explicitly, comes back as *the same stable identity* across a session
   restart, answers a message, **retains what it learned across sessions**, and
   survives instance retirement.

Three consequences the review made explicit and this document adopts. The mode
names — `provision-disposable`, `provision-durable`, `attach-existing` — are
**internal receipt vocabulary and bad first-run UX**; a customer expresses
intent, and the capability records the mode. **Exhaustive caveats belong in this
record, not on the user surface**, which needs one result: *Ready*, *Needs setup
— one command*, or *Experimental, nothing was launched*. And **learning is part
of being a resident**: a durable identity that accumulates nothing across
sessions is a stable address, not an actor — with publication to the shared
Library deliberate, never automatic.

## Ordered plan

The **ordinary provisioned worker is the mainstream path**; the durable resident
is the extension. An earlier revision of this document led with the resident,
which is the exception — we built it first, and that ordering is corrected here.

1. **Prompt separator** (`aaaa.1`). Delimit the task prompt after
   capability-contributed launch arguments. Written and merged in our source;
   **not finished** — it is open upstream as OAS-Framework PR 37, and until that
   merges the defect stands for every consumer but us.
2. **Lifecycle policy, split into decision and execution.** `aaaa.4` is the
   decision layer — the three binding modes, the receipt schema and validity
   matrix, and a judgement that carries its own assurance level. It creates and
   deletes nothing. `aaaa.33` is the execution layer that acts on that
   judgement, and it waits on `aaaa.5` for minting authority and on `aaaa.40`
   for whether a hosted grant can be reconciled after a lost response.
   `provision-durable` has no production path today and must be **refused**
   rather than half-executed; `aaaa.39` owns delivering it later.
3. **Clean external customer proof** (`aaaa.28`). A fresh workspace, two
   developers, duplicate local instance names — the ordinary
   provision-and-retire journey end to end.
4. **A working attached runtime**, which is three things and not one. A
   pre-implementation review of what was originally scoped as a single step
   found that propagation alone lands a variable on a runtime that ignores it,
   to drive an agent that could not answer if it did:
   - **Deterministic propagation** (`aaaa.29`) carrying the resolved identity
     home into the launched process. A validated hook environment map upstream
     is the *proposed* solution and the smallest one found; the requirement is
     the deterministic propagation, not that shape.
   - **Channel resolution at the selected principal** (`aaaa.35`).
     `channel-core`'s `resolveConfig(workdir)` hardcodes
     `join(workdir, ".aw", …)` for workspace, teams, identity and signing key
     (`channel-core/src/config.ts:58-62`), so both Pi and Claude read the
     disposable instance no matter what OAS places on the runtime.
   - **Outbound messaging admitted** (`aaaa.36`). The external-home allowlist
     (`cli/go/cmd/aw/identity_home_policy.go`) holds exactly one messaging
     entry, the map key `"aw mail inbox"` — no reply, no send, no chat.

   Only `.29` needs anything from upstream; the other two are ours.
5. **Throwaway Pi attach proof** (`aaaa.30`) — positive wake, reply, ordinary
   retire. It waits on all three parts of step 4, and it may not claim a broken
   binding *prevents* a model process: OAS continues after a failed hook, so
   until `.2` lands a bad binding is refused and observable, not fail-closed.
6. **Explicit per-instance capability settings** (`aaaa.31`) and required-hook
   fatal outcome with rollback (`aaaa.2`).
7. **Migrate the first durable resident** (`aaaa.19`), and not before.

This numbering is the **intended work order**, not a dependency chain: steps 3
and 4 are independent, and either could run first without breaking anything.

**The board is authoritative for dependencies, and this document deliberately
does not mirror it.** Two earlier revisions enumerated the edges here, and both
enumerations were wrong within the hour — which is this epic's recurring defect
shape, a copy diverging from its source while both look authoritative, committed
in the document that exists to name it. What is recorded below is the set of
*ordering constraints the design requires*, which are stable; the board records
them as edges, and `aw task dep list` is how you check them:

- lifecycle policy precedes the minting authority that provisioning uses, which
  in turn precedes any proof of the provisioned journey;
- the crash-recovery proof waits until the ordinary journey passes — hardening
  a path before it works is effort spent on a shape that may still change;
- the Pi wake-and-reply proof waits on deterministic propagation, because
  without it there is nothing to wake as;
- resident migration waits on that proof;
- the per-instance settings contract waits on propagation, so that only one
  contract addition is in front of the upstream maintainer at a time.

Step 6 is two tasks: `.2` for required-hook fatality, `.31` for per-instance
settings. Step 1 is merged in our source and **still open as `.1`**, because
what remains is upstream acceptance of PR 37, and the defect is unfixed for
every consumer but us until that lands.

**What is already delivered.** Two bounded *safety* results, both requiring no
upstream change: ordinary retire of an attached instance preserves the principal
(`.17`), and the attach path cannot register the disposable instance path, so
the gone-workspace route is unreachable by construction (`.24`). This is *not*
non-destruction in full — see *What is NOT yet proven*.

Plus the *mechanism* those proofs guard, built since: identity resolution with
default-deny admission (`.11`, `.22`, `.23`, `.34`, `.36`, `.10` — each command
routed through the selected principal *before* it was admitted, never the
reverse, and each admission proven load-bearing by removing it and requiring its
own test to fail); the binding decision layer, whose judgement carries its own
assurance level so a caller cannot mistake local accident-resistance for a
security boundary (`.4`); minting authority declared and verified per path,
hosted and local having opposite failure modes (`.5`); the runtime's own
resolution — channel config at the selected principal (`.35`) and outbound
messaging admitted (`.36`); and the exclusive **tasks** layer bound to aweb
(`.10`), which completes the three bindings the founding scope named — identity,
messaging, and tasks/work.

Two supporting results are worth naming because they protect the rest.
Diagnostics are rooted at the selected principal with an **enforced** export
allowlist (`.34`): a support bundle is the one artifact designed to leave the
machine, and a documented allowlist turned out to export an unknown field
verbatim until enforcement was made structural. And the suites are hermetic with
respect to the identity environment (`.37`) — the variable this epic exists to
set was one that our own tests could not tolerate, which would have made a
resident unable to distinguish a real regression from an environment artifact.

**What is not:** fail-closed admission, which is impossible while hook failure
is advisory. Until required hooks land, any attach is an **attended development
experiment against controlled throwaway principals** — not a supported release
and not valid for durable production principals. Returning deliberately broken
launch arguments so the command dies in the window was considered and rejected
as a dishonest hack.

**No longer deferred**, because the reframe put the provisioned worker on the
mainstream path: the write-ahead provision journal is part of step 2 (`.4`), and
the declared minting authority is `.5`, which step 3 waits on. An earlier
revision of this list deferred both, which was correct when attach was the
primary case and is wrong now.

**Deferred, deliberately:** the provision crash-recovery proof (`.18`) until the
ordinary journey passes, admission lease, true fencing, session start/end/resume,
and resident GC. Each is real work and none is on the path to a first working
resident; several would harden a mechanism whose positive capability is still
unproven.

## Proofs

A slice is not done because its components merged. It is done when its scenario
passes with attached evidence.

### What is NOT yet proven, stated here rather than in a footnote

**Nothing binds the launched runtime to the declared principal.** The spawn
hook verifies the principal and persists the binding in capability metadata,
emitting exactly `meta` and `brief`
(`oas/.agents/capabilities/owned/aweb-identity-attach/bin/aweb-identity-attach.mjs:171-174`)
and so contributing nothing to the launch. OAS accepts a hook `launch` map of
runtime → extra **command arguments** — documented at `lib/core.mjs:854-857`,
aggregated at `:893`, appended to the command at `:1457`. It has no hook
**environment** map: the command's environment prefix is built from a fixed set
of core variables at `lib/core.mjs:1467`, with no hook contribution. So the
authority variable `AWEB_IDENTITY_HOME` (`cli/go/awconfig/identity_home.go:12`)
is **not deterministically set by the hook or by OAS**. It is not "never set" — the
launched process inherits an environment, and something in it may happen to
carry that variable, which is precisely the ambient case described next.

The precise claim is **no deterministic binding**, not "the model cannot act as
the principal". The launch command does not scrub ambient identity state, so a
session could still resolve *some* identity from the environment or working
directory it inherits. That is arguably worse than none, because it can appear
to work. What does not exist is any mechanism that makes it the *declared*
principal.

**Propagation alone would not have been enough, and that is why it is one of
three.** Scope review — not a failure — found two further gaps behind it, both
in our own code, and **both are now closed**:

- the channel resolved its workspace, team state, identity and signing key from
  the working directory regardless of any identity home, so an attached agent
  would have read as the wrong identity or *signed validly as the wrong
  identity*, which is the failure that looks like success. Closed by `.35`:
  `resolveConfig` honours the selected principal on both Pi and Claude, proven
  against a complete valid divergent shadow, with the packaged MCP child
  observed over real stdio.
- the outbound half of messaging was not admitted for an external home at all —
  `"aw mail inbox"` was the only messaging key in the allowlist, so a resident
  could read and never answer. Closed by `.36`: reply, send, ack and the whole
  chat surface routed through the selected principal *before* admission, each
  with its own divergent evidence.

What remains of the three is propagation itself (`.29`), which needs an upstream
change. So the gap is no longer "an attached agent could not act as its
principal"; it is precisely that **nothing places the resolved identity home on
the launched process**. Everything downstream of that variable now honours it.

`.17` exercises the real spawn/retire lifecycle through
`oas spawn --no-launch`: kernel, hook dispatch, instance lifecycle and retire
path are all real, and only session launch is skipped.

`.24` is a different shape — it traces the attach path's complete HTTP request
surface, and its *conclusion* is launch-mode-independent in the current source,
because the attach path issues the same single request either way. Its
*evidence* is not purely so: the proof composes an exact-wire regression and the
server handler's behaviour with a no-launch OAS wiring regression. So the
conclusion would survive a launched session; the demonstration, as run, did not
include one.

So the established results are bounded **safety** results, and are exactly three:

- ordinary `oas retire` of an attached instance neither altered nor deleted the
  principal, and leaked no material into the instance (`.17`). The harness
  `scripts/e2e-oas-attached-principal-retire.sh` runs a throwaway principal on a
  fresh loopback stack (`:282-317`), spawns a real attached instance (`:355`),
  and re-asserts the principal unchanged at four boundaries — after spawn
  (`:378`), after direct use from the instance (`:395`), after ordinary retire
  (`:399-415`), and after an independent workspace's gone-workspace sweep
  (`:417-437`). Merged at `46b684ad`.
- the attach path cannot register the disposable instance path, so the
  gone-workspace destruction route is unreachable by construction (`.24`). This
  is a **three-part composition**, and citing only one part understates it: the
  real OAS attach spawn-and-retire wiring regression
  (`oas/test/attach-binding.test.mjs:173-228`); the exact-wire request-surface
  guard, which asserts the attached path emits exactly one
  `GET /v1/agents/me/inbound-mode` and observes method, URI, body, headers and
  path disclosure (`cli/go/cmd/aw/identity_home_test.go:26-115`, especially the
  assertions at `:68-71,102`); and the server handler behind that route, which
  is `SELECT`-only (`server/src/aweb/routes/agents.py:541-582`). Merged at
  `affe23ac`; `2aec5f3e` added **headers** to the already-observed
  method/URI/body surface.
- local-controller disposable cleanup is exercised against a fresh loopback
  AWID and aweb stack in the same committed harness. A forged instance-side
  victim receipt and an independently forged execution operation both leave the
  throwaway victim active; ordinary retire then revokes its real AWID
  certificate, soft-deletes its real aweb agent/workspace rows, and removes its
  local grants and credential material. Seeded PostgreSQL task-claim/reservation
  and Redis presence controls are removed; the external journals are terminal;
  and pre-cleanup credential snapshots find no name/digest/symlink/inode copies
  in either instance or the controlled repository. The second throwaway identity
  is removed through the native, active/trust-gated, exact-operation OAS command.
  Removing the target operation comparison makes the forged execution cleanup
  revoke/delete the real victim and turns the owning-authority assertion red.
  This is a local same-UID accident/confused-deputy result, not hostile-model
  resistance (`.33`).

None establishes the absence of *every* harm — not unsupported provision paths, not
future code, not a route nobody has tested. Do not restate these as "cannot harm
a principal". That it can *use* one is unproven, and stays unproven until some
mechanism propagates the resolved identity home into the launched process
deterministically. A validated hook environment map upstream is the proposed
shape and the smallest one found; the requirement is the deterministic
propagation, not that shape.

Two related limits, for the same reason of not overstating by omission:

- binding is **config-scoped**, so a declared principal applies to every
  instance of that soul; there is no per-instance selection yet;
- the deployment configuration in this repo is deliberately **not committed**,
  because it would activate the capability with no binding and resolve the
  declaration under a doubled path. Fixing those alone would produce a config
  that resolves correctly and still attaches nothing.

The architecture rests on one claim, and if it fails everything else was wasted:

> **Destroying an OAS instance attached to a principal cannot destroy or change
> the principal.**

Create a throwaway durable principal; spawn an instance bound to it in attach
mode; confirm the session reports the expected address and stable id; run an
ordinary `oas retire`; then show the principal still registered with an
unchanged address and unchanged `did:aw`, and no key material copied or
symlinked into the instance home at any point.

Never exercise a retire or delete path against a live principal.

Further scenarios: provision cleanup leaves no workspace; a crash between
provisioning and launch orphans nothing and duplicates nothing on replay; a
message injects into a live session; a second start is refused while a lease is
unexpired.

## Open

- Whether attach should add registry resolution and cryptographic DID-log
  verification. The v1 path does neither; it establishes only local
  credential–declaration agreement.
- Whether upstream deprecates its own aweb capability in favour of ours, or
  transfers maintainership. Two permanent implementations is not an acceptable
  steady state. Authority over vendor-depth correctness and security releases
  must be aweb's and must not be informal.
- Resident instance GC. Restart-as-a-new-instance means residents accumulate
  homes. Manual retire only for now — never GC from tmux-window absence or aweb
  presence, both of which are unreliable liveness signals.
- **Hosted disposable provisioning is not deliverable, and the reason is a
  cleanup authority we cannot hold safely.** The hosted creator certificate can
  create, list and revoke grants; it cannot remove the member it created, since
  hosted remove-member rejects workspace-bound keys and then requires team owner
  or admin authority. The only way to hold that in the spawn hook is to place an
  owner key where the launched model can read it — hook and model share a UID —
  which would give every disposable worker team-wide administrative authority
  and make the hosted path *strictly weaker than local* while claiming to be
  stronger. `aaaa.42` established that the created identity **can** self-delete
  its workspace and bound identity, because hosted acceptance creates a
  *local-scoped* identity and the OSS delete rejects only `global`; what it
  cannot reach is the AWID certificate and the organization-membership row. A
  lingering organization membership is **live authorization, not an audit
  tombstone**, and one accrues per provisioned worker — so partial cleanup is
  worse than an honest refusal, and hosted refuses before creating. This
  resolves when AC offers either a local/ephemeral-aware delete that also
  revokes the certificate and removes the membership, or a scoped
  revoke-own-member capability on the creator certificate. The first is smaller
  and needs no new credential class.
