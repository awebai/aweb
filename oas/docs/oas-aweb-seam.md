# The OAS–aweb seam: Principal, Instance, Session

Status: design agreed, implementation in progress
Date: 2026-07-25
Owner: alice (`aweb-oas.aweb.ai/alice`), team `aweb-oas:aweb.ai`
Epic: `aweb-oas-aaaa`

Binds OAS to aweb identity, messaging, and tasks. Remote host dispatch is out
of scope.

Every claim about external behaviour in this document was verified against
running code at a stated version, and cites the file and line so a reader can
re-check rather than trust. Versions: OAS 0.18.1, aw CLI 1.32.10, Claude Code
2.1.219.

## The invariant

> A principal's existence and authority are never a side effect of execution.

OAS creates, runs, and destroys instances and sessions. It may **attach** a
principal, but it never owns one it did not provision, and cleanup authority is
**recorded at provision time**, never **inferred at retire time**.

## The three entities

| Entity | Owner | Lifetime | Holds |
|---|---|---|---|
| **Principal** | aweb | Durable; exists while offline | Address, `did:aw` stable id, credentials, durable mutable state |
| **Instance** | OAS | Until explicit retire | Home, worktree, task context |
| **Session** | OAS | One model process | Nothing durable |

A **worker** is an instance whose principal was provisioned for it, and is
therefore cleanup-owned by it. A **resident** is a durable principal with zero
or one active instances.

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

- **`aw` creates and custodies** a principal — create, verify, rotate, migrate.
  It has no OAS knowledge, ever.
- **The aweb OAS integration attaches and runs** one, delegating to `oas spawn`.
  It never touches tmux, worktrees, runtime flags, or instance directories.

This ordering also makes bootstrap obvious: create the principal with `aw`, then
attach it.

## Filesystem layout

Committed, in the one owning repo — public, reviewed, no keys:

```
<repo>/oas/agents/<soul>/principals/<name>.yaml   # the v1 fields below
<repo>/oas/agents/<soul>/soul/                    # the durable expert
```

The v1 declaration is exactly: `schema_version` (`1`), `address`, `stable_id`
(the `did:aw`), `team_id`, `soul`, and an optional `soul_version`. Unknown
fields are rejected, so a stray secret cannot ride along.

There is deliberately **no policy block**. Cleanup ownership is a property of a
*binding* — attach versus provision — not of a principal, so a policy field here
would be speculative. `schema_version` exists to allow additive evolution when a
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
`did:aw` — so pinning the stable id detects re-mint and tolerates rotation.

### What the pin does and does not buy

Guaranteed:
- detection of alias delete-and-re-mint, and of a wrong stable identity;
- resolution of legitimate key rotation without editing the declaration.

**Not** guaranteed: detection of a compromised registry returning an
attacker-controlled current `did:key` for the same `did:aw`. That holds only if
resolution cryptographically verifies rotation history. `aw id verify <did_aw>`
verifies the full audit log and a DID-log verifier exists in both Go and TS
backed by shared signed vectors, so the primitive is probably present — but
whether the *attach-time path* invokes it, rather than calling `aw id resolve`
and trusting the answer, is an open test. Verifier parity is not runtime parity:
this codebase has previously shipped a byte-identical verifier sitting behind a
resolver that did not walk the log.

Do not compensate for this by pinning the rotatable `did:key`.

## Identity binding

Declared per run, never inferred:

- **`attach`** — expected stable id, credential reference; `cleanup_owner = external`
- **`provision`** — authority reference, requested alias; `cleanup_owner = instance`
- **`none`**

Inferring cleanup ownership from the presence of a `.aw` directory is rejected.
That inference is the bug class that destroys durable identities.

The attach-only walking skeleton is implemented by the owned `oas.aweb`
capability under `oas/capabilities/oas-aweb`. Its resolved capability setting is
explicit and positive:

```yaml
settings:
  identity_binding:
    schema_version: 1
    mode: attach
    principal: <declaration-basename>
```

At the production `spawn` hook, it validates the selected declaration, resolves
and rechecks the host store, and verifies the declaration against
`aw --identity-home <credentials> whoami --json` from the empty instance. OAS
persists the resulting non-secret reference at
`instance.json.capabilityMeta["oas.aweb"].identity_binding`, including
`cleanup_owner: external`. It does not create an instance `.aw` directory or a
second binding file.

At the production `retire` hook, only a persisted v1 attach binding with
external cleanup ownership produces an explicit `preserve_principal` receipt.
The hook invokes no `aw` or principal filesystem cleanup operation. Missing or
malformed metadata grants no cleanup authority. Modes other than `attach` are
rejected in this slice rather than falling through to the pre-existing
per-instance mint behavior.

Provisioning uses a write-ahead lifecycle journal: journal **intent** keyed by a
stable idempotency key, record the created resource id atomically, mark
**active** before launch, and recover by scanning incomplete intents. Ordering
alone is insufficient — without an idempotency key, a crash between remote
creation and the journal update orphans the resource anyway. Attach journals no
cleanup authority, and its rollback must be provably non-destructive.

## Single-runner control

Two levels, named honestly, because conflating them would put a false claim in
the documentation:

**v1, admission lease.** Prevents a second session starting while one is live.
`aw lock` is already a server-side TTL lease with `SELECT FOR UPDATE`
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

## Slices

**Slice 1 — a resident runs and no identity is destroyed.** Prompt separator;
declaration and principal store; explicit identity resolution; attach-only
binding. Delivers **non-destruction** in full, with no upstream change required.

It does **not** deliver fail-closed admission, which is impossible while hook
failure is advisory. Before critical hooks land, the proof may be exercised only
as an **attended development experiment against controlled throwaway
principals**. It is not a supported release and is not valid for durable
production principals. Returning deliberately broken launch arguments so the
command dies in the window was considered and rejected as a dishonest hack.

**Slice 2 — safety.** Critical hooks (the supported-release gate); admission
lease v1.

**Slice 3 — execution correctness.** Session start/end/resume; true fencing v2;
liveness from process state.

## Proofs

A slice is not done because its components merged. It is done when its scenario
passes with attached evidence.

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

- Whether the attach-time resolution path cryptographically verifies the audit
  log, or trusts the registry response.
- Whether upstream deprecates its own aweb capability in favour of ours, or
  transfers maintainership. Two permanent implementations is not an acceptable
  steady state. Authority over vendor-depth correctness and security releases
  must be aweb's and must not be informal.
- Resident instance GC. Restart-as-a-new-instance means residents accumulate
  homes. Manual retire only for now — never GC from tmux-window absence or aweb
  presence, both of which are unreliable liveness signals.
