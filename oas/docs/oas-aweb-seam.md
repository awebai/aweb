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

Declared explicitly, never inferred:

- **`attach`** — expected stable id, credential reference; `cleanup_owner = external`
- **`provision`** — authority reference, requested alias; `cleanup_owner = instance`
- **`none`**

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
lifecycle, and who owns cleanup**. Retire consumes that record and deletes only
identities that are both **disposable** and **OAS-owned**. This is the same rule
the epic's proofs establish — authority recorded at provision time, never
inferred at retire time — applied to creation as well as to attachment.

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

**Hosted (AC)** — verified in `ac/backend/src/aweb_cloud/services/spawn.py`:
`max_uses` defaults to **1** and must be ≥ 1; expiry defaults to **24h**
(`DEFAULT_EXPIRES_IN_SECONDS`), minimum 60s, maximum 30 days
(`MAX_EXPIRES_IN_SECONDS`); revocation exists (`revoked_at`); and consumption is
transactional under `FOR UPDATE` (`:413`), so the use counter is race-safe.

**Local controller / BYOIDT** — verified in `cli/go/awconfig/team_invites.go`:
the `TeamInvite` record has **no expiry field and no use counter** at all. It is
single-use only by convention — the consumer deletes the local pending file
(`cli/go/cmd/aw/id_team.go:1389`). There is no server-side enforcement of either
property.

So a policy that relies on max-uses or expiry holds on the hosted path and does
**not** hold on the local path. Do not reason about "the invite" as one thing.

### Alias policy

Alias derivation and uniqueness are a **capability** concern. The server's
UNIQUE `(team_id, alias)` index is a **backstop**, not the mechanism: it rejects
a duplicate cleanly, so the failure is availability rather than collision, but
it cannot make names unique *by construction*. Note also that the index is
partial on `deleted_at IS NULL`, so a soft-deleted workspace frees its alias.

### Acquisition stays separate from onboarding

`oas install` is deterministic acquisition and lock restore. It must not issue
or accept invitations, mutate remote membership, or wait for interactive login.
Onboarding belongs in an explicit, trusted, idempotent setup step.

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

### What is NOT yet proven, stated here rather than in a footnote

**Nothing binds the launched runtime to the declared principal.** The spawn
hook verifies the principal and persists the binding in capability metadata
(`aweb-identity-attach.mjs`, spawn path), but contributes nothing to the launch.
OAS accepts a hook `launch` map of runtime → extra **command arguments**
(`lib/core.mjs:1452`); it has no hook **environment** map, and the authority
variable `AWEB_IDENTITY_HOME` (`cli/go/awconfig/identity_home.go:12`) is never
set for the session.

The precise claim is **no deterministic binding**, not "the model cannot act as
the principal". The launch command does not scrub ambient identity state, so a
session could still resolve *some* identity from the environment or working
directory it inherits. That is arguably worse than none, because it can appear
to work. What does not exist is any mechanism that makes it the *declared*
principal.

`.17` exercises the real spawn/retire lifecycle through
`oas spawn --no-launch`: kernel, hook dispatch, instance lifecycle and retire
path are all real, and only session launch is skipped. `.24` is a different
shape — it traces the attach path's complete HTTP request surface, and does not
depend on `--no-launch` at all.

So the established results are bounded **safety** results, and are exactly two:

- ordinary `oas retire` of an attached instance neither altered nor deleted the
  principal, and leaked no material into the instance (`.17`);
- the attach path cannot register the disposable instance path, so the
  gone-workspace destruction route is unreachable by construction (`.24`).

Neither establishes the absence of *every* harm — not provision-mode paths, not
future code, not a route nobody has tested. Do not restate these as "cannot harm
a principal". That it can *use* one is unproven, and requires an upstream
environment seam that does not exist today.

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
