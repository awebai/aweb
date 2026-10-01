# The aweb OATS workspace

The aweb OSS team (aweb team `aweb:juan.aweb.ai`) runs on OATS workspace model
v2, kernel 0.30 or later. This repository hosts the workspace and is its only
member. Each machine realizes the workspace with its own deployment directory
and `oats-local.yaml`.

Souls are named by function. A standing instance is spawned with `--name`, and
its aweb alias is its instance name. A task-purpose instance is spawned with
`--purpose` and is named `<soul>-<purpose>`. Teammates address each other by
instance name.

| Instance (aweb alias) | Soul | Spawned as |
|---|---|---|
| aweb | `coordinator` | `oats spawn coordinator --name aweb` with the retained identity (see [the hand-over](#hand-over-from-the-classic-seats)) |
| `aweb-protocol-expert-<purpose>` | `aweb-protocol-expert` | `oats spawn aweb-protocol-expert --purpose <slug>` |
| `aweb-expert-<purpose>` | `aweb-expert` | `oats spawn aweb-expert --purpose <slug>`, adding `--work worktree` for an implementation |

Only the coordinator spawns and retires aweb instances.

## Layout

| Path | What it is |
|---|---|
| `oats-workspace.yaml` | The shared declaration: members, pinned packages, the shared team `aweb` (`aweb:juan.aweb.ai`), defaults and the knowledge store. |
| `oats-membership.yaml` | The backlink that completes the membership handshake. |
| `souls/<name>/` | The three souls: `soul.yaml`, `AGENTS.md` (`CLAUDE.md` links to it) and `okf.json` (the node it owns and the nodes it reads). |
| `knowledge/` | The aweb knowledge base (id `aweb-oss-knowledge`): one node per soul, owned by the id in `knowledge/okf-base.json`. |
| `agents/` | The classic souls and the pre-OATS coordinator record (`agents/coordinator/decisions`, `docs`, `memory`). OATS v2 does not discover them. They are removed after the hand-over. |

Every soul gets `oats.core`, `oats.okf` (knowledge) and `oats.aweb`
(messaging) from the pinned packages. The OATS tasks slot is empty: tasks live
on the aweb board of team aweb, used with `aw task …` from each instance home.

| Soul | Work mode | Launch preference |
|---|---|---|
| `coordinator` | `workspace`: `./work` is the deployment; member repositories are read context | Codex, its own default model |
| `aweb-expert` | `workspace`; `--work worktree` for an implementation | Claude; the model is still to decide |
| `aweb-protocol-expert` | `worktree` | Claude; the model is still to decide |

Yolo is a host fact, not a soul's: each machine sets it in `oats-local.yaml`
(below).

### Knowledge reads

| Soul | Owns | Reads |
|---|---|---|
| `coordinator` | `aweb/coordinator` | all three nodes |
| `aweb-expert` | `aweb/aweb-expert` | its own node and `aweb/aweb-protocol-expert` |
| `aweb-protocol-expert` | `aweb/aweb-protocol-expert` | its own node and `aweb/aweb-expert` |

The coordinator routes and reviews work in both experts' domains, so it reads
both. Each expert reads the other because their reviews overlap: protocol-shaped
work is co-reviewed, and the direction decisions bound the contracts. The
experts do not read the coordinator node, which starts empty. Its legacy
material is the classic coordinator's bundle, and the knowledge migration
promotes it later. Once it holds accepted lessons, adding the node to an
expert's `reads` is a one-line change.

## Each machine's deployment: `~/Agents/aweb`

Instance homes live outside the repository, in a deployment directory on each
machine. The deployment points at the machine's aweb checkout through
`clones:`.

```
~/Agents/aweb/
├── oats-local.yaml        # this machine's file; never committed
├── oats-lock.json         # written by `oats sync`
├── agents/                # instance homes: agents/<soul>/instances/<instance>/
└── okf/
    ├── bindings.json      # where the knowledge base lives, for this machine
    └── state/             # harvest evidence and the consult cache
```

Start it with `oats onboard ~/Agents/aweb --workspace git:github.com/awebai/aweb`,
then complete `oats-local.yaml`:

```yaml
schemaVersion: 2
workspace: git:github.com/awebai/aweb

clones:
  github.com/awebai/aweb: <path to your awebai/aweb checkout>

defaultTeam: aweb                                 # the shared team: aweb:juan.aweb.ai

settings:
  oats.aweb:
    delivery: session                             # the host wake broker delivers to every instance but the coordinator
    # root: written by `oats aweb setup`, a minting root for team aweb. Never the
    # coordinator's retained identity directory: that identity has one holder.
  oats.okf:
    bindings-file: <absolute path of ~/Agents/aweb>/okf/bindings.json

launch-configs:                                   # yolo for every launch of each harness (0.32)
  codex:  { harness: codex,  default: true, yolo: true }
  claude: { harness: claude, default: true, yolo: true }

host:
  name: <this machine's name>
```

The `default: true` launch configurations need kernel 0.32. On an older kernel,
pass `--yolo` at spawn instead.

The knowledge bindings file binds the base alias `aweb`, the name every soul's
`okf.json` uses. The classic deployment bound the same base as `aweb-oss`, and
that alias does not carry over. The binding's `id` must equal the one in
`knowledge/okf-base.json`:

```json
{
  "version": 1,
  "stateDir": "<absolute path of ~/Agents/aweb>/okf/state",
  "bases": {
    "aweb": {
      "id": "aweb-oss-knowledge",
      "kind": "git",
      "repository": "git@github.com:awebai/aweb.git",
      "root": "knowledge",
      "acceptedBranch": "main",
      "pr": { "repository": "awebai/aweb" }
    }
  }
}
```

Harvest is off unless a machine switches it on
(`settings.oats.okf.harvest: on`). A soul cannot be spawned until its
`okf.json` exists, and oats.okf refuses a soul directory that still holds a
legacy `knowledge/` bundle (`E_MIGRATION`). The migration stages bundles there,
so `souls/*/knowledge/` is gitignored.

## One holder per instance name

An instance name has exactly one live instance across every machine of this
workspace, and the table below records where it lives.

- **Moving an instance** means retiring it on one machine before spawning it
  on the other. The instance first brings STATE.md and its task records up to
  date at a safe boundary. The coordinator retires it (`oats retire
  <instance>`), confirms it is gone (`oats status` on that machine,
  `oats aweb roster`), updates this table, and only then spawns it on the other
  machine.
- **The coordinator cannot move itself**, since it would have to spawn after it
  is retired. Juan moves the coordinator, by the same sequence.
- **`juan.aweb.ai/aweb` has one holder.** The retained identity is held by
  exactly one seat. A classic seat and an OATS seat at once are two holders,
  even for a hand-over. The oats.aweb seat lock beside the retained `.aw`
  refuses a second seat while the holder's home exists. Never override it with
  `identity.takeOver: true` unless the old runtime is known to be dead.
- Anyone who sees a second live instance of a name, or a second holder of the
  coordinator identity, stops working as that instance and tells the
  coordinator and Juan.
- The coordinator keeps this table current: a spawn, retirement or move is
  recorded here the same day.

| Instance | Soul | Machine | Live |
|---|---|---|---|
| aweb | coordinator | the classic seat's machine | the classic seat holds the identity; the OATS seat is not yet spawned |

Task-purpose instances are recorded here only while they run.

## The coordinator's message wake stays deregistered

This is Juan's rule, and a new home does not change it. Every other instance
uses session delivery, so its spawn and launch hooks register it with the host
wake broker (`aw wake register`). The coordinator must not be registered.

A soul cannot enforce this. The provider payload merges the soul's settings,
then `oats-local.yaml` `settings`, then the spawn's `--provider` flags, and the
later layer wins. The machine's `delivery: session` would override a soul's
`delivery: channel`. The rule is therefore a fact about the spawn: the seat is
spawned with `--provider oats.aweb delivery=channel`. That is recorded in the
instance's `instance.json` and survives restarts, and in channel mode no hook
registers the home. The Codex harness has no aweb channel, so nothing presents
mail in the session. The coordinator checks `aw mail inbox` and
`aw chat pending` at every task boundary.

After the spawn, `aw wake status` must not list the coordinator's home. If it
does, `aw wake deregister --home <home>` removes it. Removing it after a
session-mode spawn is not a substitute for the spawn flag, because a later
launch would register the home again.

## Session delivery and the recovery rule

Every other instance runs with `delivery: session`: the host wake broker
presents each new mail and chat in its terminal, either as a line naming what is
waiting or as the full event, and the server marks it read on delivery.

Read state therefore says nothing about completion. After a crash, restart,
compaction or any uncertain interval, an instance reconciles STATE.md and its
task records against the exact message ids delivered to it. It uses
`aw mail show --message-id <id> --json`, or a paginated
`aw mail inbox --show-all --json` (passing each `next_cursor` back with
`--cursor`) through the uncertain interval. `--conversation-id` is not a
recovery check. Before retrying an earlier side effect (a sent mail, a task
comment, a push, a tag), the instance checks that effect's receipt.

## Hand-over from the classic seats

The classic seats run from the classic deployment (`<classic deployment root>`,
OATS workspace model v1). At drafting time (2026-09-30) its homes were the
coordinator seat `coordinator-aweb` and three task-purpose runs of
aweb-protocol-expert: `grant-fixes`, `wake-stability` and
`server-cli-stability`. These are runs of the one soul, not separate souls.
Verify liveness at hand-over time rather than relying on this list.

A classic seat retires only after **a recorded safe boundary** and **an
identity, claim and memory disposition**. Both are recorded on the seat's task,
or in this document for the coordinator, before `oats retire` runs.

1. **Prerequisites.** This workspace is on the default branch, and
   `~/Agents/aweb` is onboarded and synced (`oats sync`). `oats workspace
   status` shows the member as `confirmed`. The knowledge base is bound as
   `aweb`, and `oats aweb setup` has a minting root for team aweb.
2. **Safe boundary, per seat.** Nothing is in flight: no integration or landing
   half-done, no push or tag unconfirmed. STATE.md and the task records are
   current and reconciled under the recovery rule above.
3. **Disposition, per seat.**
   - *Identity.* The coordinator's identity is retained and re-taken by the
     OATS seat. A task-purpose seat's identity retires with it, unless the
     record says why it is kept.
   - *Claims.* Each claim is completed, released, or carried to a named
     successor with a task comment. The coordinator's claims stay with its
     identity and are checked from the new home.
   - *Memory.* STATE.md, log.md, notes and any instance knowledge are harvested
     into the soul's node, preserved under `agents/<soul>/` as history, or
     recorded as dropped. The classic coordinator's knowledge bundle
     (`agents/coordinator/soul/knowledge`) is staged into
     `souls/coordinator/knowledge/` (gitignored). It is migrated into the
     provisioned `knowledge/coordinator` node with `oats okf migrate` and
     delivered by a reviewed pull request. Its Markdown links to the
     historical `decisions`, `docs` and `memory` records need a decision at
     migration time.
4. **The coordinator, moved by Juan.** At the safe boundary, retire
   `coordinator-aweb` from the classic deployment. That releases the seat lock
   beside `<home of the retained coordinator identity>/.aw` and leaves the
   identity untouched.
   Confirm that the classic home and the lock are gone. Then, from
   `~/Agents/aweb`:

   ```bash
   oats spawn coordinator --name aweb \
     --provider oats.aweb identity.source="<home of the retained coordinator identity>/.aw" \
     --provider oats.aweb delivery=channel
   ```

   From the new home, `aw workspace status` must show `juan.aweb.ai/aweb` with
   the classic seat's did, `aw wake status` must not list the home, and the
   seat's claims must be visible. There is no re-onboarding: never `aw init`
   or `oats aweb setup` for the seat. Record the move in the table above.
5. **The expert runs.** Each classic task-purpose run reaches its safe
   boundary, gets its disposition recorded, and retires. Continuing work is
   respawned by the coordinator as an OATS task-purpose instance.
6. **After the last classic seat retires,** a follow-up change removes the
   classic `agents/` souls. The coordinator's historical record stays
   available until its knowledge migration has landed. The classic deployment
   is decommissioned on Juan's decision.
