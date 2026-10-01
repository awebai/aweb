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
| `aweb-expert` | `workspace`; `--work worktree` for an implementation | TODO(decide): harness and model (the classic soul recorded `claude` and no model; `soul.yaml` carries `claude` until decided) |
| `aweb-protocol-expert` | `worktree` | TODO(decide): harness and model (the classic soul recorded `claude` and no model; `soul.yaml` carries `claude` until decided) |

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
workspace. Where each instance lives, and who holds what, is read from shared
state (`oats status` on each machine, `oats aweb roster`,
`aw workspace status`), never from a copy in this repository.

- **Moving an instance** means retiring it on one machine before spawning it
  on the other. The instance first brings STATE.md and its task records up to
  date at a safe boundary. The coordinator retires it (`oats retire
  <instance>`), confirms it is gone (`oats status` on that machine,
  `oats aweb roster`), and only then spawns it on the other machine.
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

## The coordinator's message wake stays deregistered

This is Juan's rule, and a new home does not change it. Every other instance
uses session delivery, so its spawn hook registers it with the host wake broker
(`aw wake register`). The coordinator must not be registered.

A soul cannot enforce this. The provider payload merges the soul's settings,
then `oats-local.yaml` `settings`, then the spawn's `--provider` flags, and the
later layer wins. The machine's `delivery: session` would override a soul's
`delivery: channel`. The rule is therefore a fact about the spawn: the seat is
spawned with `--provider oats.aweb delivery=channel`. The Codex harness has no
aweb channel, so nothing presents mail in the session. The coordinator checks
`aw mail inbox` and `aw chat pending` at every task boundary.

After the spawn, `aw wake status` must not list the coordinator's home. If it
does, stop and find out why before removing it with
`aw wake deregister --home <home>`.

### Provider evidence (oats.aweb v1.17.3)

What follows is read from the pinned package source, not from an experiment:
`oats-package/capabilities/oats-aweb/bin/oats-aweb.mjs` at tag `v1.17.3`
(commit `84c30c72336a9d00b2cd7015bd41fbe9c14a04cd`, cited as `oats-aweb.mjs`),
plus `oats-package/capabilities/oats-aweb/lib/wake-receive.mjs` at the same
tag. The kernel lines are from `lib/core.mjs` in `@awebai/oats` 0.32.0.

- **`delivery=channel` is persisted in the instance meta.** Every hook computes
  its delivery mode from the merged settings it receives as `OATS_SETTINGS`
  (`oats-aweb.mjs:216`, `:220-223`; anything but `session` is `channel`). The
  retained-seat spawn writes it into the hook's meta as
  `delivery: deliveryMode` (`oats-aweb.mjs:833`), as does the minted-identity
  spawn (`:1336`). The kernel stores each hook's meta per capability in
  `instance.json` (`core.mjs:1420`) and passes it back to the launch hook as
  `OATS_META` (`core.mjs:4706`). The launch paths read `meta.delivery` first
  (`oats-aweb.mjs:541`, `:1194`).
- **No `aw wake register` for a channel home at spawn or relaunch.**
  `wakeRegister` (`oats-aweb.mjs:421`) has these call sites:
  - `:828`, the retained-seat spawn, behind `deliveryMode === "session"`;
  - `:1332`, the minted spawn, behind the same test;
  - `:663`, the global-grant spawn, inside `if (deliveryMode === "session")` at
    `:662`;
  - `:605`, global-grant renewal, behind `newMeta.delivery === "session"`
    (`:604`), and reached only for `identity.mode: global` or
    `identity.renew: launch` (`:1217`; renew defaults to `off`, `:444`);
  - `:1209`, inside `syncWakeReceive`, behind `delivery === "session"`.

  The other registration, `:1201`, sends the document built by
  `wakeRegistration` (`wake-receive.mjs:28-37`). That document is null without
  joined teams, and null for any runtime other than Claude or Pi in channel
  mode (`wake-receive.mjs:18-23`, `:30`). The launch hook
  (`oats-aweb.mjs:1216-1250`) and a live join (`:1147`) reach registration only
  through `syncWakeReceive`. For a Codex seat in channel mode the source
  therefore shows no registration at spawn, launch, restart or join. Two
  limits: if the coordinator's harness became Claude or Pi and it joined a
  second team, the broker would attach that team's identity (mixed mode), but
  never the primary one. And retiring a session-mode home deregisters it
  (`:1368`), which a channel home never needs.
- **The retained-identity path keeps the same DID.** The spawn copies only the
  identity authority files (`signing.key`, `identity.yaml`, `teams.yaml`,
  `team-certs`, `encryption.yaml`, `encryption-keys`; `oats-aweb.mjs:412`,
  `:778-786`). It drops the old workspace binding and delivery state (`:787`),
  and re-binds the service workspace to the new home with
  `aw workspace connect` (`:790`). It then fails the spawn, rolling the binding
  back to the old home, unless `aw whoami --json` from the new home shows the
  copied identity's did and address (`:814-815`) and the alias matches the
  address (`:819`). The seat lock (`:701`, `:736`) refuses a second seat while
  the holder's home exists.
- **Claims carried over: unproven.** Task claims belong to the server-side
  workspace record (`docs/cli-command-reference.md`, `team admin
  remove-agent`). The oats.aweb source shows only that the record is re-bound
  by `aw workspace connect` (`:790`), and that v1.17.3's retire of a retained
  seat never runs `aw workspace delete` (`:1365-1367`, `:1379`). It does not
  show that the server keeps the same record, with its claims, across the
  re-bind. It also does not cover the retire hook of the classic deployment's
  own oats.aweb version. The hand-over therefore inventories claims before
  retirement and compares them after the spawn (below).

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
OATS workspace model v1). Which seats exist, and which are live, is read from
that deployment's `oats status` and from `aw workspace status` at hand-over
time. Classic aweb-protocol-expert runs such as `grant-fixes`,
`wake-stability` and `server-cli-stability` are task-purpose runs of the one
soul, not separate souls.

A classic seat retires only after **a recorded safe boundary** and **an
identity, claim and memory disposition**. Both are recorded on the seat's
hand-over task before `oats retire` runs. Retiring a home deletes that home,
so nothing it alone holds may be needed afterwards.

1. **Prerequisites.** This workspace is on the default branch, and
   `~/Agents/aweb` is onboarded and synced (`oats sync`). `oats workspace
   status` shows the member as `confirmed`. The knowledge base is bound as
   `aweb`, and `oats aweb setup` has a minting root for team aweb.
2. **Safe boundary, per seat.** Nothing is in flight: no integration or landing
   half-done, no push or tag unconfirmed. STATE.md and the task records are
   current and reconciled under the recovery rule above.
3. **The retained identity lives outside the home that retirement removes.**
   For the coordinator, `identity.source` is an external `.aw`. The seat's
   home holds only a copy, which goes with the home. Before retirement, show
   that this is still true and record the output on the hand-over task:

   ```bash
   set -euo pipefail
   CLASSIC_HOME="<classic coordinator home>"                       # what `oats retire` removes
   IDENTITY_SOURCE="<home of the retained coordinator identity>/.aw"
   home=$(cd "$CLASSIC_HOME" && pwd -P)
   src=$(cd "$IDENTITY_SOURCE" && pwd -P)
   case "$src/" in "$home/"*) echo "STOP: the identity is inside the home retirement removes" >&2; exit 1 ;; esac
   case "$home/" in "$src/"*) echo "STOP: the home is inside the identity directory" >&2; exit 1 ;; esac
   test -f "$src/signing.key" && test -f "$src/identity.yaml"
   # The source the classic seat re-took, as its instance.json records it; it must equal $src.
   jq -r '[.. | objects | select(has("identity")) | .identity | objects | .source // empty] | unique | .[]' "$home/instance.json"
   grep -E '^(did|address):' "$src/identity.yaml"                  # record did and address; never print key files
   ```

4. **Hand-over archive, before the home is removed.** Archive the seat's
   STATE.md, log.md, `notes/`, the `tmp/` receipts its tasks or STATE.md
   reference, and its claim inventory. The archive goes to a named restore
   destination outside both the classic home and the new deployment's agents
   root. No key material is copied anywhere: not into the archive, this
   repository, a pull request or a log.

   ```bash
   set -euo pipefail
   CLASSIC_HOME="<classic coordinator home>"
   ARCHIVE="<hand-over archive directory>"                         # the restore destination
   AGENTS_ROOT="<absolute path of ~/Agents/aweb>/agents"
   mkdir -p "$ARCHIVE"
   home=$(cd "$CLASSIC_HOME" && pwd -P); a=$(cd "$ARCHIVE" && pwd -P)
   for d in "$home" "$AGENTS_ROOT"; do case "$a/" in "$d/"*) echo "STOP: archive inside $d" >&2; exit 1 ;; esac; done
   RECEIPTS=(<each task-linked tmp/ receipt, relative to the home>)
   (cd "$home" && rsync -aR --exclude='.aw/' --exclude='*.key' --exclude='encryption-keys/' \
     STATE.md log.md notes "${RECEIPTS[@]}" "$a/")
   # Read-back: every archived file matches its source byte for byte.
   (cd "$a" && find . -type f ! -name 'claims-*' ! -name 'MANIFEST.sha256' -print0 | xargs -0 shasum -a 256) > "$a/MANIFEST.sha256"
   (cd "$home" && shasum -a 256 -c "$a/MANIFEST.sha256")
   # No key material in the archive.
   if [ -n "$(find "$a" \( -name '.aw' -o -name '*.key' -o -name 'encryption-keys' \) -print)" ] || grep -rIl 'PRIVATE KEY' "$a"; then
     echo "STOP: key material in the archive" >&2; exit 1
   fi
   ```

   Then, from the classic home and each as its own command, write the claim
   inventory into the archive: `aw workspace status --json` into
   `claims-before.json`, and `aw work active --json` into
   `claims-work-active-before.json`. Record the archive path on the
   hand-over task.
5. **Disposition, per seat.**
   - *Identity.* The coordinator's identity is retained and re-taken by the
     OATS seat. A task-purpose seat's identity retires with it, unless the
     record says why it is kept.
   - *Claims.* Each claim is completed, released, or carried to a named
     successor with a task comment. The coordinator's claims are expected to
     stay with its identity. That is unproven (see the provider evidence), so
     they are compared against the inventory after the spawn.
   - *Memory.* The empty `knowledge/coordinator` node must not strand
     anything. The classic coordinator's knowledge bundle
     (`agents/coordinator/soul/knowledge`) is migrated before or with the
     retirement: staged into `souls/coordinator/knowledge/` (gitignored),
     migrated into the node with `oats okf migrate`, and delivered by a
     reviewed pull request. Its Markdown links to the historical `decisions`,
     `docs` and `memory` records need a decision at migration time. Those
     records stay in `agents/coordinator/` until that migration has landed.
     The seat's pending notes are harvested into the node before or with the
     retirement, not after. The archive keeps the bundle, its history and the
     notes until the promoted knowledge is verified on the accepted branch.
6. **The coordinator, moved by Juan.** At the safe boundary, with steps 3–5
   recorded, retire `coordinator-aweb` from the classic deployment. That
   releases the seat lock beside the retained `.aw` and leaves the identity
   untouched. Confirm that the classic home and the lock are gone. Then, from
   `~/Agents/aweb`:

   ```bash
   oats spawn coordinator --name aweb \
     --provider oats.aweb identity.source="<home of the retained coordinator identity>/.aw" \
     --provider oats.aweb delivery=channel
   ```

   From the new home, `aw whoami --json` must show the did and address
   recorded in step 3, and `aw wake status` must not list the home. Compare
   `aw workspace status --json` and `aw work active --json` with the archived
   inventory. A claim missing from the new home is reported to Juan before any
   work continues. There is no re-onboarding: never `aw init` or
   `oats aweb setup` for the seat.
7. **The expert runs.** Each classic task-purpose run reaches its safe
   boundary, is archived and gets its disposition recorded as above, and
   retires. Continuing work is respawned by the coordinator as an OATS
   task-purpose instance.
8. **After the last classic seat retires,** and once the coordinator's
   knowledge migration has landed and been verified, a follow-up change
   removes the classic `agents/` souls. The archives are released only after
   that verification. The classic deployment is decommissioned on Juan's
   decision.
