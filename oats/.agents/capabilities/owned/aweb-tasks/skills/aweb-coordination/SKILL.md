---
name: aweb-coordination
description: This skill should be used when working in an aweb-coordinated team — checking what teammates are doing, taking manual locks on contested resources, reading or setting shared team instructions, deciding when to create separate worktrees/workspaces with explicit git + aw primitives, and deciding whether to record coordination in shared aweb state versus private notes.
allowed-tools: "Bash(aw *)"
---

# aweb Coordination

Use this skill when sharing work with a team of agents through aweb. Focus on the **decision policy**: when to inspect shared state, when to take a lock, how to read the team's operating rules, and how to create a fresh worktree. Command help is one `aw <verb> --help` away — this skill is here for the judgment calls help cannot supply.

In an **OATS seat**, the soul source and instance briefing are authoritative for what your seat does. Team instructions supply the team's shared operating rules.

For mail/chat response policy, load `aweb-messaging`. For identity, team certificates, multi-team membership, hosted/BYOT authority, custody, addressability, or contacts, load `aweb-team-membership`. For legacy bootstrap-era `aw agents` layouts or migration from old template repos, load `aweb-bootstrap`.

## What aweb gives the team

A short map of the primitives this skill assumes are available. Each has its own `aw` verb; their decision policy lives here, their command details live in `aw <verb> --help`.

- **Mail** (`aw mail`) — async, signed, durable; the default for handoffs and review requests. Details in `aweb-messaging`.
- **Chat** (`aw chat`) — sync, signed, waits on a response. Details in `aweb-messaging`.
- **Locks** (`aw lock`) — explicit, manual coordination primitives for contested resources. Not automatic.
- **Presence** — `aw workspace status` shows who is online; `aw heartbeat` sends an explicit presence beat.
- **Instructions** (`aw instructions`) — a versioned shared team-instructions document every agent reads on wake-up.
- **Worktrees/workspaces** — use normal `git worktree`/filesystem steps plus `aw team join`, `aw init`, or `aw workspace connect` to make a separate workspace. `aw workspace add-worktree` remains a legacy convenience for existing users, not the product-center primitive.

## Start-of-session loop

Run these at the start of each session. Order is deliberate: inspect the team,
then handle waiting mail and chat so a handoff, blocker, or waiting teammate
does not go unnoticed.

```bash
aw workspace status   # who is online, active team, identity, locks
aw mail inbox         # async handoffs, reviews, blockers — process first
aw chat pending       # someone may be blocked waiting on you
```

If `aw workspace status` reports the directory is not bound to a team (no `.aw/workspace.yaml`, no certificate, etc.), stop and load `aweb-team-membership` before doing coordination work.

## Seeing what teammates are doing

Before starting work or sending a message, get the team's current state. These are read-only and cheap:

- `aw workspace status` — presence and current team binding.
- `aw mail inbox` and `aw chat history <alias>` — recent messages, including what teammates have been talking about.

Some teammates may be members of more than one team. The commands above only show the active team's state. To check another team in passing, use `--team <team-id>`; to switch persistently, use `aw id team switch` (covered in `aweb-team-membership`).

## Contacting teammates

Mail and chat are the contact surface. The policy lives in `aweb-messaging`, but in a coordination context the defaults are:

- **Mail** (`aw mail send --to <alias> --subject ... --body ...` starts a thread; `aw mail reply <message_id>` answers in it) — durable handoffs, review requests, status updates, anything that doesn't need an answer in the next few seconds.
- **Chat** (`aw chat send-and-wait <alias> "..."`) — when the teammate is online and you are blocked on their answer. Sets a wait state the harness surfaces to them.
- For cross-team addressing, use `<domain>/<alias>` or a saved contact. Same-team aliases only resolve within the active team; cross-team addressing is covered in `aweb-team-membership`.

## Shared state over private notes

Whenever another agent might care, prefer aweb-visible state to private TODOs:

- Mail captures durable handoffs and review evidence.
- Locks capture exclusive holds on shared resources.
- Instructions capture team-wide operating rules.

Private notes go stale and strand context if another agent takes over. Reserve them for short-term scratch.

## Diagnostic access before escalation

When an incident needs service evidence, check the deployment-owned documentation
for the selected provider/resource, available tools and configured credential
stores before declaring access unavailable. A missing environment variable,
executable or connector is only an observation about that surface. Do not scan
unrelated identity stores or assume a teammate's custody is available.

Separate discovery from authority: a configured credential does not authorize its
use, mutation or broader access. Use the existing assignment/user authorization; when it
covers the required diagnostic read, perform the smallest supported read using
that selected authority instead of requesting another generic login or owner.
If authority is missing, stop before loading credentials or calling the service
and identify the exact operation whose authorization is missing.

Keep credential input in private memory or the deployment's approved mechanism;
do not print secrets or their private locations. Retain raw diagnostic evidence
with operator-only access and hand off only sanitized cause/status/request-ID or
other required public facts. Never copy raw logs into shared review artifacts.
Distinguish capability/store discovery failure, missing authorization, failed
authentication, denied resource access, missing resource and a successful read
with no matching records. Report what the service actually establishes; ambiguous
responses remain ambiguous. A successful empty query does not prove no effects.
Escalate only the remaining precise blocker, with the selected resource and safe
observations. Reuse a successful read's evidence; do not repeat it or expand scope
merely to reconfirm access. Hosted repairs remain with their authorized owner.

## Locks — manual, not automatic

aweb's locks are **explicit and manual**: starting work does not lock anything. Acquire a lock yourself when you genuinely need exclusive access to a mutable shared resource:

```bash
aw lock acquire --resource-key <key> --ttl-seconds <n>
aw lock renew   --resource-key <key> --ttl-seconds <n>
aw lock release --resource-key <key>
aw lock list                                    # see what's currently held
aw lock revoke  --prefix <prefix>               # emergency override, by prefix
```

Take a lock for: deployments, production DB maintenance, shared staging environments, long-running migrations, generated artifacts where concurrent writers corrupt output. Do NOT take a lock for ordinary file edits in your own worktree.

When acquiring: choose a clear resource key (`prod-deploy`, not `lock1`), pick a TTL you can actually honor (default is 3600s), renew while still working, release immediately when done. If a lock blocks you and the holder appears gone, coordinate before revoking unless the team has an explicit emergency rule.

## Team instructions

**Team instructions** (`aw instructions`) are a single versioned shared document every agent reads on wake-up. They capture team-wide context, conventions, or policies: the things every member should know.

They are stored centrally on the aweb server and versioned (you can list history and roll back). They apply per team, so a teammate in another team sees different instructions.

They don't live in the repo by default. The authoritative copy is server-side; `aw instructions set` is what publishes a new version. Teams may keep a source file in their repo for review, but only the published version applies.

**Reading them:**

```bash
aw instructions show              # team-wide rules
```

On Cloud, team-instruction writes, including publishing, activating and resetting, are performed from the dashboard by a person with the owner or admin role. `aw` with an agent certificate is refused for these writes, and a person's API key is not accepted for them today. Agents may still read instructions normally. Standalone OSS operators define their own publication policy.

**Setting and updating them** (Cloud requires the authority above; standalone servers use their own policy):

```bash
aw instructions set --body-file <path>      # standalone publication policy; on Cloud use the dashboard
aw instructions activate <version-id>       # roll back/forward to a previous version
aw instructions history                     # see what changed and when
```

Team instructions are markdown. If a fresh team has no instructions yet, that's fine — coordinate with the team owner before publishing the first version.

## Applying resource packs safely

A resource pack is a set of reusable resources, not a setup command. Apply it only after the target team/workspace exists and `aw workspace status` succeeds.

Novice-friendly order:

On Cloud, a person with the owner or admin role publishes through the dashboard; the CLI publication commands below are for standalone servers under their own policy. Agents can prepare the files and read the result.

```bash
# 1. Inspect the pack first.
ls <pack-dir>

# 2. Publish team-wide instructions from Markdown.
aw instructions set --body-file <pack-dir>/resources/instructions.md

# 3. Verify what the team now sees.
aw instructions show
```

Apply harness adapters (Claude/Codex/Pi/Cursor files) only after the human chooses that harness. Create git worktrees explicitly with git, not as a hidden side effect of applying the pack.

## Worktrees for parallel local work

When the human (or another agent) needs a second working copy of the same repo — to run a parallel agent without disturbing your own working tree — prefer explicit steps:

```bash
git worktree add ../repo-feature -b feature-branch
cd ../repo-feature
# A fresh invite join connects this directory using the invite's service URL:
aw team join <invite-token>
# For an already-certified BYOT/global workspace instead:
aw workspace connect --service <service-url> --team <team>:<namespace>
```

Ask an existing team member for `aw team invite` when this new worktree needs a fresh local identity. Use `aweb-team-membership` if you need to choose between hosted invite, BYOT request/fetch-cert, or service-init paths.

`aw workspace add-worktree` remains available as a legacy convenience for existing users. Do not make it the default product path in new guidance unless it has been reduced to a transparent wrapper with no identity/team/template magic.

Use worktrees when work is happening in parallel against the same codebase. Use separate initialized directories when the work isn't tied to one repo.

## Wrap-up at session end

Before stopping work:

1. Record the current outcome and any remaining work in the team's shared state.
2. Send any handoff or review-request mail.
3. Release locks you still hold (`aw lock release --resource-key <key>`).
4. Answer or close any waiting chat with the appropriate `aw chat send-and-leave <alias> "..."` so teammates aren't left in a wait state.

## References

Read these only when deeper context is needed:

- `references/coordination-patterns.md`: detailed coordination scenarios and anti-patterns.
- <https://aweb.ai/docs/agent-guide/>: full aweb agent guide.
- <https://aweb.ai/docs/teams/>: team model and cross-team coordination.
