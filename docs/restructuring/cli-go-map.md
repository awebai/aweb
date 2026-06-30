# aw Go CLI map for restructuring

Purpose: file:line-anchored map of the current Go `aw` CLI (`cli/go/`) for restructuring SOT §10 and milestone 2. This maps the current implementation against the existing folio plugin design brief at `/Users/juanre/prj/awebai/folio/docs/aw-plugin-brief.md`; the current-vs-brief gap is the work still ahead. Verified against branch `aw-developer` on 2026-06-16 after merging current `main`. Unless otherwise noted, file paths below are relative to `cli/go/`.

## Existing design brief baseline

The folio brief proposes a kubectl/gh-style mechanism:

- On unknown `aw <name>`, resolve executable `aw-<name>` from `~/.aw/plugins/` and `PATH`, then `exec` it with remaining args.
- Keep app verbs out of core `aw`; a plugin is a separate binary in any language.
- Pass context by environment, not argv secrets: `AW_DID`, `AW_TEAM`, `AW_SERVER`, `AW_HOME`/profile, and `AW_HELPER` (path to `aw`).
- Plugins should use `AW_HELPER` to call `aw id request --team-auth ...`, keeping signing keys/team certificates inside `aw`.
- Provide `aw plugin list/install/remove` and optional `aw plugin search`.

## Headline current-vs-brief gap: plugin / external binary dispatch is absent

Current `aw` is a closed Cobra command tree. There is no implemented `aw plugin ...` command, no `~/.aw/plugins/` search path, no `AW_DID`/`AW_TEAM`/`AW_SERVER`/`AW_HOME`/`AW_HELPER` plugin env contract, and no kubectl/gh-style unknown-command fallback that searches `$PATH` for `aw-<name>`.

Evidence:

- Cobra root is a normal `*cobra.Command` named `aw`; it relies on Cobra's built-in dispatch and error path (`cmd/aw/root.go:25`, `cmd/aw/root.go:137`).
- Root command groups and persistent flags are registered statically (`cmd/aw/root.go:59`, `cmd/aw/root.go:101`).
- Top-level commands are added by static `rootCmd.AddCommand(...)` calls in `init()` functions, e.g. `cmd/aw/root.go:125`, `cmd/aw/agents.go:13`, `cmd/aw/task.go:18`, `cmd/aw/work.go:58`, `cmd/aw/lock.go:210`, `cmd/aw/roles.go:151`, `cmd/aw/instructions.go:85`.
- `find . -iname '*plugin*'` finds no aw plugin-management implementation; textual `plugin` hits are Claude plugin setup strings (`cmd/aw/init.go:479`, `cmd/aw/channel_setup.go:131`) or unrelated tests, not `aw plugin`.
- Runtime check after `make build`: `./aw plugin list` returns `unknown command "plugin" for "aw"`; `./aw definitely-not-a-command` returns `unknown command "definitely-not-a-command" for "aw"`.
- `exec.Command`/`exec.LookPath` uses are specific integrations, not plugin dispatch: provider execution in `run/loop.go`, shell services in `run/services.go`, git worktree helpers in `cmd/aw/workspace.go`, and macOS codesign in `cmd/aw/upgrade.go`. The old `cmd/aw/team_bootstrap.go` helpers were removed with the retired `aw agents` family.

Brief gap for SOT §10 / milestone 2: all plugin mechanics in the brief are absent today. The only current seam to map is Cobra's unknown-command error path plus the existing generic signed-request helper (`aw id request --team-auth`).

## Build / smoke verification

- `cd cli/go && make build` succeeded; the build target runs `go build -o aw ./cmd/aw` (`Makefile:16`).
- `./aw version` printed `aw dev`.
- `./aw --help` showed the static command groups: Workspace Setup, Identity, Messaging & Network, Coordination & Runtime, Obsolete / Legacy Compatibility, Utility.
- Source package inventory: `go list ./...` shows `github.com/awebai/aw`, `a2a`, `a2agw`, `awconfig`, `awid`, `chat`, `cmd/aw`, `cmd/aweb-a2a-gw`, `internal/conformance`, `internal/identityutil`, and `run`.
- Current Go command files: 150 files under `cmd/aw`, 153 under all `cmd/`.

## Command dispatch model

- Entry point is `cmd/aw/main.go:11` -> `Execute()`.
- `Execute()` calls `rootCmd.Execute()`, then maps errors through `checkVerificationRequired` and `exitCode` (`cmd/aw/root.go:137`).
- Root persistent pre-run loads `.env`/`.env.aweb` and performs best-effort update checks unless disabled (`cmd/aw/root.go:29`, `cmd/aw/helpers.go:27`).
- Root flags are global `--server-name`, `--debug`, `--json` (`cmd/aw/root.go:101`).
- Team selection is not universal: `bindTeamSelector` adds `--team` only to selected commands (`cmd/aw/root.go:104`, `cmd/aw/root.go:130`).
- The `id` parent command is registered in `cmd/aw/agents.go:7` and `cmd/aw/agents.go:13`.
- The `task` parent command is registered in `cmd/aw/task.go:12` and `cmd/aw/task.go:18`; subcommands are spread across `task_*.go` (`cmd/aw/task_create.go:27`, `cmd/aw/task_list.go:25`, `cmd/aw/task_update.go:29`, `cmd/aw/task_close.go:22`, `cmd/aw/task_reopen.go:21`, `cmd/aw/task_delete.go:19`, `cmd/aw/task_dep.go:41`, `cmd/aw/task_comment.go:33`, `cmd/aw/task_stats.go:19`).
- `work ready|active|blocked` is a thin task/claim view (`cmd/aw/work.go:14`, `cmd/aw/work.go:55`, `cmd/aw/work.go:61`, `cmd/aw/work.go:104`, `cmd/aw/work.go:155`).
- `lock acquire|renew|release|revoke|list` maps to reservations (`cmd/aw/lock.go:13`, `cmd/aw/lock.go:25`, `cmd/aw/lock.go:63`, `cmd/aw/lock.go:98`, `cmd/aw/lock.go:132`, `cmd/aw/lock.go:165`, `cmd/aw/lock.go:209`).
- `roles` and `instructions` are first-class static commands (`cmd/aw/roles.go:19`, `cmd/aw/roles.go:143`, `cmd/aw/instructions.go:15`, `cmd/aw/instructions.go:80`).
- `workspace status|connect|add-worktree|migrate-multi-team|delete` is static (`cmd/aw/workspace.go:21`, `cmd/aw/workspace.go:121`).
- `run <provider>` is a static command; it intentionally says it excludes bead-specific dispatch (`cmd/aw/run.go:61`, `cmd/aw/run.go:78`).

## Client creation and request signing path

Normal coordination commands follow this path:

1. Command handler calls `resolveClientSelection()` / `resolveClient()` (examples: `cmd/aw/work.go:61`, `cmd/aw/lock.go:34`, `cmd/aw/roles.go:161`, `cmd/aw/instructions.go:89`).
2. `resolveClientSelectionForDirWithTeamOverride` loads a workspace selection, normalizes the base URL, creates a certificate-authenticated client, configures address/resolver/pin-store state, and stores `lastClient` (`cmd/aw/helpers.go:217`, `cmd/aw/helpers.go:431`, `cmd/aw/helpers.go:456`).
3. The wrapper client in `client.go` embeds `awid.Client` and adds coordination methods (`client.go:13`, `client.go:28`).
4. `awid.NewWithCertificate` checks the local signing key matches the certificate member DID, encodes the team certificate header, and stores team id/cert alias (`awid/client.go:250`).
5. `awid.DoWithHeaders` / `DoRawWithHeaders` is the common HTTP JSON path (`awid/client.go:867`, `awid/client.go:899`).
6. For team-certificate clients, every request is signed with `Authorization: DIDKey ...`, `X-AWEB-Timestamp`, and `X-AWID-Team-Certificate`; the canonical payload is `{body_sha256, team_id, timestamp}` (`awid/client.go:934`, `awid/client.go:936`, `awid/client.go:980`).
7. For identity-only clients, the request gets `Authorization`, `X-AWEB-Timestamp`, and optional `X-AWEB-DID-AW`; the canonical payload is `{body_sha256, did_aw, timestamp}` (`awid/client.go:941`, `awid/client.go:994`).
8. Messaging envelopes have a separate signed-envelope path that signs the canonical `MessageEnvelope` and stamps `signature`, `signing_key_id`, `timestamp`, and `signed_payload` (`awid/client.go:79`, `awid/signing.go:115`).

Raw app/plugin prerequisite path today, matching the brief's `AW_HELPER` idea:

- `aw id request <method> <url>` is implemented at `cmd/aw/id_request.go:58` and `cmd/aw/id_request.go:110`.
- `--team-auth` is wired at `cmd/aw/id_request.go:73`; when present it builds a v2 team-bound payload with `aud`, `method`, `path`, `team_id`, `body_sha256`, and `v` (`cmd/aw/id_request.go:268`, `cmd/aw/id_request.go:290`).
- The signed request then attaches `Authorization`, `X-AWEB-Timestamp`, `X-AWEB-Signed-Payload`, and `X-AWID-Team-Certificate` (`cmd/aw/id_request.go:155`).
- This is the only current generic app-call primitive; there is no `aw <app>` plugin dispatcher, plugin env contract, or helper-path injection around it yet.

## Local identity / AWID / bootstrap map

Local files and selection:

- Workspace binding schema is `WorktreeWorkspace` with `aweb_url`, memberships, repo/canonical origin, hostname, and workspace path (`awconfig/workspace.go:23`).
- Identity state is `WorktreeIdentity` with `schema_version`, `did`, `stable_id`, address, custody, canonical `identity_scope`, deprecated-read-compat `lifetime`, registry URL/status, created-at (`awconfig/identity.go`).
- Local signing key path is `.aw/signing.key` (`awconfig/identity.go:35`, `awconfig/identity.go:47`).
- Active team is read from `.aw/teams.yaml`; `ActiveMembershipFor` chooses the workspace membership whose team id matches team state (`awconfig/team_state.go:125`, `awconfig/team_state.go:275`).
- `ResolveWorkspace` merges workspace, team state, identity, certificate, env URL override, and optional `--team` override into an `awconfig.Selection` (`awconfig/selection.go:26`, `awconfig/selection.go:59`, `awconfig/selection.go:137`).
- `ResolveIdentity` loads `.aw/identity.yaml` and computes handle/domain from address (`awconfig/identity.go:101`).

AWID primitives:

- DID key computation: `awid/didkey.go:15`.
- Ed25519 key generation/load/save: `awid/keys.go:14`, `awid/keys.go:40`, `awid/keys.go:45`.
- Team certificate sign/load/save/header encoding: `awid/certificate.go:50`, `awid/certificate.go:159`, `awid/certificate.go:169`, `awid/certificate.go:183`.
- Registry team id parsing: `awid/team_id.go:20`.
- Registry identity registration: `awid/registry_register.go:32`.
- CLI hosted signup request/response path: `awid/onboarding_cli_signup.go:47`, `awid/onboarding_cli_signup.go:91`.

Bootstrap / setup commands:

- `aw init` is the main workspace bootstrap; `runInit` branches between addon-only setup, API-key bootstrap, certificate connect, implicit local flow, and guided onboarding (`cmd/aw/init.go:108`).
- `aw id create` creates a standalone global identity and persists `.aw/` material (`cmd/aw/id_create.go:42`, `cmd/aw/id_create.go:91`).
- `aw id register|show|resolve|verify|namespace` are registry commands (`cmd/aw/id_registry.go:71`, `cmd/aw/id_registry.go:118`).
- `aw id team ...` covers hosted invite/accept plus BYOT/admin certificate operations (`cmd/aw/id_team.go:251`, `cmd/aw/id_team.go:396`).
- `aw workspace connect` is an alias to `aw service init`, deliberately not a team/identity creator (`cmd/aw/workspace.go:41`).
- `aw workspace add-worktree` remains a legacy convenience that shells out to git worktree operations (`cmd/aw/workspace.go`) and uses the shared invite/connect helper in `cmd/aw/workspace_invite.go`.

## Coordination surface and SOT movement

Current CLI surface that the SOT moves out of core or splits:

| Surface | Current CLI | Current client/API | SOT target |
|---|---|---|---|
| Tasks | `aw task ...` static parent and subcommands (`cmd/aw/task.go:12`) | `/v1/tasks`, `/v1/tasks/ready`, `/v1/tasks/blocked`, `/v1/tasks/active`, `/v1/tasks/{ref}` (`tasks.go:152`, `tasks.go:190`, `tasks.go:198`, `tasks.go:206`, `tasks.go:214`, `tasks.go:226`) | tasks app; keep compat aliases during transition |
| Work discovery | `aw work ready|active|blocked` (`cmd/aw/work.go:14`, `cmd/aw/work.go:55`) | combines claims + task ready for `ready` (`cmd/aw/work.go:70`, `cmd/aw/work.go:80`), uses `/v1/tasks/active` and `/v1/tasks/blocked` (`tasks.go:206`, `tasks.go:198`) | tasks/dev app surface; not core |
| Claims | no `aw claim` parent; visible through `aw work ready`, `aw workspace status`, and task status transitions | `/v1/claims` (`claims.go:19`) plus task 409 held handling (`tasks.go:226`) | tasks/dev app surface |
| Locks / reservations | `aw lock ...` (`cmd/aw/lock.go:13`) | `/v1/reservations` mutations/list (`reservations.go:45`, `reservations.go:87`, `reservations.go:104`, `reservations.go:135`, `reservations.go:143`) | drop from core or rebuild in dev, with compat/deprecation path |
| Workspaces / status | `aw workspace status` (`cmd/aw/workspace.go:26`, `cmd/aw/workspace.go:129`) | `/v1/workspaces/team`, `/v1/reservations`, `/v1/status` (`workspaces.go:99`, `reservations.go:143`, `coordination.go:82`) | split: core presence/identity/location/role; tasks/dev supplies claims/focus/locks |
| Roles | `aw roles ...` (`cmd/aw/roles.go:19`, `cmd/aw/roles.go:143`) | `/v1/roles/active`, `/v1/roles/history`, `/v1/roles`, activation/reset/deactivate endpoints (`team_roles.go:98`, `team_roles.go:119`, `team_roles.go:131`, `team_roles.go:139`, `team_roles.go:147`, `team_roles.go:155`) | stays core as runtime team facts |
| Instructions | `aw instructions ...` (`cmd/aw/instructions.go:15`, `cmd/aw/instructions.go:80`) | `/v1/instructions/active`, history/get/create/activate/reset (`team_instructions.go:55`, `team_instructions.go:63`, `team_instructions.go:75`, `team_instructions.go:83`, `team_instructions.go:91`, `team_instructions.go:99`) | stays core as runtime team facts |
| Repo/dev metadata | workspace structs include repo, branch/current branch/canonical origin/focus task fields (`workspaces.go:14`, `coordination.go:10`) | `aw workspace status` renders this mixed view | dev app / split from core presence |

## Messaging and event surface (current static CLI)

- Mail/chat/contact/control/events are static Cobra commands in the Messaging & Network group (`cmd/aw/root.go:69`).
- Signed message envelopes use `awid.Client.signEnvelope` (`awid/client.go:79`) and `awid.SignMessage` (`awid/signing.go:115`).
- `aw events` is registered as a root command (`cmd/aw/events.go:162`) and feeds `aw run` via `runNewEventBus` (`cmd/aw/run.go:49`) and `Loop.EventBus` (`run/loop.go:19`, `run/loop.go:178`).
- SOT says mail/chat semantics eventually become first-party apps, but the current CLI has no app/plugin separation; they are core static commands today.

## `aw run` and provider/process execution

- `aw run <provider>` is implemented in `cmd/aw/run.go:61`; it resolves settings, onboarding/client, provider, event bus, dispatcher, and loop options in `runRun` (`cmd/aw/run.go:105`).
- It resolves/initializes workspace client state through `resolveRunClientForDir` (`cmd/aw/run.go:442`).
- Event wakeups are connected through `awrun.NewEventBus` (`cmd/aw/run.go:49`) and started/stopped in the loop (`run/loop.go:178`).
- Provider execution happens in the run loop (`run/loop.go:1490`) and optional PTY wrapper (`run/pty.go:11`). This is provider subprocess execution, not CLI plugin dispatch.
- Background services from run config execute through shell commands (`run/services.go:132`).

## A2A / gateway / release packaging

A2A CLI and library:

- `aw a2a card|send|status|cancel|publish` is a static root command (`cmd/aw/a2a.go:93`, `cmd/aw/a2a.go:98`, `cmd/aw/a2a.go:117`, `cmd/aw/a2a.go:142`, `cmd/aw/a2a.go:164`, `cmd/aw/a2a.go:186`, `cmd/aw/a2a.go:221`).
- A2A client fetches Agent Cards and calls JSON-RPC methods with optional API key/bearer/caller/task credentials (`a2a/client.go:116`, `a2a/client.go:141`).
- `a2agw.Gateway` builds per-route cards and serves A2A HTTP (`a2agw/gateway.go:88`, `a2agw/gateway.go:130`, `a2agw/gateway.go:138`, `a2agw/gateway.go:304`).
- Separate `aweb-a2a-gw` binary loads config or AC-managed env config and serves the gateway (`cmd/aweb-a2a-gw/main.go:37`, `cmd/aweb-a2a-gw/main.go:44`, `cmd/aweb-a2a-gw/main.go:82`, `cmd/aweb-a2a-gw/main.go:146`).

Packaging / release:

- `Makefile` builds local `aw` with `go build -o aw ./cmd/aw` (`Makefile:16`).
- GoReleaser builds two binaries, `aw` and `aweb-a2a-gw`, for linux/darwin/windows amd64/arm64 (`.goreleaser.yaml:10`, `.goreleaser.yaml:27`, `.goreleaser.yaml:15`, `.goreleaser.yaml:19`).
- `install.sh` installs from GitHub release `awebai/aw` and only installs binary `aw` (`install.sh:18`, `install.sh:19`, `install.sh:48`, `install.sh:114`).
- npm package `@awebai/aw` exposes `aw` and `aweb-a2a-gw` bins and optional platform packages (`npm/aw/package.json:7`, `npm/aw/package.json:16`).
- npm postinstall selects the platform package and hard-links/copies the native `aw` binary over the JS launcher when possible (`npm/aw/install.js:6`, `npm/aw/install.js:11`, `npm/aw/install.js:46`).
- `npm/publish.sh` maps GoReleaser artifacts into platform npm packages, copies both `aw` and `aweb-a2a-gw`, updates package versions, publishes platform packages first, and publishes the wrapper last (`npm/publish.sh:18`, `npm/publish.sh:28`, `npm/publish.sh:52`, `npm/publish.sh:62`, `npm/publish.sh:72`).

## Gap checklist against the folio plugin brief

This is a current-state gap map, not an implementation task list.

| Brief item | Current `cli/go` state |
|---|---|
| Unknown `aw <name>` dispatches to `aw-<name>` | Absent. Cobra returns unknown-command errors (`cmd/aw/root.go:137`); runtime smoke confirmed `./aw definitely-not-a-command` errors. |
| Search `~/.aw/plugins/` and `PATH` | Absent. No plugin path code or `aw-<name>` lookup found. |
| `AW_DID`, `AW_TEAM`, `AW_SERVER`, `AW_HOME`, `AW_HELPER` env contract | Absent. Current selection has the needed raw facts (`awconfig/selection.go:26`, `awconfig/selection.go:137`), but there is no plugin env builder/exporter. |
| `AW_HELPER` re-invokes `aw id request --team-auth` | Generic helper command exists (`cmd/aw/id_request.go:110`, `cmd/aw/id_request.go:268`); no plugin-facing helper env wiring exists. |
| `aw plugin list/install/remove` | Absent. `./aw plugin list` errors as unknown command. |
| Optional `aw plugin search` / hub integration | Absent from CLI. |
| Keep app verbs out of core | Current compiled command tree still contains all first-party surfaces as static commands; no app-plugin boundary exists. |
