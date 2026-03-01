# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Autonomous multi-agent development pipeline where AI agents handle the full software development lifecycle — planning, implementation, testing, and PR submission — with minimal human involvement. The human role is limited to initial plan approval and escalation resolution.

**Owner:** Woodson / Nessei Inc.
**Current Phase:** Phase 1 — Local Validation

## Architecture

Three-phase system built on open, self-hostable infrastructure:

### Coordination Layer
- **BeadHub** (self-hosted Python API + frontend) — central coordination server at `http://localhost:8000`
- **PostgreSQL** — persistent state (claims, issues, policies)
- **Redis** — ephemeral state (presence, locks, messages)
- All three run via Docker Compose locally (Phase 1), then k3s on Raspberry Pi 5 (Phase 2+)

### Agent Team (Fixed Aliases)

The following three agents are the **permanent team** across ALL BeadHub projects. These are the ONLY aliases that may be used.

| Alias | Role | Description |
|-------|------|-------------|
| **ordis** | coordinator | Global orchestrator (Remote Control pod). Plans, assigns, reviews, unblocks. Reachable via Discord and Claude Code Remote Control. |
| **neo** | developer | Worker agent. Implements features, fixes bugs, submits PRs. |
| **hawk** | reviewer | QA/review agent. Reviews PRs, checks security, test coverage, code quality. |

**Rules:**
- Agents must ONLY use these three aliases — no ad-hoc names (no worker-xyz, no task-dev, etc.)
- Same compute can serve all projects — agents switch context by pulling the repo and running `bdh :init --alias <name> --role <role>`
- ordis is the coordinator for every project; neo and hawk register per-project as needed
- If a project needs more agents, get human approval first

### Coordination Flow
1. Human gives feature spec to ordis (coordinator)
2. ordis breaks spec into Beads tickets via `bdh` CLI
3. Human approves plan
4. neo claims tickets, implements in a Ralph Loop (iterate: code → build → test → validate)
5. Blockers resolved agent-to-agent via BeadHub chat; only true escalations surface to human
6. neo submits PR on completion
7. hawk reviews the PR, approves or requests changes

### Key Tools
- **`bdh`** — Beads CLI (git-native issue tracking)
- **`bdh`** — BeadHub CLI (coordination, chat, locks, presence)
- **Ralph Loop** — persistent agent iteration pattern (max 30 iterations)

## Phase 1 Setup (Local Validation)

```bash
# Start BeadHub stack
make start                          # Docker Compose: beadhub + postgres + redis

# Initialize workspaces (fixed team)
bdh :init --alias ordis --role coordinator          # Register ordis (coordinator)
bdh :add-worktree developer --alias neo             # Register neo (developer)
bdh :add-worktree reviewer --alias hawk             # Register hawk (reviewer)
```

ordis, neo, and hawk run as separate Claude Code instances in separate git worktrees, coordinating through BeadHub.

## Phase 2+ Infrastructure

- **Daytona** — isolated compute sandboxes for workers (sub-90ms creation, pay-per-second)
- **Cloudflare Tunnel + Access** — zero-trust ingress to BeadHub on Pi 5
- **GitHub** — PR submission and code review
- **Discord** (Phase 3) — escalation notifications and PR alerts

## CRITICAL: Ticket Sync Rules — No Local Dolt

Agents must NEVER use a local dolt database for ticket operations. All ticket data flows through git and the BeadHub server.

**Allowed:**
- `bdh list`, `bdh show`, `bdh ready` — reads from BeadHub server API
- `bd create`, `bd update`, `bd close` — writes to local git-backed JSONL
- `bd sync` — pushes JSONL to git remote, pulls updates

**Forbidden:**
- Starting or depending on a local dolt database
- Attempting to fix dolt `table not found` errors — use `bdh` (server) instead
- Syncing tickets from the upstream fork (`beadhub/beadhub`)

**Ticket creation flow:**
1. `bd create ...` (creates in local JSONL)
2. `bd sync` (pushes to git remote via `beads-sync` branch)
3. BeadHub server picks up changes from git

**If `bd` commands fail**, fall back to `bdh` (server API). Never try to repair a local database.

## CRITICAL: Agent Identity Rules

Agents must ONLY use aliases that are **pre-registered in the BeadHub server**. Never create ad-hoc or one-off aliases.

**Current registered team:**

| Alias | Role |
|-------|------|
| **ordis** | coordinator |
| **neo** | developer |
| **hawk** | reviewer |

**Rules for ALL agents (including any future additions):**
- Check registered aliases with `bdh :aweb who` before starting work
- ONLY use an alias that appears in the registered list — never invent new ones
- To add a new agent, get human approval first, then register via `bdh :add-worktree <role> --alias <name>`
- All agents are registered per-project in BeadHub via `bdh :init --alias <name> --role <role>`
- Same compute machine can work across projects — switch by pulling the repo and running `bdh :init`
- The coordinator receives all agent messages via the bdh notify hook
- Chat and mail are scoped per-project, so `bdh :init` into the correct repo before communicating

**Switching projects (applies to ALL agents):**
```bash
cd ~/workspace/<project-repo>
bdh :init --alias <your-alias> --role <your-role>
bdh :status    # verify identity
bdh ready      # start working
```

**Why this matters:** Ad-hoc aliases lose chat history, can't be coordinated, and create identity sprawl on the server. Pre-registered aliases ensure persistent memory and proper coordination.

## Key Design Decisions

- No vendor lock-in beyond Claude API — all infrastructure is self-hostable
- Agents coordinate without human relay; human is only in the loop for plan approval and escalations
- Ralph Loop has a hard cap (`--max-iterations 30`) to prevent cost runaway
- Workers use file locks via BeadHub to avoid conflicts
- Claude Code PostToolUse hook handles incoming chat while workers are in Ralph Loop

## Infrastructure Architecture

### Orchestrator Deployment (K8s)

ordis (the coordinator) runs as a **Deployment** in the `beadhub` namespace on a Raspberry Pi 5 (k3s). It uses **Claude Code Remote Control** — a persistent interactive session that the human connects to from the Claude mobile app.

```
Human ↔ Claude Code Remote Control (phone app) ↔ ordis pod
Human ↔ Discord → discord-bridge → ordis pod
Agent-to-agent chatter → bdh chat → Discord (visibility only)
```

**The ordis pod runs `claude remote-control`, NOT a dispatcher or `claude -p`.** The entrypoint:
1. Sets up git auth and copies CLAUDE.md from the mounted ConfigMap
2. Runs `bdh :init --alias ordis --role coordinator` for each project
3. Starts `claude remote-control --dangerously-skip-permissions` — the human connects from the Claude mobile app
4. The session persists as long as the pod is running

**Important:** The agent image must use the native Claude Code install (`claude install`), not the npm package. The npm version fails with `node: bad option: --sdk-url` when running `claude remote-control`.

Worker communication happens via `bdh :aweb chat` — ordis checks for pending messages proactively via the notify hook. Discord shows inter-agent chatter for visibility. ordis is reachable from both Discord and Claude Code Remote Control.

### CRITICAL: Do Not Modify the Orchestrator Deployment

**The orchestrator Deployment manifest is managed by ArgoCD from `Woody88/homelab-k8s`.** If an agent modifies it via `kubectl apply/patch/edit`, ArgoCD will revert the change and break the session.

**Rules:**
- The orchestrator Deployment is in `Woody88/homelab-k8s` at `manifests/platform/beadhub/orchestrator.yaml`
- Changes to the orchestrator entrypoint or CLAUDE.md must go through a commit to homelab-k8s (ArgoCD syncs from Git)
- Agents must NEVER `kubectl patch/apply/edit` the `orchestrator` Deployment directly
- Agents CAN create/modify Jobs (workers), ConfigMaps, and other resources freely
- If the orchestrator pod is not responding, check: `kubectl logs deployment/orchestrator -n beadhub`

### Recovery Procedure

If the orchestrator Remote Control session is broken:

```bash
# 1. Check if remote-control is running
kubectl logs deployment/orchestrator -n beadhub --tail=5

# 2. If not, force restore from Git
cd ~/Code/DevOps/homelab-k8s
git pull
kubectl replace -f manifests/platform/beadhub/orchestrator.yaml --force

# 3. If ArgoCD overrides with stale state, force sync
kubectl -n argocd patch app beadhub --type merge \
  -p '{"operation":{"sync":{"revision":"HEAD","prune":true,"syncStrategy":{"apply":{"force":true}}}}}'

# 4. Verify — look for Remote Control session URL
kubectl logs deployment/orchestrator -n beadhub --tail=10
```

### Related Repos

| Repo | Contains |
|------|----------|
| `Woody88/hq-beadhub` (this repo) | discord-bridge source, agent-image Dockerfile, beads, project docs |
| `Woody88/homelab-k8s` | K8s manifests including orchestrator Deployment, RBAC, kustomization |
| `beadhub/beadhub` | Upstream BeadHub (this repo was originally forked from here) |

### CRITICAL: Git Remote Rules

This repo is a fork of `beadhub/beadhub`, but **the `upstream` remote has been intentionally removed**. The only remote is `origin` → `Woody88/hq-beadhub`.

**Rules for ALL agents:**
- **NEVER add an `upstream` remote** pointing to `beadhub/beadhub`
- **NEVER push to `beadhub/beadhub`** — not fixes, not PRs, not anything
- **ALL pushes go to `origin` (`Woody88/hq-beadhub`) only**
- If you need upstream changes, the human will handle cherry-picks manually
- If `git remote -v` shows any remote other than `origin`, stop and ask the human

### Discord Bridge

Source: `discord-bridge/src/` in this repo. Key files:
- `discord-listener.ts` — Routes Discord messages: new threads → ordis (Redis), existing BeadHub threads → BeadHub API
- `orchestrator-relay.ts` — BLPOPs `orchestrator:outbox`, posts responses to Discord threads
- `session-map.ts` — Maps Discord thread IDs ↔ Claude session UUIDs with source tracking ("beadhub" vs "ordis")

### Agent Image

Dockerfile: `agent-image/Dockerfile` in this repo. Published to `ghcr.io/woody88/claude-agent:latest`. Contains:
- Node.js 22, npm, Claude Code CLI, kubectl, gh, bd, bdh, dolt, wrangler

<!-- BEADHUB:START -->
## BeadHub Coordination Rules

This project uses `bdh` for multi-agent coordination and issue tracking, `bdh` is a wrapper on top of `bd` (beads). Commands starting with : like `bdh :status` are managed by `bdh`. Other commands are sent to `bd`.

You are expected to work and coordinate with a team of agents. ALWAYS prioritize the team vs your particular task.

You will see notifications telling you that other agents have written mails or chat messages, or are waiting for you. NEVER ignore notifications. It is rude towards your fellow agents. Do not be rude.

Your goal is for the team to succeed in the shared project.

The active project policy as well as the expected behaviour associated to your role is shown via `bdh :policy`.

## Start Here (Every Session)

```bash
bdh :policy    # READ CAREFULLY and follow diligently
bdh :status    # who am I? (alias/workspace/role) + team status
bdh ready      # find unblocked work
```

Use `bdh :help` for bdh-specific help.

## Rules

- Always use `bdh` (not `bd`) so work is coordinated
- Default to mail (`bdh :aweb mail list|open|send`) for coordination; use chat (`bdh :aweb chat pending|open|send-and-wait|send-and-leave|history|extend-wait`) when you need a conversation with another agent.
- Respond immediately to WAITING notifications — someone is blocked.
- Notifications are for YOU, the agent, not for the human.
- Don't overwrite the work of other agents without coordinating first.
- ALWAYS check what other agents are working on with bdh :status which will tell you which beads they have claimed and what files they are working on (reservations).
- `bdh` derives your identity from the `.beadhub` file in the current worktree. If you run it from another directory you will be impersonating another agent, do not do that.
- Prioritize good communication — your goal is for the team to succeed

## Using mail

Mail is fire-and-forget — use it for status updates, handoffs, and non-blocking questions.

```bash
bdh :aweb mail send <alias> "message"                         # Send a message
bdh :aweb mail send <alias> "message" --subject "API design"  # With subject
bdh :aweb mail list                                           # Check your inbox
bdh :aweb mail open <alias>                                   # Read & acknowledge
```

## Using chat

Chat sessions are persistent per participant pair. Use `--start-conversation` when initiating a new exchange (longer wait timeout).

**Starting a conversation:**
```bash
bdh :aweb chat send-and-wait <alias> "question" --start-conversation
```

**Replying (when someone is waiting for you):**
```bash
bdh :aweb chat send-and-wait <alias> "response"
```

**Final reply (you don't need their answer):**
```bash
bdh :aweb chat send-and-leave <alias> "thanks, got it"
```

**Other commands:**
```bash
bdh :aweb chat pending          # List conversations with unread messages
bdh :aweb chat open <alias>     # Read unread messages
bdh :aweb chat history <alias>  # Full conversation history
bdh :aweb chat extend-wait <alias> "need more time"  # Ask for patience
```
<!-- BEADHUB:END -->