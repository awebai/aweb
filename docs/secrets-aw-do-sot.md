---
title: "Secrets and mediated execution"
kicker: "Product SOT"
description: "How secrets.aweb.ai and aw do let agents use secrets without seeing them, with signed audit of the mediated action."
weight: 28
---

# Secrets and mediated execution

This is the source of truth for `secrets.aweb.ai` and `aw do`.

The product promise:

> Agents can use approved secrets without seeing them, and humans get a signed
> record of when, why, by whom, and under which approval the secret was used.

This is a launch-critical capability because real company work almost always
touches credentials, tokens, keys, or private integration access. The right
answer is not to let agents read secrets. The right answer is to let agents
request secret-mediated actions.

## 1. Boundary

Aweb audit only covers **Aweb-mediated actions**.

For launch, do not claim that Aweb signs or audits arbitrary filesystem edits,
shell commands, browser clicks, model reasoning, or side effects that happen
outside Aweb-controlled tools. Aweb can show agent-reported activity, but it is
not signed audit unless it crosses an Aweb authority surface.

Signed audit covers actions such as:

- identity, team, certificate, and app-grant changes;
- messages, chat, tasks, app events, and approvals;
- hosted MCP tool calls;
- app-mediated mutations;
- `aw do` mediated local execution;
- future runner-mediated secret execution.

This makes the claim honest:

> Aweb keeps a tamper-evident signed audit trail of agent work and app access
> that goes through Aweb authority.

## 2. Rule

Agents should never receive raw secret values by default.

Instead:

- agents see secret refs/handles, labels, descriptions, scopes, and policy;
- agents request that a secret be used for an approved action;
- `secrets.aweb.ai`, `aw do`, or an approved runner resolves the secret
  internally;
- outputs are redacted before returning to the agent;
- the use is recorded in the audit trail.

There should be no general-purpose `secrets.get_value` tool for agents.

## 3. Local agents: `aw do`

For local terminal agents, the primary interface is `aw do`.

Example:

```bash
aw do --secret GITHUB_TOKEN --secret STRIPE_KEY -- make deploy
```

or:

```bash
aw do GITHUB_TOKEN STRIPE_KEY -- ./script.sh
```

`aw do`:

1. authenticates the agent and team;
2. resolves secret refs through `secrets.aweb.ai` or local configured secret
   providers;
3. checks team grants, profile requests, per-agent overrides, and approval
   policy;
4. prompts for human approval when required;
5. launches the child process with secrets injected by the safest available
   mechanism;
6. redacts stdout/stderr;
7. writes a signed audit event.

Prefer secret injection through environment variables, file descriptors, stdin,
or short-lived files with strict permissions. Avoid placing secret values in
argv because argv can leak through shell history, process listings, logs, and
error messages.

`aw do` is the blessed path for local agents to use secrets. Directly pasting a
secret into a prompt or shell is outside the signed audit boundary.

## 4. Custodial MCP agents

Custodial MCP agents can use secrets, but they cannot receive secret values.

The MCP surface should expose:

```text
secrets.list_refs
secrets.request_use
secrets.run_with_secret
secrets.audit_secret_use
```

It should not expose:

```text
secrets.get_value
```

The model is:

```text
custodial MCP agent requests action using secret refs
  -> policy and grant checks
  -> approval if needed
  -> approved app or runner executes with secret
  -> redacted result returns to the agent
  -> signed audit event records what happened
```

For app integrations, prefer app-native actions over arbitrary command
execution. For example, the agent calls `github.comment_pr`, and the GitHub app
uses its installed credential internally. The agent never sees `GITHUB_TOKEN`.

For arbitrary command execution, MCP alone is not enough. A runner must exist:

- a local `aw runner` on a company machine;
- a customer BYO runner;
- GitHub Actions or another CI runner;
- n8n or enterprise workflow runner;
- future aweb-hosted runner.

Without a runner, a custodial MCP agent can request app-mediated secret use but
cannot run arbitrary secret-backed shell commands.

## 5. Audit fields

Every secret-mediated action should produce an audit record with:

- actor identity: agent id, alias, `did:aw`/`did:key`;
- custody context: self-custodial, hosted MCP connector grant, service account,
  or runner identity;
- human principal if a human authorized the connector or approval;
- team id;
- secret refs, versions, and policy labels, never values;
- approval id or policy that allowed the use;
- action kind: local command, app action, runner job, webhook, workflow;
- command template or app operation;
- argv/env/stdin/file injection mode, with secret positions redacted;
- working directory or runner target where relevant;
- started/finished timestamps;
- exit status or app result status;
- stdout/stderr hashes and redacted excerpts when safe;
- request/body hash and signed envelope where applicable;
- server signature/hash-chain fields from the team audit ledger.

Never log raw secret values. Redaction should use exact-value matching when the
secret is known to the local executor, plus conservative pattern matching for
common credential formats.

## 6. Launch scope

Launch should prove:

- local `aw do` can run one real command with a secret ref;
- the agent does not see the secret value;
- approval can be required for a sensitive secret;
- audit shows the secret ref, action, actor, approval, and result;
- hosted MCP agents can see/request secret refs but cannot read values;
- at least one app-native secret use path is explainable, even if not broad.

Do not block launch on:

- arbitrary hosted command execution;
- full hosted runner fleet;
- every secret provider;
- complex secret rotation;
- multi-party approval workflows beyond one clear approval policy;
- legal-grade external timestamping or third-party notarization.

## 7. Future hardening

Later hardening should add:

- runner attestations;
- short-lived scoped secret leases;
- external timestamping or anchoring of audit checkpoints;
- HSM/KMS-backed secret custody;
- break-glass policy;
- secret rotation workflows;
- policy simulation before execution;
- richer output redaction and leak detection;
- per-command egress/network controls.
