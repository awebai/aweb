# aw's contract with the framework, version 1

**Status: draft for approval.** aweb owns this contract and its number. The
machine-readable copy is
[`cli-integration-contract-v1.json`](vectors/cli-integration-contract-v1.json);
where the two disagree, that is a defect in this repository.

This contract lists what a framework that runs agents (OATS) may rely on when
it calls the `aw` command line: which commands, how to select the identity
they act as, what their JSON answers contain, and what their exit statuses and
error codes mean. Version 1's consumers may rely on nothing that is not listed
here; what released clients already use keeps working (section 7). The
framework talks to `aw` only through these commands: it does not read `aw`'s
files, match its sentences or probe its help text.

Part 1 is the contract. Part 2 keeps the detailed rules of individual
commands, which part 1 refers to by section.

# Part 1. The contract

## 1. The version and how it is accepted

`aw version --json` answers before anything else is read. It selects no
identity, makes no update check and no network request, so the framework can
ask the exact `aw` executable it will run:

```json
{"version": "1.37.0", "commit": "<hash>", "commit_repo": "github.com/awebai/aw", "built": "<RFC 3339>", "integration_contract": 1}
```

All values are strings except `integration_contract`, an integer. A value the
build was not stamped with is an empty string. Text `aw version` is for people
and is not part of the contract.

- `integration_contract` is this document's number. An `aw` reports `1` only
  when it keeps every promise of version 1. An `aw` that predates this
  contract has no such key.
- The number changes only when this contract changes, never with an ordinary
  `aw` release. The release number in `version` says nothing about the
  contract.
- A framework release states the contract version it accepts. At start, before
  any effect, it runs `aw version --json` on the exact `aw` it will use and
  refuses if the key is missing, malformed or not the accepted number. The
  refusal names the required contract and what `aw` reported. Acceptance is
  exact: a higher number is accepted only under a written rule in a later
  version of this document.
- When `aw` is upgraded, the framework restarts, or keeps the checked
  executable for its lifetime.

## What version 1 adds to released `aw`

Everything in this contract exists in released `aw` (1.36.59) except:

- `aw version --json` and its `integration_contract` key. Released `aw
  version` prints text and ignores `--json`.
- The `release` receipt of `aw id grant revoke`, its `--expect-subject`
  check, and `revoked_at`. Released revoke answers `status` and `grant_id`.
- `aw workspace delete --retire-member --expect-certificate`.
- The code `username_unavailable`.

All are additions: no released key, exit status or code changes meaning, with
one exception, stated in [Release receipts](#release-receipts): a revoke whose
reply was lost now exits 0 when `aw` reads back that the grant was revoked.

## 2. Rules for every call

**Invocation.** The framework runs `aw` with an argument array, never through a
shell, and passes `--json` to every listed command except the exit-only ones
(`wake register` and `wake deregister`, section 3.8). Under `--json` no update
check runs. Secrets (invite tokens) are passed on stdin where the command says
so, never as arguments. A flag's value may follow it as the next argument or
be joined to it with `=`: `--team T` and `--team=T` are the same.

**Selecting the identity.** `--identity-home PATH`, placed before the
subcommand, selects the identity `aw` acts as; PATH is the absolute credential
directory (it holds `signing.key` or `grant.yaml`; usually `<workspace>/.aw`).
It wins over `AWEB_IDENTITY_HOME`, which wins over the current directory's
`.aw`. A selected home that cannot be loaded fails; it never falls back to
another identity. Where a command creates an identity, the flag names the
fresh recipient directory, and the command says what authorises it
([identity selection](cli-identity-selection.md)).

**Environment.** Variables that select a service or credential (`AWEB_URL`,
`AWEB_API_KEY`, `AWID_REGISTRY_URL`, `AWEB_IDENTITY_HOME`) change what a
command acts on. The framework sets them only where a command below says so,
and clears them otherwise.

**Output.**
- Success of a JSON command writes exactly one JSON document to stdout; the
  exit-only commands (section 3.8) write nothing the contract covers. Key
  order and whitespace are not part of the contract.
- A listed key is promised with its type. Keys marked optional may be absent;
  absent and empty mean the same unless the command says otherwise. Keys not
  listed may appear and must be ignored. Objects with an `alias` may also
  carry `name` with the same value; it is not part of the contract.
- stderr carries sentences for operators, including notices on success. It is
  never part of the contract.

**Exit status.** `0` is success. `1` is a failure. `2` is a usage error or a
refusal. An exit status alone never says whether something changed: most
refusals come before any effect, but a command that writes can fail or refuse,
with `1` or `2`, after part of its effect is stored (accepting an invitation,
section 3.3). For such commands section 3 says which recorded facts to read
after any nonzero exit. A command that prints a result and then exits nonzero
says so, and the framework reads that result; it is not an error envelope.

**The error envelope.** On failure under `--json`, when nothing was printed to
stdout, `aw` prints one document:

```json
{"error": {"code": "...", "message": "...", "http_status": 404, "detail": "...", "reason": "...", "classification": "..."}}
```

- `code` and `message` are always present. `message` is for operators; the
  framework branches on `code`, never on `message`.
- `http_status`, `detail` and `reason` are optional. They appear for a
  refusal by the aweb service or the AWID registry when that refusal supplied
  them: a service may answer with a plain detail or with no readable body, and
  invite inspection never copies them.
- `classification` is optional and appears only for the classified team
  errors in [Refusal codes](#refusal-codes).
- `invite` (invite inspection) and `release` (release receipts) sit beside
  `error` where the command says so, in the same document.
- Where `code` comes from, and who owns it:
  - `aw`'s generic codes: `error` (no more specific code), `http_error` (a
    service refusal: read `http_status` and `reason` when present),
    `alias_conflict`, `outcome_unknown` (a write that may have applied:
    inspect before retrying);
  - `aw`'s CLI codes, owned by this contract, listed in section 4 and in
    [`cli-integration-codes-v1.json`](vectors/cli-integration-codes-v1.json),
    whose version 1 edition the machine list pins by digest;
  - command-specific codes listed with their command in section 3, such as
    invite inspection's, owned by that command's document;
  - for service registration (`aw id team register`), the service's own open
    code, copied into `code` and `reason` unchanged.

  A code the framework does not know gets a generic remedy, with `message`
  shown to the operator.

**Recovery steps are the framework's.** `next_step` and any command in a
message are text for operators; the framework never executes them. Where a
retry is safe, section 3 states it as a rule: run the same argument array with
the same `aw` executable, the same `--identity-home` and the same routing
inputs (`AWEB_URL`, `AWID_REGISTRY_URL`, any `--server-name`), changing
nothing else.

**Telling failures apart.** The framework must keep these distinct: `aw`
could not be started; it was stopped by the framework's own timeout; its
stdout is empty, truncated or not one JSON document; it printed the error
envelope; it printed a result and exited nonzero (only where listed). Only
the last two are answers.

## 3. The commands

Each command lists who authorises it, what it reads or changes, its input, the
keys of its answer, and its exits. Types: `string`, `bool`, `int`, `array`,
`object`, `null`. "Recorded" means read from the selected home's own files,
with no network; it proves what was written, not current authority.

### 3.1 The version
- `aw version --json`. No identity, no network. Answer as in section 1.

### 3.2 Facts about a home
- `aw --identity-home H id status --team T --json`. Recorded. Answer (all
  always present): `team_id`, `signing_key_present` bool, `identity_present`
  bool, `identity_registered` bool, `registry_status` (`registered`,
  `pending`, `unknown` or `not_applicable`), `did`, `stable_id`, `address`,
  `alias`, `certificate_present` bool, `certificate_id`, `workspace_bound`
  bool, `workspace_id`, `service`, `partial_init` {`present` bool, `stage`:
  `absent`, `identity_prepared` or `response_received`},
  `pending_hosted_accept` bool, `mint_complete` bool. A home whose files are
  corrupt or inconsistent fails with exit 1 and a repair instruction. See
  [Recorded initialization and membership](#recorded-initialization-and-membership).
- `aw --identity-home H id team list --json`. Recorded. Answer: `active_team`
  string, `memberships` array of {`team_id`, `alias`, `active` bool,
  `registry_url`, `aweb_url`, `certificate_id`, `workspace_id` (each always
  present, empty when unknown); optional `identity_scope`, `issued_at`}.
- `aw --identity-home H whoami --json`. Reads the home and, for its inbound
  mode, the service. Answer, every key optional: `alias`, `address`, `domain`,
  `did`, `stable_id`, `custody`, `identity_scope`, `grant_id`, `grant_status`,
  `grant_scopes` array, `grant_expires_at`, `inbound_mode`,
  `inbound_mode_error`. A failed inbound-mode read is reported in
  `inbound_mode_error` and does not fail the command.
- `aw --identity-home H doctor identity --offline --json` and
  `aw --identity-home H doctor registry --online --json`. Answer: `version`
  (`doctor.v1`), `status` (`ok`, `info`, `warn`, `fail`, `unknown` or
  `blocked`), `mode`, `subject` object (optional `team_id`, `workspace_id`,
  `alias`, `identity_scope`), `checks` array of {`id`, `status`, `message`;
  optional `detail` object, `next_step`}. These always exit 0, whatever the
  status. Check ids are `identity.*`, `awid.*`; a check's `detail` keys are
  not part of the contract.
- `aw --identity-home H check --online --json`. The same report as `doctor
  --online`, with a verdict in its exit status: when the report's `status` is
  `fail` it prints the report and then exits 1; otherwise it exits 0. Because
  the report was printed, no error envelope follows it (the failure is coded
  `check_failed` internally, but that code does not reach stdout); stderr asks
  the operator to follow each failed check's `next_step`. Released OATS runs
  `aw check --online` without `--json` and relies on the exit status alone.

The framework reads nothing else about a home. A bounded recorded read that
answers what the framework reads from `aw`'s files today is planned for a
later version (section 5).

### 3.3 Creating an agent's identity and membership

The issuer and the recipient are different homes, acting under different
authorities. These are separate journeys, not one operation. Which authority
an invitation needs depends on the team:

- a **hosted** team's invitation is minted under the issuer's hosted
  membership and redeemed at the team's service;
- a **controller** team's invitation is minted with the team controller key,
  and accepting it needs the same machine's invite record and that controller
  authority: it cannot be accepted on another machine.

The commands:

- **Mint an invitation.** `aw --identity-home ISSUER id team invite --team-id T
  --json`. Answer, for both kinds: `status` (`created`), `invite_id`, `token`
  (secret: never log it or pass it as an argument), `for_human` (null for an
  agent's invitation), optional `expires_at`. The answer carries no service
  URL: the caller uses the service it already selected or verified.
- **Inspect an invitation.** `aw team invite inspect --json`, the token on
  stdin. It follows the shared identity selector (a selected home that is
  missing or invalid fails first) but creates nothing. The answer is unsigned:
  `canonical_team_id` and `server_url` are claims, to be checked against
  coordinates the framework selected or verified independently before acting.
  Its forms ([invite inspection](invite-inspection.md) owns them):
  - hosted, active: exit 0; `kind` `hosted`, `canonical_team_id`,
    `identity_scope` (`local`, `global` or `unknown`), `server_url`, `status`
    `active`, `expires_at` (string or null);
  - controller: exit 0 after local decoding only; `kind` `controller`,
    `canonical_team_id`, `server_url` (may be empty), `identity_scope`
    `unknown`, `status` `unverified`, no `expires_at`;
  - hosted, known inactive with metadata: exit 1, error envelope with `code`
    `expired`, `exhausted` or `revoked`, and `invite` beside it in the hosted
    form, whose `status` equals that code;
  - hosted, inactive without metadata: exit 1, `code` `exhausted` (HTTP 409)
    or `expired_or_revoked` (HTTP 410), and no `invite`;
  - other failures: exit 1 with `malformed_token`, `unsupported_version`,
    `unknown_or_invalid`, `server_unreachable` or `server_mismatch`; exit 2
    for usage errors (absent, multiline or oversized stdin).

  This spelling, under the older `aw team` tree, is kept until the command tree
  is reorganised (E1).
- **Accept an invitation.** `aw --identity-home FRESH id team accept-invite
  --token-stdin --name A --local [--parent ROOT/.aw] --json`, the token on
  stdin; FRESH holds no credentials yet. Answer: `status` (`accepted`),
  `team_id`, `alias`, `cert_path`; optional `connected` bool, `aweb_url`,
  `connect_command`, `id_registration`, `team_key` object, `responsibility`
  object. Code `native_agent_signature_pending` (exit 1): keep the home and
  retry with the same token, name and home. Acceptance can store the
  membership and then fail or refuse, with exit 1 or 2 (for example, when the
  invitation gives no usable service URL, or connecting the workspace fails).
  So after any nonzero exit the framework reads `id status --team T` for the
  exact recipient home and team, and binds what it finds to this join:
  - reconnect, with `workspace connect` to the verified service for this
    join and without reusing the token, only when `team_id` is T, `alias` is
    the requested name, `certificate_present` and `signing_key_present` are
    both true, and `workspace_bound` is false. `workspace_bound` says only
    what is recorded locally;
  - `certificate_present` false: nothing is installed locally, but the
    service's side is unresolved; keep the home and do not reuse the token
    elsewhere;
  - anything else, including a binding to another team or name or an
    ambiguous one: keep the home and stop.

  A retry after `native_agent_signature_pending` keeps the same token, name,
  home and `--parent`.
- **Invite and join in one process.** `aw --identity-home FRESH init
  --join-from SOURCE --join-team T --name N --json`. SOURCE mints with its own
  authority (its hosted membership, or the team controller key on this
  machine); FRESH must be explicitly selected and free of credentials. No
  token is returned. Answer: `status` (`connected`), `team_id`, `alias`,
  `aweb_url`; optional `workspace_id`, `stable_id`, `address`,
  `identity_scope`, `id_registration`, `team_key`, `responsibility`,
  `next_steps` array, `guide`. Codes: `invite_not_created`, `alias_conflict`,
  `native_agent_signature_pending`. After a nonzero exit, read FRESH as for an
  acceptance. After `native_agent_signature_pending`, rerun the exact original
  argument array, keeping SOURCE, the team, FRESH, the name and the scope: the
  CLI keeps the token, the child key and the source selection across the
  resumed attempt, and the framework never sees the token.
- **Connect a workspace.** `aw --identity-home H workspace connect --service
  URL --team T --json`. Answer: as the join's, without `next_steps` and
  `guide`.
- **A global resident.** `aw init --global --name N --json` in the resident's
  directory, with `AWEB_URL` and `AWEB_API_KEY` set (a setup key). Answer: as
  the join's, with `identity_scope` `global`, `stable_id` and `address`.
- **An addressed global identity.** `aw --identity-home FRESH id create --name
  N --domain D --json`. Precondition: namespace D's controller is already set
  up on this machine. A new controller may first need its DNS record set up,
  which asks a person and refuses without a terminal; this contract promises
  no automatic DNS setup. Registering the address uses namespace D's authority
  (the answer's `controller_did`); a parent and a team's admission are
  separate authorities, used later. Answer: `status` (`created`, or
  `chain_installed` on resume), `address`, `did_aw`, `did_key`,
  `registry_status` (`registered`), `identity_path`, `signing_key_path`;
  optional `controller_did`, `registry_url`, `registry_error`,
  `encryption_key_id`.
- **A hosted account.** `aw init --new-account --username U --name N --json`
  with `AWEB_URL` set. Answer: as the join's. Code `username_unavailable`
  (exit 2) when the name is taken.

`--preflight` on invitation minting is not part of version 1.

### 3.4 A team the user controls (bring your own team)
- `aw id team create --name N --namespace D --json`. Authority: the
  namespace's controller key on this machine. Answer: `status` (`created`),
  `team_id`, `team_did_key`, `team_key_path`; optional `registry_url`. Codes:
  `controller_key_missing` (exit 2); classifications `team_name_taken`,
  `team_name_unconfirmed`.
- `aw id team show-server --team N --namespace D --json` and `aw id team
  set-server --team N --namespace D --url URL --json`. Answer: `status`
  (`verified` for show, `published` for set), `team_id`, `server_url`,
  `audience`, `issued_at`, `team_did_key`, `registry_url`. No record:
  classification `team_server_record_missing`.
- `aw id team register --service URL --team T --json`. Authority: the team
  controller key. Answer: `status`, `awid_team_id`, `service_url`, `dry_run`
  bool, `timestamp`, `controller_did`; optional `next_steps`. The service's own
  refusal code is kept in `error.code` and `reason`.
- `aw id team invite --team N --namespace D --json`. As 3.3's mint.

### 3.5 Residents, grants and custody
- `aw id grant mint --team T --scope S --ttl D --label L --out GRANTHOME
  --custody-socket SOCK --json`, run in the resident's directory. Answer:
  `grant_id`, `team_id`, `expires_at` (`never` or RFC 3339), `out`, `apps`
  array, `skipped_apps` array; optional `alias`, `address`,
  `custody_socket_path`.
- `aw id grant show ID --team T --json` and `aw id grant list --team T
  --json`. Answer: a grant (or `grants`, an array of grants): `grant_id`,
  `team_id`, `subject_alias`, `subject_did_aw`, `grant_did_key`, `scopes`
  array, `issued_at`, `expires_at`; optional `label`, `status` (`active`,
  `expired` or `revoked`), `revoked_at`. Code `grant_not_found` names the
  selected team.
- `aw id grant revoke ID --team T --json`: see 3.8.
- `aw custody status --json`, run in the resident's directory. Answer:
  `status` (`running` or `not_running`), `socket_path`, `resident` object,
  `teams` (array or null) of {`team_id`, `ready` bool, `certificate_present`
  bool, `grant_status_endpoint_ready` bool}, `keys` (object or null) with
  `signing_ready` and `encryption_ready` bools, `ops` (array or null) of
  operation names, `errors` optional array. Unreachable custody answers
  `not_running` with `errors` `["custody_unavailable"]` and exits 0.

### 3.6 Who is in the team, and who answers for an agent
- `aw --identity-home H id team members --team-id T --json`. Answer:
  `team_id`, `members` array of {`certificate_id`, `team_id`, `alias`,
  `member_did_key`, `identity_scope`, `issued_at`; optional `member_address`,
  `member_did_aw`, `revoked_at`}; optional `source` and `limitations`. From a
  grant home the answer is the service's roster: `source` is `service-roster`,
  `limitations` says what it omits, and certificate fields are empty.
- `aw --identity-home H workspace status --json`, for operator display only:
  `selected_team`, `team` array (never null; the other workspaces of the team,
  as the service projects them, each with `alias`, `status`, optional
  `last_seen`, `hostname`, `role`, `workspace_path`), `team_has_more` bool,
  `workspace` object. It is a projection of the service, not authority.
- `aw --identity-home H who --json [--registry ORIGIN]`. Answer: `id`,
  `domain`, `outcome` (`nearest_human`, `no_human`, `unavailable` or another
  value, which means unknown), `human_id` (string or null), `identity_valid`
  (bool or null), `kind` (string or null), `reason`; optional `chain` array of
  {`id`, `kind`}, ending with `id`. It exits 0 whatever the outcome.

### 3.7 Messages
- `aw --identity-home H mail send --to A --subject S --body-file F --json`.
  Each send to a recipient starts a new conversation. Answer: `message_id`, `status`, `delivered_at`; optional `conversation_id`.
- `aw --identity-home H mail show --message-id ID --json` and `mail show
  --conversation-id ID --limit N --json`. Answer: `messages` array, `has_more`
  bool, optional `next_cursor`. Each message: `message_id`, `subject`, `body`,
  `priority` (`low`, `normal`, `high` or `urgent`), `created_at`, `read_at`
  (string or null), `from_alias`; optional `conversation_id`, `from_address`,
  `to_address`, `from_did`, `to_did`, `from_stable_id`, `to_stable_id`,
  `content_mode`, `message_version`, `encrypted_envelope`, `signed_payload`,
  `verification_status` (`verified`, `verified_legacy`, `verified_custodial`,
  `unverified`, `failed` or `identity_mismatch`).
- `aw --identity-home H mail threads --limit N [--cursor C] --json`. Answer:
  `conversations` array of {`conversation_type`; optional `conversation_id`,
  `subject`, `title`, `last_message_at`, `unread_count`}, optional
  `next_cursor`.
- `aw --identity-home H mail inbox --count-only --json`. Answer:
  `unread_count` int. It never marks mail read.

### 3.8 Wake delivery
- `aw wake status --json`, and `aw wake status --home H --min-daemon-version V
  --json`. Answer: the daemon's status (`updated_at`, `daemon_running` bool,
  optional `daemon_version`, `daemon_version_state`, `daemon_pid`, `instances`
  array), and `readiness`: an array of verdicts without `--home`, one verdict
  with it. A verdict: `home`, `ready` bool, `code`, `reason`,
  `daemon_version`, `updated_at`, `last_inspect_at`, `advisories` array; codes
  in [Wake readiness](#wake-readiness). Not ready still exits 0. The fields of
  `instances` are diagnostic: the framework decides on `readiness`.
- `aw wake register --registration-json -`, the registration on stdin:
  {`home`, `identity_home`, `delivery`; optional `runtime_delivery`,
  `primary_identity_home`, `backend`, `receive_identities` array of
  {`identity_home`; optional `team_id`, `label`, `delivery_owner`,
  `event_classes`, `controls`}}. And `aw wake register --home H --identity-home
  I --delivery session [--backend tmux]`. Exit 0 means saved; its output is
  text, not part of the contract. Registering the same binding again is
  idempotent.
- `aw wake deregister --home H`. Exit 0 means the home is no longer
  registered, including when it never was.

`wake register` and `wake deregister` are exit-only: they take no `--json`,
and their output is not part of the contract.

### 3.9 Releasing an agent

Two effects, two commands, under different authorities.

- **Revoke a session grant** (the resident stays): `aw id grant revoke ID
  --team T --json [--expect-subject ALIAS]`, from the resident's home.
  Answer: `status` (`revoked`), `grant_id`, `revoked_at`, `release`. See
  [Release receipts](#release-receipts).
- **Retire the member and its workspace**: `aw workspace delete WORKSPACE_ID
  --retire-member --expect-certificate CERT --json`, from the member's own
  home. It never falls back to plain deletion. Answer: as in
  [Retirement and owner log access](#retirement-and-owner-log-access), with
  `release`. Hosted self-removal cannot yet bind the exact workspace, so on a
  hosted team this mode refuses with `certificate_binding_unavailable` before
  sending.

A `release` object: `effect`, `team_id`, `subject` {`alias`, `did`,
`stable_id`}, `target`, `outcome`, `code` (empty when confirmed), `next_step`
(text for the operator, or empty). Each command's receipt is bound to its own
request:

- `aw id grant revoke`: `effect` is always `revoke_grant`; `target` is
  {`grant_id`}, the requested grant (compared as UUIDs), and `team_id` the
  requested team. On success `outcome` is `confirmed` and `revoked_at` is an
  RFC 3339 timestamp; on failure `outcome` is `unknown` (exactly when
  `code` is `outcome_unknown`) or `refused`.
- `aw workspace delete --retire-member`: `effect` is always `retire_member`;
  `target` is {`workspace_id`, `certificate_id`}, the requested workspace and
  expected certificate. A printed result's `outcome` is `confirmed` (exactly
  for `retired_and_revoked` with `alias_released` true), `pending` (exactly for
  `retired_key_holder_required`) or `unknown`; a refusal's is `refused`, or
  `unknown` when cleanup was not confirmed.
- `target` always carries the request's coordinates. `team_id` and the
  `subject` fields match the selected identity. `subject.stable_id` is
  always empty for a local resident or member, which has no global identity;
  any other empty value occurs only on a refusal where that identity's
  evidence could not be read.

What the framework does with each outcome is its own rule, never running
`next_step`:

- `confirmed`: the effect happened; nothing to retry.
- `refused`: nothing was sent, or the service refused definitively; fix the
  cause named by `code`.
- `unknown` after a revoke: keep the state, and retry the same argument array
  under the same `aw` executable, `--identity-home`, routing inputs, `--team`,
  grant ID and `--expect-subject`. A retry that reads back the recorded
  revocation confirms it.
- `unknown` after a retirement: keep the home and retry the same argument
  array in the same way; the retained receipt resumes the exact operation.
- `pending` (`retired_key_holder_required`): keep the home and its receipt and
  hand off to the team controller's key holder; that step is outside the
  framework's authority.

A retirement that prints its result and exits nonzero is a retained result,
read as above; it is not an error envelope. A refusal before sending is an
error envelope with `release` beside it.

## 4. Codes that drive a recovery

The framework branches only on codes. Each place where OATS today reads
`aw`'s sentences to decide what to do next has a code instead:

| Situation | What the framework reads |
| --- | --- |
| The alias is taken | `error.code` `alias_conflict`, or `http_error` with `reason` `self_custody_reinit_unproven` |
| Team creation made no invitation, or join-from could not mint in an existing source team | `error.code` `invite_not_created` |
| The controller key is missing here | `error.code` `controller_key_missing` |
| A hosted username is taken | `error.code` `username_unavailable` (new in version 1) |
| Deleting through an external home that cannot release the alias | `error.code` `team_not_hosted` |
| A revoke may have applied | `release.outcome` `unknown`, `error.code` `outcome_unknown` |
| A read was forbidden, or a message or team is not found | `error.code` `http_error` with `http_status` |
| No team server record, or the team name is held by another key | `error.classification` `team_server_record_missing` or `team_name_taken` |

### The code list's version 1 edition

[`cli-integration-codes-v1.json`](vectors/cli-integration-codes-v1.json)
holds `aw`'s CLI codes and vocabularies. Version 1 pins the edition released
with it, which is today's file plus:

- `cli_error_codes`: `username_unavailable`, `certificate_binding_unavailable`
  and the retirement refusals `not_own_workspace`, `global_identity`,
  `team_not_hosted` and `no_workspace_credential`. These are also
  `alias_released_reason` values in plain `aw workspace delete`'s receipt, and
  they stay there (section 7): the edition adds them as codes and takes nothing
  away from the receipt;
- `release`: the effect `retire_member` and the outcome `pending`.

Not in the list, by ownership: invite inspection's codes (owned by
[invite inspection](invite-inspection.md)), wake readiness codes (in the
list's `wake_readiness` section, owned by [Wake readiness](#wake-readiness)),
service refusal codes (open, owned by each service), and `check_failed`, which
never reaches stdout (section 3.2).

## 5. What is not in the contract

- **`aw`'s files.** `workspace.yaml`, `identity.yaml`, `teams.yaml`,
  `signing.key`, `grant.yaml`, team certificates, recovery files, journals and
  locks are private to `aw`. A bounded recorded read of what the framework
  reads from them today is planned, outside version 1 (E6.3). The first
  readiness path in the framework that needs those recorded facts waits for
  it; version 1 gives the framework no dependency on it. What released OATS
  does today is unaffected: released clients keep working.
- **Text output, stderr and help text.** No sentence is promised, and no
  command's help is a feature test: the contract version replaces feature
  probing.
- **Fallback key names** (`teams` for `memberships`, `id` for `team_id`,
  `cert_id` and similar). Only the keys listed here.
- **Older spellings**: `aw team list` and `aw team invite` (use `aw id team
  list` and `aw id team invite`). `aw team invite inspect` is the exception and
  is listed.
- **Health and status publishing.** The framework in aweb has no health
  commands and does not call `aw status publish` or `aw status-host`. Released
  `aw` keeps them for released OATS.
- **`aw heartbeat`.**
- **Installing the wake and custody services.** Commands to install, remove
  and report the launchd and systemd units are planned but not in version 1;
  they need a test environment with a real user service manager first.
- **The workspace roster as authority.** `workspace status` is for display.

## 6. How the contract is kept

- The machine list pins this document's promises and the code list's edition
  by digest. Changing either without a new version number fails aweb's tests.
- Every listed answer is checked against the machine list, nested fields,
  types and enumerated values included, from a real run of the real `aw`
  against a real aweb service and AWID registry, success and failure shapes
  alike, so a test fails when a listed answer changes shape. Keys the list
  marks diagnostic are not checked. Each kind of check is shown to fail: with a
  wrong nested value, and with a promised key missing.
- Release evidence runs a framework release against the supported `aw`, and
  against an older and a newer `aw` that it must refuse at start.

## 7. Released OATS and version 1

Version 1 is what the framework in aweb may rely on. Released OATS aweb
providers, v1.17 and later, which deployments still run, also call `aw` in
ways version 1 does not list. Those keep working under aweb's rule that a
released client is a permanent constraint until it is measured that nothing
sends it, but they are not promises to the new framework. Each is kept with
the keys and values the providers read:

- plain `aw workspace delete ALIAS_OR_ID --json`, at retire from the
  instance's own directory and at leave with `--identity-home`. Its receipt
  keeps `alias_released`, `identity_deleted` and `alias_released_reason`, whose
  values include `team_not_hosted`, `not_own_workspace`,
  `controller_key_missing`, `retired_revocation_pending`, `global_identity` and
  `no_workspace_credential`. Through an external identity home on a team that
  is not hosted, the refusal keeps exit 2 and its one stderr line,
  `refusing aw workspace delete through external identity home for principal
  P; only own hosted local self-release is supported for an external identity
  home (reason: team_not_hosted)`. P is the first nonempty of the selected
  home's `stable_id`, `address` and `did` in its `identity.yaml`, else the
  selected identity-home path. The providers compare the whole trimmed stderr
  with that line exactly, so both the words and how P is rendered are kept.
  This refusal stays outside the version 1 rules, which read `error.code`;
- `aw workspace status --limit N --json`, for the roster: `selected_team`,
  `team` (each entry's `alias`, `status`, `last_seen`, `hostname`, `role`,
  `workspace_path`, `context_kind`, `agent_identity_scope`), `team_has_more`
  and `workspace`;
- `aw id team members --team NAME --json`, for the roster when the team id
  has no colon, with the answer of section 3.6;
- `aw init --do-not-touch-agents-md`, without `--json`, with `AWEB_URL` and
  `AWEB_API_KEY` set, for the deployment root's first initialisation;
- `aw init --join-from R --join-team T --name N --json
  --do-not-touch-agents-md`, the join of section 3.3 with that flag;
- the command the roster prints for a team controller to run, `aw id team
  remove-member --namespace D --team N --cert-id C [--registry ORIGIN]
  --json`: its spelling is kept, so released rosters do not print a dead
  command. In the roster, `--registry` is the provider's currently configured
  registry origin, never a locator from a cleanup record; the retained-record
  writer prints the same command with its stored origin;
- `aw heartbeat`; `aw team list --json`; `aw team invite --team-id T --json`;
  `aw team join TOKEN --name N --json`, with the token as an argument (up to
  v1.41); `aw --team T init`, and `aw init` without
  `--do-not-touch-agents-md`;
- `aw id team accept-invite TOKEN ...` with the token as an argument (up to
  v1.35); `aw id grant show` and `revoke` without `--team` (up to v1.42);
  `aw id team members ... --registry ORIGIN` (v1.42);
- `aw status-host` and `aw status publish` (v1.29 and later);
- `aw custody serve` and `aw wake run`, written into the service units the
  providers install; `aw wake register --backend` with values other than
  `tmux` (up to v1.44);
- text `aw version`, whose first line they parse as `aw X.Y.Z`: that first
  line keeps its form;
- before v1.43, the whole environment, including `AWEB_URL`, `AWEB_API_KEY`
  and `AWID_REGISTRY_URL`, is passed to `aw`.

One released call already fails: providers v1.25 to v1.42 send `aw mail send
--new-conversation` in their delivery probe, and `aw` 1.36.53 removed that flag
(each send now starts a new conversation).

# Part 2. Details of individual commands

## Recorded initialization and membership

`aw id status --team T --json` reads the selected home's recorded state without
network access or credential renewal. It returns:

- `signing_key_present`, `identity_present`, `identity_registered`, `did`,
  `stable_id`, `address`, and `alias`;
- `certificate_present` and `certificate_id` for the selected team;
- `workspace_bound`, `workspace_id`, and `service`;
- `partial_init: {present, stage}` and `pending_hosted_accept`;
- `registry_status` and `mint_complete`.

`partial_init.stage` is `absent`, `identity_prepared`, or `response_received`.
The response exposes marker presence and stage, never its contents. For global
identities, `registry_status` is recorded `registered`, `pending`, or `unknown`;
local membership uses `not_applicable`. `mint_complete` requires a key, identity,
registration where applicable, team certificate, and workspace binding, with no
unfinished initialization marker. It proves recorded completion, not live
registry freshness. Missing state is incomplete; corrupt or unreadable state
fails with a repair instruction.

`aw id team list --json` always includes `registry_url`, `aweb_url`,
`certificate_id`, and `workspace_id` strings on every membership. Absent values
are empty strings. These are recorded coordinates, without discovery or network
validation. If the workspace binding cannot be read or parsed, the list still
reports the recorded team memberships and omits coordinates from that binding.
`aw id cert show --team T --json` selects T even when another team is
active, including the legacy certificate layout when no teams state exists.
`aw workspace status --json` always includes `team`, including `[]` for a
singleton workspace.

`aw check --online --json` retains the doctor report and exits nonzero if a
check fails. `aw doctor` remains a report command. `aw init --join-from SOURCE
--join-team T --identity-home FRESH --name NAME` performs the invite and join in
one process without returning its token. FRESH must be explicitly selected and
free of existing identity credentials or workspace bindings; an inherited identity home is never an implicit creation destination.

## Validation

These identity-independent commands use the existing CLI or SDK owner and make
no network requests:

```sh
aw validate alias NAME --json
aw validate team-id NAME:DOMAIN --json
aw validate team-server-url URL --json
```

They return `kind`, `input`, `valid`, and `canonical`; the URL command also
returns its signing `audience`. Invalid input exits nonzero. Alias validation
uses the enrollment rule, which lowercases and trims a nonempty name and
rejects `/`. The team-ID command
uses the SDK input normalization rule, not a stricter signed-field profile.
Canonical URL validation establishes format, not permission to connect to a
destination. The signed record vectors are
[`team-server-record-v1.json`](vectors/team-server-record-v1.json).

## Refusal codes

The machine-readable CLI code list is
[`cli-integration-codes-v1.json`](vectors/cli-integration-codes-v1.json).
It also names invite inspection states and wake verdicts. It does not replace
the registry's or service's own open refusal vocabulary.

The existing JSON error envelope carries `error.code`, `error.message`, and,
for service refusals, `http_status`, `detail`, and `reason` where available.
Local ID-certificate refusals such as `request_binding_mismatch`,
`human_mismatch`, `human_required`, `unregistered_parent`, `wrong_kind`, and
verifier refusals use `error.code="error"` with the reason in `error.message`.
A direct refusal has the bare reason as its message. A command may wrap it
with context. HTTP refusals normally use `error.code="http_error"` with
`error.http_status` and `error.reason` when the service supplies a reason.
Consumers branch on the process exit status and structured fields and display
`error.message` to the operator. See [the CLI error envelope](../cli/go/cmd/aw/errors.go#L136-L158).

Service registration preserves the service's own refusal code as `error.code`
and `reason`; unrecognized codes are retained. Service codes remain owned by
the service, rather than becoming a universal CLI vocabulary.

| CLI code | Meaning and action |
| --- | --- |
| `invite_not_created` | Team creation completed without an invite; follow the retained `--admission-team-id` alternative in the message. |
| `alias_conflict` | A membership already holds this alias; recover that membership or choose another alias. |
| `outcome_unknown` | A write may have applied; inspect the recorded operation before retrying. |
| `controller_key_missing` | The required controller key is unavailable here; use the installation or key-holder command in the message. |
| `team_name_unconfirmed` | A command needs a team key that is set aside pending confirmation. Retry `aw id team create --namespace <domain> --name <team>` after the registry answers. |
| `grant_not_found` | The selected team has no such grant; run grant list in that team and identity home. |
| `certificate_persistence_incomplete` | Registry issuance succeeded but its recipient copy could not be saved; retain the key and fetch the exact certificate named in the recovery command. |
| `certificate_rollback_pending` | The exact issued certificate could not be revoked during rollback; keep the recipient home and ask the team controller to revoke it. |
| `retirement_receipt_unavailable` | The CLI could not lock or write the retirement receipt; retain the identity home and repair the receipt destination before retrying. |
| `workspace_cleanup_incomplete` | The service did not confirm cleanup of the exact workspace and local identity; reconcile it before revoking the certificate. |
| `invite_issuance_pending` | Issuance is attempted or unknown; keep the exact recipient and record, check online, and resume the retained certificate. Offline cancellation leaves its child untouched. |
| `native_agent_signature_pending` | Hosted invite acceptance stopped before submitting membership because the child needs an agent signature. The CLI exits with status 1 and retains the child key and pending invite, including any prepared request. Preserve the identity home and finish the exchange, then retry with the same token, name, scope, and home. |
| `invalid_alias`, `invalid_team_id`, `invalid_team_server_url` | Correct the input using the validation command's remedy. |

Team discovery and creation preserve the released refusal code, HTTP status,
and message. Read `error.classification` for the additional CLI classification.
The server's own `error.reason` remains available where supplied.

| Classification | Released refusal | Action |
| --- | --- | --- |
| `team_server_record_missing` | `error`, with `no team server record is published for <team>` | The controller can publish it with `aw id team set-server`. |
| `team_name_taken` | `error`, with `team <domain>/<name> is already pinned to <did:key>` when the registry returns the foreign pin. A private team's proof of foreign control after a create conflict preserves the original `http_error` 409. | Restore the registered controller key or choose another name. |
| `team_name_unconfirmed` | `http_error` 409 with the original `create team at registry: ...` message when the follow-up read cannot confirm ownership. | Retry the same creation command when the registry answers. It restores the set-aside key if the registry pins it and otherwise removes it after confirming another key holds the name. |

A repeat attempt while a team key is set aside reports the result of the
reconciliation read. The creation command supplies the same classifications
when that read confirms foreign control or fails to establish ownership.

The aweb service registration owner is
[`service_registration.py`](../server/src/aweb/routes/service_registration.py).
Its current refusals include `service_url_mismatch` (select the team's service),
`awid_team_not_found` (register the team), `awid_team_controller_mismatch`,
`invalid_controller_signature`, and
`invalid_controller_timestamp` (repair controller selection, key or signing
time), and `validation_error` (correct the request). Consumers may give unknown
codes a generic remedy while displaying the code. Consumers may also encounter
`awid_team_missing_controller`; preserve that code and repair the controller
configuration. Federated mail/chat errors have a separate
[owner-published reference](federation-error-reference.md); they are not the team
registry or service-registration vocabulary.

## Wake readiness

`aw wake status --home HOME --min-daemon-version VERSION --json` adds a
`readiness` object while retaining the existing status fields. Without `--home`,
`readiness` is an array with one verdict per reported instance. The minimum
version is caller policy. Each verdict returns `home`, `ready`, `code`, `reason`,
`daemon_version`, `updated_at`, `last_inspect_at`, and `advisories`.

A ready verdict has code `ready`. Non-ready codes are:

| Code | Condition |
| --- | --- |
| `daemon_unavailable` | Control failed; `control_error` retains the error. This does not prove process absence. |
| `daemon_not_running` | Status reports the daemon stopped, or the control dial finds no listener and the state lock has no owner. A failed dial still appears in `control_error`. |
| `daemon_version_unknown`, `daemon_outdated` | Version cannot establish the caller's requirement. |
| `home_not_registered` | No saved registration or live row for HOME. |
| `registration_mismatch` | Live delivery, primary identity, binding set or pending/conflicting registration differs from the saved registration. |
| `foreign_grant_home` | A grant seat receives through another grant home. |
| `stream_not_connected` | A registered receive stream is not live and admitted. |
| `worker_not_running`, `worker_error` | Delivery worker stopped or reports an error. |
| `paused`, `binding_error`, `inspection_failed` | Paused delivery, binding refusal or failed inspection. |
| `endpoint_unusable`, `session_waiting` | Endpoint cannot accept agent input, or awaits a person/session action. |
| `status_timestamp_unknown`, `observation_invalid` | Missing snapshot timestamp, future observation or inspection after the snapshot. |

`observation_aged` (over 30 seconds), `observation_unproven` (missing inspection
or readiness evidence), and `inspection_pending` are advisories. Age alone
never makes an idle healthy receiver fail. The query does not force inspection
or certify recent observation, delivery, or consumption. Fix registration drift
by idempotently registering the caller's current binding facts again.

## Invite planning and cancellation

`aw team invite --preflight --team-id T --json` and
`aw id team invite --preflight --team-id T --json` use the same authority plan
as minting. They return `team_id`, `kind` (`hosted` or `controller`),
`expiry_known`, and `expires_at`, without creating a token, secret, child invite,
or identity key. An unknown expiry is an empty string; consumers display the
returned expiry rather than infer a lifetime. Mint output includes `invite_id`
and its known `expires_at`.

Controller invites expire after 24 hours by default. `--expires 48h` selects
a different controller lifetime, up to `720h` (30 days); hosted overrides are
refused because their service owns expiry. Controller preflight computes the
same default or requested lifetime without creating anything. Saved invitations
without an explicit expiry use their creation time plus 24 hours. Native
acceptance reads routing and lifetime from the saved issuer record, never from
unsigned token hints. Unknown or expired invitations refuse with
`invite_unknown_or_expired` and the issuer-reissue action. Malformed positional
tokens keep the released `error` code and token-decoder message. Attempted
issuance takes precedence over age and retains its exact recovery record.

`aw id team revoke-invite --invite-id ID --json` locally cancels an unused
controller enrollment. It makes no network request. `status` and `code` are
`cancelled`/`invite_cancelled`, `absent`/`invite_absent`, or
`already_used`/`invite_already_used`. An absent record is idempotent and may
represent a used legacy invite. An established consumed record exits nonzero;
it is never reported as successfully cancelled. A linked child invitation is
voided, or its missing/already-issued disposition is reported. Consumption
retains a secret-free record and its original lifetime metadata as soon as native
registry issuance succeeds, before later recipient writes. A failed recipient
write therefore leaves a used invite and an active certificate, with a recovery
command for that exact certificate.

Before submitting a native certificate, acceptance durably saves its exact signed
bytes, recipient identity home and selected registry inside the existing invite
record. Its shared recovery header reports `attempted`; it is neither unused nor
consumed. `ConsumedAt` is set only after confirmed exact issuance. A failed or
unknown confirmation write keeps the attempt. Offline cancellation refuses an
attempt with `status: attempted`, `code: invite_issuance_pending`, and a retained
linked-child disposition. Its complete `next_step` command includes the original
recipient `--identity-home`, also returned as `identity_home`, when the fence is
readable. Unknown progress is also refused. A definite refusal
of the original registration restores the unused invite and its original token;
an uncertain write or refusal of a later replay does not.

`aw id team check-invite --invite-id ID --json` inspects the existing record and,
when it retains a certificate, reads that certificate's status at its recorded
registry. It returns `state`, `code`, `certificate_id`, `identity_home`,
`registry_url` and `next_step`, without a token or private key. A failed check
exits nonzero. An absent certificate after an uncertain submission does not
clear the attempt or authorize cancellation: the earlier write may still finish.
Unfenced inspection reports `unused`, `expired` or `consumed` from the shared
lifecycle owner, including a validated `expires_at` when available. Unknown
lifecycle evidence is a refusal, not unused state. A revoked certificate returns
an empty `next_step` and a `message` requesting a new invitation from its issuer;
nonempty recovery steps are complete commands rather than guessed issuer homes.

`aw --identity-home HOME id team resume-invite --invite-id ID --json` requires
the original recipient key and home and resumes that same certificate, member
and registry. It never creates another certificate or recipient. An
already-registered reply is successful only when the fetched certificate is
identical and its exact team status is active. Confirmed effects complete local
installation without resubmitting. A stored registry URL records routing, not
private-network admission; the same explicit administrative pin is still needed.

The controller's existing bearer is suspended outside the public issuance
payload while attempted, leaving the released `secret` field empty. Released
acceptors therefore refuse to mint another certificate while ignoring the new
metadata. Confirmation removes both bearer copies. The payload shares the
`RecoveryProgress` version/state header with identity recovery, but retains public
membership proof rather than recipient key custody. No extra journal is created.

Cancellation does not revoke an issued certificate. `next_step` names
`aw id team remove-member` for that separate controller-authorized operation.

## Release receipts

A release command performs one explicit effect and reports it in a `release`
object: `effect`, `team_id`, `subject` (`alias`, `did`, `stable_id` of the
selected principal, empty where local evidence cannot be read), `target`,
`outcome` (`confirmed`, `pending`, `unknown` or `refused`), `code` and `next_step`. On
success the object sits beside the command's released fields; on failure it
sits beside `error` in the same JSON document.

`aw id grant revoke GRANT --team T --json [--expect-subject ALIAS]` has effect
`revoke_grant`: that one session grant ends and the resident stays. The
service binds the grant to the selected team and resident. `--expect-subject`
is a sanity check refused before sending (`subject_mismatch`, with the refused
`release` beside `error`) when the selected identity's alias differs or cannot
be read. Grant IDs are compared as UUIDs, whatever their spelling. Confirmed
means the route returned that grant revoked, with a valid `revoked_at`; a
repeat on a revoked grant returns the original `revoked_at`. A definitive refusal, such as `grant_not_found`, or a
connection that was never made is `refused`. After the request was sent, a
server failure or a lost or unusable reply is settled only by reading back that
exact grant from the same service, team and resident: a recorded revocation
confirms, exit 0; anything else is `unknown` with code `outcome_unknown`, exit
nonzero, and `next_step` repeats the command with the same identity home,
service and `--expect-subject`.

`aw workspace delete WORKSPACE_ID --retire-member --expect-certificate CERT
--json` has effect `retire_member`: the selected local member's own workspace
is deleted and its exact certificate revoked, as the native retained receipt
below records. Before sending, it refuses (exit 2) unless WORKSPACE_ID is the
selected member's own workspace (`not_own_workspace`), the member is local
(`global_identity`), its certificate is CERT (`subject_mismatch`), the team's
controller key is here (`controller_key_missing`), and the team is not hosted
(`certificate_binding_unavailable`: the hosted self-removal route chooses the
workspace from the member's credential, so the exact workspace cannot yet be
bound). It never falls back to ordinary deletion. `target` carries
`workspace_id` and `certificate_id`. `retired_and_revoked` is `confirmed`;
`retired_key_holder_required` is `pending`, with the key holder's command in
`next_step`; `retired_revocation_pending` and an unconfirmed cleanup are
`unknown`, retried with the same command. Without `--retire-member`,
`aw workspace delete` keeps its released behaviour and carries no `release`.

## Retirement and owner log access

For retirement results, retained credentials and controller-only retries, see
[orchestrator cleanup](orchestrator-integration.md#stale-local-identity-workspace-cleanup). Complete retirement
requires `alias_released: true`, not merely `identity_deleted: true`.

Sealed logs use the existing owner reader described in
[configuration](configuration.md#local-message-logs):
`aw log read FILE... --json` accepts explicit file paths and emits decrypted
entries as JSON lines. It needs the owner's encrypted log keys in the local
keychain and an interactive passphrase for every distinct key encountered.
There is no automatic agent access or stdin/passphrase flag. Retain unreadable
boundaries: the reader can emit a readable prefix and then fail. A recorder
must not advance past unreadable input or infer whole-source success from that
prefix. Decrypted entries remain untrusted input.
