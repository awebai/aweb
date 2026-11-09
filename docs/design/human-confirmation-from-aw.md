# Human confirmation started from `aw`

Status: **decided** (aweb-acwd.4, gap G-B for the LF demo epic aweb-acwd).
Juan ruled every item below. This is a contract; implementation tasks are
filed from [Work this creates](#work-this-creates).

With it, a human finishes every protected naapp operation that `aw` starts:

- confirming a frozen request;
- entering a value or the 1Password service-account token;
- receiving a runner's registration code;
- signing in as a logs reader.

The default gesture is a passkey ceremony in a browser that `aw` opens on the
app's human origin. Touch ID, Windows Hello, a phone or a password manager's
passkey all qualify, and a browser used only for that gesture is enough. A
security key used from the terminal is an
[optional profile](#optional-a-security-key-from-the-terminal). Nothing
requires it, and the default never accepts its credentials.

The existing B2 and B3 machinery carries all of this. The holder is bound by
[human-role acts](human-role-holders.md) (aweb-acgh.16.38). There is no
approval service, credential architecture or token profile beyond what is
here. A plain human-key signature is not an approval and is not offered as
one.

Requirement: Bookshelf `kb/concepts/customer-agent-servers.md` at `5c83ed85`,
lines 127-145, 157 and 173.

## Rulings

| Item | State | Main tradeoff |
| --- | --- | --- |
| Browser passkey by default, opened by `aw` | Ruled | Each app origin is its own relying party, so a human creates one passkey per app origin. Synced passkeys make that one gesture each. |
| A security key from the terminal | Ruled optional | It is accepted only for a holding bound under it, never by default. |
| A plain human-key signature as an approval | Ruled out | Not offered. |
| N3. How an approver finds a pending request | Ruled: the console lists them | With no approval email for a human role, the console's own list of the approver's pending approvals is how it finds them. |
| N4. Terminal input and output | Ruled: offered beside the console | Typing a value, or receiving the runner code, in the terminal keeps them out of the browser. It is a local barrier, not gesture evidence. |

## Trust

- The browser, the authenticator and `aw` are trusted for what they show. A
  compromised one can show one action and confirm another.
- Every login and approval is a user-verified WebAuthn assertion that B3
  verifies at the app's human origin and retains as
  `aweb.passkey-evidence/1`. There is no attestation
  (`naapp-lib/src/aweb_naapp/runtime/passkeys/webauthn.py:37-50`), so the
  evidence proves the credential and the origin the client reported, as for
  any WebAuthn relying party.
- A `session` handoff returns its result only to the loopback on the machine
  whose browser completed the ceremony ([The handoff](#the-handoff)), so a
  phished sign-in yields nothing to a remote attacker.
- An agent running as the same OS user can drive the browser and the
  terminal. It cannot produce the authenticator's user verification, which
  is why every effect needs a fresh assertion.
- An unsupported configuration refuses. Nothing falls back to an ordinary
  signature, a team-auth request or a member-session assurance.

## The handoff

One mechanism connects `aw` to a browser ceremony. It is L6's planned device
flow (aweb-acgh.16.24), specified here once for every naapp and served on the
installation's pinned `owner_acts.origin`. By default the result comes back
to `aw` through a loopback redirect on the same machine, as RFC 8252 describes
for native apps:

1. `aw` makes an ephemeral key, held only in memory, listens on
   `127.0.0.1:<random port>`, and makes a random verifier. It calls
   `POST <origin>/handoffs` with its purpose, the public key, that loopback
   redirect URI, the verifier's SHA-256 and, for a session, the holder's
   scope, signed with team-auth v2 as the holder
   ([Membership evidence](#membership-evidence)). The app accepts only a redirect URI of the form
   `http://127.0.0.1:<port>/<path>` or `http://[::1]:<port>/<path>`, a
   literal loopback address; `localhost` and every other URI are refused
   (RFC 8252 §8.3). It answers a handoff id and a ten-minute expiry. The
   handoff grants nothing.
2. `aw` opens `<origin>/handoff/{id}` in the local browser. The page names
   the purpose, the app and the installation.
3. The browser runs the purpose's ceremony (below) with B3's existing
   routes, challenges and checks.
4. The page then redirects the browser to the stored loopback URI, never to
   one taken from a request, with a single-use code. That is a redirect the browser follows to `aw`, not one
   that `aw` follows.
5. `aw` collects the result from `POST <origin>/handoffs/{id}/result` with
   the code and the verifier, signed by the ephemeral key. The app releases
   the result only for all three, once, before the handoff expires.

**Why the loopback.** A typed user code ties nothing to the `aw` that started
the handoff, which is the device-code phishing pattern:

- an attacker starts a `session` handoff for the victim's scope with its own
  key;
- it sends the victim the real page and code;
- the victim signs in;
- the attacker collects a console session for the victim's scope.

Each decision still needs its own assertion, but for `logs.reader` the
session is the read boundary. With the loopback, a phished victim's browser
delivers the code to the victim's own machine, where the attacker's `aw` is
not listening, and the attacker's result request is refused without it.

**Fallback: no local browser** (`aw --no-browser`, for example over SSH). The
app answers a short user code instead of a loopback. `aw` shows it, and the
human types it into `<origin>/handoff` on any device; the URL never carries
it. The page:

- says to continue only if this person started it in their own terminal,
  moments before;
- shows the requesting `aw`'s hostname, as reported.

Each completed fallback `session` handoff emits a `post-governance-hook`
event, so the owner sees it. The `credential` purpose may use either path,
because it grants nothing: a phished registration gives the attacker only a
public key, and binding still needs the owner's act and the
[fingerprint comparison](human-role-holders.md#what-the-owners-client-shows-and-signs).

`aw` sends these requests only to the pinned origin and follows no
redirects. The app rate-limits handoffs as it rate-limits login.

**Purposes:**

- **`credential`.** The page runs WebAuthn registration with B3's options:
  rp.id the origin's hostname, user verification required, no attestation,
  and a single-use challenge bound to the handoff. B3 verifies the
  registration as it verifies an enrolment (`verify_registration`), including
  the origin and the user-verification flag. The result is the public credential, for a
  [human-role act](human-role-holders.md#three-acts) to bind. Until an act
  binds it, it authorizes nothing.
- **`session`.** The page runs the existing console login for the holder's
  scope, then asks the human to allow `aw` with that user code. The result is
  a console session for that scope, bound to the ephemeral key: at most 15
  minutes, with its CSRF token. Each request carries the session id and a
  signature by that key over team-auth v2's request-bound bytes
  ([Authentication](../aweb-sot.md#authentication): `aud`, `method`, `path`,
  `body_sha256`, `timestamp`), with the session id in place of `team_id` and
  a random `nonce`. The app refuses a timestamp outside the 300-second window
  and a nonce already seen in that session. Every session refusal (a session
  that is unknown, closed or expired, a signature that does not verify, a
  timestamp outside the window, a nonce already seen) is
  `401 console_session_required`, the console's existing code, and it does
  not say which check failed. Each request re-checks that the principal is a
  current human member ([Use](human-role-holders.md#use)), from the session's
  retained certificate ([Membership evidence](#membership-evidence)), and
  refuses with `403 principal_not_member`, `403 principal_not_human` or
  `503 principal_status_unavailable`.

### Membership evidence

An app learns that a holder is a current human member of its team from the
holder's own signed team certificate, not from a registry read of the team's
members. `aweb_naapp` owns this evidence once, for every app: no app stores
or verifies it on its own. The certificate is evidence, never authority by
itself. Passkey, owner-act and session authority stay as they are, and each
must still pass on its own.

- **Presented.** The holder's existing team certificate is presented in
  two places, in the encoding team-auth's `X-AWID-Team-Certificate` uses:
  - At designation and replacement, it travels in the
    [delivery body](../owner-act-delivery.md#delivery) next to `credential`.
    The holder's `aw` exports it with the public credential, and the owner's
    client passes it through. A team certificate is a public statement signed
    by the team key, so it needs no proof of who carried it. The owner's
    signature still covers the credential and the binding.
  - At a `session` handoff, `aw` signs `POST <origin>/handoffs` with
    [team-auth v2](../team-auth-envelope-v2.md) as the holder, so the request
    carries the certificate, which team-auth verifies as for any request. An
    unsigned handoff request is refused.

  A `credential` handoff is also signed this way, which keeps its
  rate-limit identity, but the app retains nothing from it: no state is kept
  for a credential that no act has bound yet.
- **Retained.** The app keeps the exact certificate bytes of a verified
  designation or replacement with the holding. It keeps those of a `session`
  handoff with the session, for at most the session's lifetime. Retaining
  them extends no session, approval or holding, and resets no freshness.
- **Bound.** The certificate's `team_id` is the installation's team and its
  `member_did_aw` is the holding's principal. A `session` handoff whose login
  is for a holding of another principal refuses, and nothing changes.
  Retained evidence is never borrowed from one holding or session for
  another. The same public certificate may still be presented on its own for
  each of the human's holdings and sessions in that team, and passes each
  binding there.
- **Checked at each use:** at designation and replacement (delivery stage
  3), and at each login and each approval. Each check covers:
  - the certificate's signature under the team's current key;
  - its `member_did_key` against the principal's current key;
  - its publication and revocation, through AWID's anonymous certificate
    status;
  - the principal's own registered ID kind `human`.

  Each read keeps its existing freshness bound of at most 60 seconds and
  fails closed. A designate or replace uses the certificate in its body. A
  `session` handoff uses the certificate it presents. A browser login that
  `aw` did not start presents none, so it uses the holding's.
- **Outcomes.** A revoked certificate, a wrong team, principal or key, a
  signature the current team key does not verify, or no usable certificate
  retained gives `403 principal_not_member`. A kind other than `human` gives
  `403 principal_not_human`. Neither starts a session or changes a holding.
  Status that cannot be read gives `503 principal_status_unavailable`, never
  "not human". "No usable certificate" means that none was presented and
  retained, as for a holding or session made before this contract. The
  holder then runs a fresh handoff, which presents a current one. No caller
  flag, certificate id or matching metadata stands in for verifying the
  bytes.
- **Refresh.** After a team-key rotation, the old signature no longer
  verifies. After a member-key rotation, `member_did_key` is no longer
  current. Either way, the retained certificate fails at its next use. The
  holder refreshes it with a `session` handoff that presents the reissued
  certificate. That certificate, once verified, replaces the holding's
  retained one only when its team and principal equal the holding's, and only
  when the handoff's login succeeds; a failed assertion changes nothing. A
  stale holding certificate therefore never blocks this refresh. Nothing
  rewrites a certificate, rebinds the passkey, or treats the same
  certificate id as current.
- **Compatibility.** An AWID row with no stored certificate blob is not
  refused for that reason, because the presented bytes are what the
  unchanged verifier and status contract check. The app never fetches member
  certificates from AWID and never builds one from metadata. A holder with
  none gets one through the existing membership path. Ordinary team-auth
  verification is unchanged.
- **No other authority.** No app holds a registry-wide token, and no use
  needs a human unlock beyond what each operation already requires.

## Confirming a frozen request

Approvals stay in the browser, on the console's existing pages and routes:
use and run approvals, change sets with their confirm, and reconciliation
approvals. B3 verifies each assertion and retains its evidence, B2 records
the first decision, and the console renders the terms by its rules (secrets
§6.3, §10.4).

`aw` opens the console's sign-in on the human origin for the holder's scope,
which the app keys by (installation, role, principal), and the human signs in
there with the bound passkey.
Completion is what each kind already defines:

- **Use and run:** the requester reads `secrets.status` and re-submits the
  same `request_id`. Single-use admission stays at the target (secrets
  §10.3, §10.5, §11).
- **Change set:** `POST .../confirm` applies the change
  (`naapp/secrets/src/aweb_secrets/console_changes.py:390`, `:513`). It
  requires the deciding owner's (scope, subject), not a particular session,
  and its result is the only carrier of a runner's registration code, which
  is never stored for later retrieval (`console_results.py:3-5`). The two
  journeys split here:
  - **Approved journey (from `aw`).** `aw` first holds a `session` handoff
    for the owner's scope. The human approves in the browser, with the
    APPROVE assertion. `aw` reads the change set in its session until it is
    approved, then calls `confirm` itself, so only `aw` receives the result.
    A change set drafted in a key-bound console session (the human's
    `aw`, through a `session` handoff) records that its confirm belongs to
    a key-bound session. A team-auth draft, such as an agent's
    `secrets.propose-change`, and a browser draft set no mark. A marked
    change set is confirmable by any key-bound session of the deciding
    owner's (scope, subject): the decider check confirm already makes, plus
    a key-bound session. The browser's confirm refuses it with
    `confirm_in_aw`. When `aw`'s session has expired, it opens a fresh
    `session` handoff and confirms there. On a lost reply, `aw` reads the change set's state and
    never confirms twice; a code lost with the reply is not recovered.
  - **Console journey.** An unmarked change set is confirmed on the
    console, and the browser shows its result, as on main.
- **Reconciliation:** as secrets §11.4 defines.

**N3: finding the request.** A human role has no approval email: its
contact is notice-only ([H3](human-role-holders.md#rulings)). The console
therefore lists the pending approvals for which the signed-in approver is a
candidate: approval id, kind and the page to open, with no terms. N3
applies only to an app with B2 approvals. Logs has none
(`naapp/logs/src/aweb_logs` uses no B2 approval), so its console exposes no
pending list or link provider; its holder-scope `session` handoff stays.

The existing pages open an approval only through the candidate's personal
link token (`naapp-lib/src/aweb_naapp/runtime/approvals/service.py:467-504`),
and B2 stores only its verifier, so the list cannot recover the emailed token.
Selecting an entry therefore asks B2 for a **session-issued link**:

- The request is `POST /approvals/{approval_id}/link` in the console
  session, with its CSRF token.
- B2 refuses unless the approval is pending and the session's (scope,
  subject) is one of its candidates, still eligible under the current policy,
  by the same checks a decision makes. The holder's principal must still be a
  current human member.
- B2 then mints a personal link exactly as it mints an emailed one
  (`service.py:303-316`): bound to the approval id, that candidate's subject
  and the frozen `request_sha256`, single-use, and expiring at the earlier of
  the approval's expiry and ten minutes. Minting it revokes that candidate's
  earlier unused link for the approval.
- The token is returned once, to that session only, and never logged.
- From there the page runs unchanged: `view-options` and `view` with a VIEW
  assertion, `decision-options` and `decide` with an APPROVE or REJECT
  assertion, and B2's candidate and first-decision checks.

A session-issued link authorizes nothing by itself, as an emailed one does
not. Login or an approval id never replaces the link or either assertion.
For a human role, B2 delivers no link at request time. Emailed links stay for
contact roles.

## N4. Terminal input and the runner code

In the approved journey, a value reaches secrets either from the human's
terminal through `aw`, as below, or from the team's vault by reference, with
no value typed. The runner code reaches the human only through `aw` on the
controlling terminal, because `aw` makes the confirm call (see
[Change set](#confirming-a-frozen-request)). Both use a `session` handoff. The console's value entry
and its display of the runner code stay available, outside this journey.

**Values.** A secret value, or the 1Password service-account token at
`POST /installations/{id}/backend-credentials/onepassword/versions`
(`naapp/secrets/src/aweb_secrets/console_values.py:206`):

- `aw` reads the value from the controlling terminal with echo off, reusing
  the terminal discipline of `TerminalPassphrasePrompt`
  (`cli/go/awid/human_signer.go:74`) and `humanAtTerminal`
  (`cli/go/cmd/aw/id_human.go:111`).
- It refuses with `protected_input_unavailable` when there is no controlling
  terminal or an agent-runtime marker is present. Values never come from
  argv, the environment, a pipe or a file.
- The value goes only to the pinned origin, in the handoff session. Its body
  is excluded from `--trace` (`cli/go/cmd/aw/root.go:178`) and from every
  log, never echoed, and wiped after sending.
- The response shows the version only. Staging stays inert until the change
  set is confirmed (secrets §6.2).

**Runner code.** The confirmation result carries it
(`naapp/secrets/src/aweb_secrets/console_results.py:56`):

- `aw` writes it only to the controlling terminal. Machine-readable output
  carries `runner_id` and `registration_required: true`.
- `aweb-secrets-runner register` takes no code argument, because argv
  leaks; it refuses one with `runner_arguments_invalid`
  (`naapp/secrets/runner/src/aweb_secrets_runner/main.py:17-28`). With a
  controlling terminal it prompts for the code with echo off, and that is the
  protected journey: the operator types the code that `aw` showed. Without a
  terminal it reads one line from stdin (`main.py:47-52`), for an automated
  caller on a private pipe, such as the e2e harness. That path is outside the
  protected journey, because the code is then held by another program, and
  `aw` never writes the code anywhere but the controlling terminal.
- Its limits are unchanged: ten minutes, single use, stored as a hash.

## Session actions: what `aw` drives

`aw` drives an app's human-origin routes in a `session` handoff only through
actions the pinned manifest declares, in `owner_acts.session_actions`
([manifest version 3](../app-manifest.md#manifest-version-3)). `aw` carries no
per-app code: the declaration names the route, which inputs come only from
the terminal, which outputs go only to the terminal, and how a confirm
completes. An app with no such action declares none. logs declares none,
since its reader needs only the `session` handoff.

```json
"session_actions": [
  {"name": "change-set", "kind": "read", "role": "secrets.owner",
   "method": "GET", "path": "/installations/{installation_id}/change-sets/{change_id}",
   "input_schema": {"type": "object", "properties": {"installation_id": {"type": "string"},
     "change_id": {"type": "string"}}, "required": ["installation_id", "change_id"]},
   "params": [{"name": "installation_id", "in": "path"}, {"name": "change_id", "in": "path"}]},
  {"name": "onepassword-token", "kind": "stage", "role": "secrets.owner",
   "method": "POST", "path": "/installations/{installation_id}/backend-credentials/onepassword/versions",
   "input_schema": {"type": "object", "properties": {"installation_id": {"type": "string"},
     "value": {"type": "string"}}, "required": ["installation_id", "value"]},
   "params": [{"name": "installation_id", "in": "path"},
              {"name": "value", "in": "body", "protected": true}],
   "body": {"mode": "json"}},
  {"name": "confirm", "kind": "confirm", "role": "secrets.owner",
   "method": "POST", "path": "/installations/{installation_id}/change-sets/{change_id}/confirm",
   "input_schema": {"type": "object", "properties": {"installation_id": {"type": "string"},
     "change_id": {"type": "string"}}, "required": ["installation_id", "change_id"]},
   "params": [{"name": "installation_id", "in": "path"}, {"name": "change_id", "in": "path"}],
   "body": {"mode": "json"},
   "terminal_output": ["/runner_registrations/*/registration_code"],
   "completion": {"read": "change-set",
                  "ready": {"member": "can_confirm", "in": [true]},
                  "done": {"member": "state", "in": ["applied"]},
                  "stop": [{"member": "state", "in": ["cancelled", "expired"]},
                           {"member": "approval_state", "in": ["rejected", "revoked", "expired"]}]}}
]
```

An action is a tool object of version 2 with these differences:

- `name` is unique among the session actions. `aw app human <app> <name>`
  runs it, and `aw app human <app> --help` lists the declared actions with
  their descriptions. Session actions are not agent tools: they never appear
  in `aw <app> --help`, a grant snapshot or an MCP tool list, and an agent
  call to one is not possible, because its route is on the human origin.
- `role` names a role of `owner_acts.roles`. `aw` runs the action in a
  `session` handoff for that role's holder scope, on `owner_acts.origin`. It
  reuses one live session for every action of one invocation, and signs each
  request as the `session` purpose requires.
- `path` is relative to `owner_acts.origin`, under the version 2 path and
  parameter rules. A path parameter named `installation_id` is filled by `aw`
  with the resolved installation and is not a flag. `scopes`, `mutation` and
  `invocation_contexts` are not declared: authority is the holder's session.
- `kind` is one of:
  - **`read`**: a `GET` with no protected input. It changes nothing.
  - **`stage`**: a `POST` that stages a value or a vault reference. The app
    guarantees that what it stages grants nothing until a change that names
    it is confirmed.
  - **`draft`**: a `POST` that creates a change for approval. A draft made in
    a key-bound session is what sets the confirm mark
    ([Change set](#confirming-a-frozen-request)); `aw` does nothing more.
  - **`confirm`**: a `POST` that applies an approved change, with the
    `completion` rules below.
- A param may declare `protected: true`, only on an `in: body` param of a
  `stage` action. Every other kind declares none.
- `terminal_output` lists the response members that go only to the
  terminal, as JSON pointers (RFC 6901) in which a `*` segment matches every
  index of an array. Only a `confirm` action may declare it.

**Protected input.** `aw` reads each protected field from the controlling
terminal with echo off, as in [N4](#n4-terminal-input-and-the-runner-code),
and never from a flag, the environment, a pipe or a file: a protected field
has no flag. With no controlling terminal, or under an agent-runtime marker,
`aw` refuses with `protected_input_unavailable` before it opens a handoff.
The request body is excluded from `--trace` and every log, and wiped after
sending.

**Terminal output.** Before it calls an action that declares
`terminal_output`, `aw` requires a controlling terminal and no agent-runtime
marker, or refuses with `protected_output_unavailable`, so a one-time value
is never produced where it cannot be shown. It writes each matching value
only to the controlling terminal, labelled with its concrete pointer (for
example `/runner_registrations/0/registration_code`). It removes those
members from the response it prints or returns as JSON, and keeps every
other member, such as `runner_id` and `registration_required`. A value is
never logged, traced or stored.

**Completion of a confirm.** `completion.read` names a `read` action each of
whose params names an input of the confirm, so `aw` builds the read from the
confirm's own invocation and needs nothing more from the human. A predicate names a top-level
member of that read's response and the JSON values that satisfy it, compared
by JSON type and value: `true` never satisfies `1`. `ready`
and `done` are one predicate each; `stop` is a list of predicates, any of
which stops.

1. `aw` reads the state. `done` means the change is already applied: `aw`
   reports `confirm_already_applied` and does not call confirm. `stop` refuses
   with `confirm_stopped`, naming the member's value. Otherwise it waits,
   reading again at most every two seconds, until `ready`, `done` or `stop`,
   for as long as the session lives.
2. On `ready`, `aw` calls the confirm action once, and shows its result under
   the terminal-output rule.
3. On a lost reply (no response, or a `5xx` with no JSON body), `aw` never
   calls confirm again. It reads the state: `done` reports
   `confirm_result_lost`, because the change applied and a one-time output
   with it is not recovered; `ready` reports `confirm_not_applied`, meaning
   not applied when read: a confirm still committing can land after that
   read, and a later run's first read then reports it as
   `confirm_already_applied`, its one-time output lost. Anything else reports
   the read's state.
4. When the app refuses the session (`401 console_session_required`), `aw`
   opens a fresh `session` handoff once, and reports a second refusal. If it
   has not yet sent the confirm, it resumes from step 1. If it has, it resumes in step 3: it only reads and
   reports, and never sends the confirm again, even when the read says
   `ready`, because the first confirm may still be committing. An invocation
   sends the confirm at most once.

The app's own refusals pass through with their status and `detail`, such as
`409 change_not_approved` or `403 owner_required`. `aw`'s own codes are
`protected_input_unavailable`, `protected_output_unavailable`,
`session_action_unknown` (no declared action of that name),
`confirm_already_applied`, `confirm_stopped`, `confirm_result_lost` and
`confirm_not_applied`. Each exits non-zero except `confirm_already_applied`.

**secrets** declares, for `secrets.owner`:
- the change-set `read`, `draft` and `confirm`, with the runner code as
  `terminal_output`, as in the example;
- `stage` actions for the 1Password service-account token (its `value`
  protected) and for a 1Password reference
  (`POST /installations/{installation_id}/onepassword/references`, nothing
  protected).

A native secret value is declared the same way, its value protected, on the
route that stages it.

## L6: the `aw logs` reader

`aw logs` signs in through a `session` handoff on logs' origin, with the
reader's holding. Logs issues the short-lived session bound to the ephemeral
key, as L6 plans. The reader is a human-role holder, `logs.reader`, bound by
its owner act. There is no second reader CLI.

## Optional: a security key from the terminal

A human may instead hold a roaming CTAP2 security key with user verification
and use it from `aw`, with no browser. It is never required.

- **Credential.** rp.id `aweb:`, non-discoverable, with a random user handle,
  one per human identity. `aweb:` is not a hostname, so no web page can ask a
  browser for an assertion under it.
- **Binding.** A human-role act binds it with rp.id `aweb:` in its credential
  hash ([Three acts](human-role-holders.md#three-acts)). The default is the
  origin's hostname. An installation accepts an `aweb:` assertion only for a
  holding bound under `aweb:`, and a hostname assertion only for one bound
  under the hostname. The authenticator puts the rp.id hash in every
  assertion, so neither profile's credential can answer for the other.
- **Assertion.** clientData is
  `{"type": "webauthn.get", "challenge": ..., "origin": <owner_acts.origin>}`,
  with the origin exactly the installation's pinned `owner_acts.origin`. `aw`
  fetches the challenge from, and posts the assertion to, only that origin,
  follows no redirects, and never takes an origin from a response. The
  challenge preimages bind no app or origin (`docs/hook-events.md:550-557`),
  so this rule is what keeps one app from relaying another's challenge.
- **What B3 adds:** a relying party with rp_id `aweb:` whose expected origin
  is the app's `owner_acts.origin`, since `RelyingParty` otherwise takes
  rp_id from an https hostname (`naapp-lib/src/aweb_naapp/runtime/passkeys/rp.py:29-33`).
  The retained-evidence rule that rp_id equals the hostname
  (`proof.py:393-394`) also admits exactly `aweb:` for such a holding. Under
  `aweb:`, the origin is reported by `aw`, not by a browser.
- **Use.** `aw` drives the same console routes with these assertions: a
  native login yields the console session, and use, run, change-set and
  reconciliation decisions use their existing view and decide routes.
- **Measured.** Which authenticators accept `aweb:` is measured, and the
  supported list is published with the implementation. OpenSSH's `ssh:` is
  precedent for the shape only.

The challenge preimages, their lifetimes, sign-count handling,
`candidate_subject_type` `app_local` and the hook-payload commitment are
unchanged in both profiles.

## Work this creates

Each item is filed after review, and each is one reviewed change.

- **`aweb_naapp`:** the handoff routes and page, on B3's registration and
  login, with the loopback rule and the signed session requests; the
  human-kind check at use. Tests:
  - a handoff registering a non-loopback redirect URI is refused;
  - a result requested without the loopback code is refused;
  - a replayed session request, an expired session and a request with a bad
    signature each get the same `401 console_session_required`;
  - membership evidence: a certificate for another principal, team or key, a
    revoked certificate, one signed under a rotated team key, and none
    presented or retained each refuse with `403 principal_not_member`; a
    `credential` handoff leaves no state; unreadable status
    gives `503 principal_status_unavailable`; a refreshed certificate
    presented in a session for another holding refuses and changes nothing;
    retaining a certificate does not extend a session; a valid certificate
    whose AWID row has no stored blob passes; ordinary team-auth requests are
    unchanged.
- **B2 (`aweb_naapp`):** the session-issued link, with tests:
  - a non-candidate session is refused;
  - an ineligible session is refused;
  - a link for a different request hash is refused;
  - a second issue revokes the first.
- **Consoles:** the `session` handoff for secrets and logs; for secrets, the
  N3 pending list, opening each entry through a session-issued link. Logs has
  no B2 approvals and gets no N3 entry.
- **secrets change sets:** the confirm mark, set only by a draft in a
  key-bound session, and the browser's `confirm_in_aw` refusal. Tests, for a
  marked change set that creates a runner:
  - the browser's confirm is refused and returns no code;
  - `aw`'s confirm applies it once and alone receives the code;
  - a confirm from a second key-bound session of the same decider succeeds
    once;
  - a repeated confirm does not apply it again.

  And a team-auth-drafted change set stays confirmable on the console.
- **Manifest readers** (Go `cli/go/internal/appmanifest`, `aweb_naapp.manifest`):
  `owner_acts.session_actions`, against the `manifest` cases of
  `docs/vectors/owner-act-delivery-v1.json`.
- **`aw`:** opening the browser, the loopback listener and the handoff, and
  `--no-browser`; `aw app human` driving the declared
  [session actions](#session-actions-what-aw-drives), with N4's terminal
  input and output, their exclusion from tracing, and a confirm's
  completion and lost-reply rules. Tests include the sequence: confirm sent,
  reply lost, `401` on the next read, fresh handoff, read still `ready`
  while the first confirm commits; `aw` reports and never sends a second
  confirm. Predicates compare by JSON type.
- **secrets:** the `session_actions` declaration.
- **The runner:** the registration runbook for the protected journey (the
  operator types the code at the runner's existing terminal prompt), and a
  test that the private-stdin path still reads one line.
- **L6:** the `session` handoff on logs' origin.
- **The optional security key**, a separate item that blocks none of the
  above: the `aweb:` relying party and evidence rule
  in B3; CTAP2 creation and assertion in `aw`; a test that a redirect from
  one app's route to another's is refused and no assertion is made; the
  measured authenticator list.
