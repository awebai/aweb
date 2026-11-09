# Native human confirmation for naapps

Status: **proposed, awaiting review and Juan's ruling** (aweb-acwd.4, gap G-B
for the LF demo epic aweb-acwd). This is a contract only. Implementation tasks
are filed after review.

With it, a human finishes every protected naapp operation from a terminal:

- confirming a frozen request;
- entering a value or the 1Password service-account token;
- receiving a runner's registration code;
- signing in as a logs reader.

The existing B2 and B3 machinery carries all four. The consoles stay, but they
are not the only way to finish. The holder is bound by
[human-role acts](human-role-holders.md) (aweb-acgh.16.38). This adds no
approval service, credential architecture or token profile.

Requirement: Bookshelf `kb/concepts/customer-agent-servers.md` at `5c83ed85`,
lines 127-145, 157 and 173.

## Summary for Juan

| Ruling | Recommended | Main tradeoff |
| --- | --- | --- |
| N1. Native relying-party profile | WebAuthn assertions over CTAP2 from `aw`, with rp.id `aweb:` and the target's human origin in clientData | It needs a roaming authenticator with user verification (a security key). Touch ID and synced passkeys are not in this profile. |
| N2. A native client holds a console session | `aw` opens the existing console session with a native login assertion and keeps it in memory | Console sessions are not browser-only. CSRF and the 15-minute limit stay. |
| N3. How the approver finds a pending request | The approver's session lists its own pending approvals | Nothing pushes to the human: the requester or the human runs the list. |
| N4. Terminal-only input and output | Values are read from the controlling terminal with echo off, and the runner code is written only there. Both refuse under agent-runtime markers | This is a local barrier, not gesture evidence: an agent running as the same OS user defeats it. |

## Trust

- The native client and the authenticator are trusted. A compromised client
  can show one action and confirm another, and a hash does not prevent that.
- An agent running as the same OS user, able to read the client's memory or
  drive its authenticator, defeats the custody separation. The supported
  deployment runs `aw` as the human, in a terminal that no agent harness
  shares (Bookshelf, line 139).
- There is no attestation (`naapp-lib/src/aweb_naapp/runtime/passkeys/webauthn.py:37-50`).
  User verification is required on every assertion.
- An unsupported configuration refuses. Nothing falls back to an ordinary
  signature, a team-auth request or a member-session assurance.

## N1. The native profile

**Credential.** `aw` creates one credential per human identity on a CTAP2
roaming authenticator with user verification (PIN or built-in biometric):

- rp.id is `aweb:`;
- the credential is non-discoverable;
- the user handle is random.

Separate identities get separate credentials, so one credential id never
links a person's identities across organizations. The credential is bound to
a holder only by a [human-role act](human-role-holders.md#three-acts), once
per installation. There is no enrolment ceremony at the naapp.

**Assertion.** For a challenge that the target issued, `aw` sends CTAP2
`getAssertion` with rp.id `aweb:` and user verification and presence
required. Its clientDataJSON is:

```json
{"type": "webauthn.get", "challenge": "<base64url>", "origin": "<owner_acts.origin>"}
```

clientData.origin is exactly the installation's pinned `owner_acts.origin`.
`aw` fetches the challenge from, and posts the assertion to, only that origin.
It follows no redirects on these routes, and it never takes an origin from a
response, a header or any other field. The challenge preimages bind no app or
origin (`docs/hook-events.md:550-557`), so this rule is what keeps one app from
relaying another app's challenge.

**Why `aweb:`.** It is not a hostname, so no web origin can ask a browser for
an assertion under it. A page cannot collect these assertions across apps,
which is the cost of related origins. One credential serves every naapp, and
each challenge binds its audience and request. OpenSSH's `ssh:` application
uses the same idea. That is precedent for the shape, not evidence that a given
authenticator accepts it: which authenticators accept `aweb:` is measured, and
the supported list is published with the implementation.

**What B3 changes to accept it:**

- `RelyingParty` requires an https origin and takes rp_id from its hostname
  (`naapp-lib/src/aweb_naapp/runtime/passkeys/rp.py:29-33`). A native relying
  party has rp_id `aweb:`, and its expected origin is the app's own
  `owner_acts.origin`.
- `verify_assertion` is unchanged. It uses the relying party's rp_id and
  origin (`webauthn.py:58-90`).
- Retained evidence keeps `aweb.passkey-evidence/1` and its fields. Its rule
  that `rp_id` equals the origin's hostname (`proof.py:393-394`) becomes: the
  hostname, or exactly `aweb:`, for a credential bound by a human-role act.
  `aweb:` is never a hostname, so no field is added. An offline verifier
  of retained evidence accepts both. Under `aweb:`, clientData.origin is
  asserted by `aw`, not attested by a browser: the evidence proves that this
  credential signed this challenge, with `aw` reporting that origin.
- A credential carries the profile it was bound under. A browser-enrolled
  credential is never accepted under `aweb:`, and a native one never at a
  hostname.

**Unchanged:**

- the challenge preimages and their domains (`aweb.approval-challenge/1`,
  `aweb.passkey-login/1`);
- single-use challenges and their lifetimes;
- sign-count handling;
- `candidate_subject_type` `app_local`, because the approver row is the app's
  own and is linked to the principal;
- the commitment in hook payloads.

## N2 and N3. Confirming a frozen request from `aw`

The flow uses the console's existing JSON routes on the human origin, with one
addition, the pending list:

1. **Sign in.** `aw` asks for the holder's login options, makes a native
   assertion, and receives the existing console session: at most 15 minutes,
   with a CSRF token. The session lives only in `aw`'s memory. Each request
   re-checks that the principal is a current human member
   ([Use](human-role-holders.md#use)).
2. **List.** A session-authenticated route returns the approvals for which
   this session's approver is a candidate: approval id, kind and personal
   locator, and no terms. It is added beside the existing use, run, change and
   reconciliation approval routes. Email locators stay for contact roles.
3. **View.** A `view` assertion returns the frozen bytes. `aw` renders them by
   the console's rules (secrets §6.3, §10.4):
   - from the frozen bytes;
   - a known action schema per type, so an unknown type refuses with
     `action_schema_unknown` and is never shown as free text;
   - every IDNA host as Unicode and as its A-label;
   - every widening element marked;
   - drafter text labelled untrusted.
4. **Decide.** An `approve` or `reject` assertion goes to the existing decide
   route. B3 verifies it and retains the evidence, and B2 records the first
   decision.
5. **Admit.** The requester re-submits the same `request_id`. Single-use
   admission stays at the target (secrets §10.3, §10.5).

With no supported authenticator, `aw` refuses locally with
`authenticator_unsupported` and sends nothing. The request stays pending.

## N4. Protected input and the runner code

**Values.** These are a secret value, and the 1Password service-account token
at `POST /installations/{id}/backend-credentials/onepassword/versions`
(`naapp/secrets/src/aweb_secrets/console_values.py:206`).

- `aw` reads the value from the controlling terminal with echo off. It reuses
  the terminal discipline of `TerminalPassphrasePrompt`
  (`cli/go/awid/human_signer.go:74`) and `humanAtTerminal`
  (`cli/go/cmd/aw/id_human.go:111`), not the human-key signing operation.
- It refuses with `protected_input_unavailable` when there is no controlling
  terminal or an agent-runtime marker is present. Values never come from
  argv, the environment, a pipe or a file.
- The value goes only to the installation's pinned `owner_acts.origin` over
  TLS, inside a native session.
- Its request body is excluded from `--trace`
  (`cli/go/cmd/aw/root.go:178`) and from every log, and it is never echoed in
  output or in an error. The buffer is wiped after sending.
- The response shows the version only, as the console's does.
- Staging stays inert. The value is active only after its change set is
  confirmed through N2 (secrets §6.2).

**Runner code.** A runner record is created by a widening change confirmed
through N2. The confirmation result carries the code
(`naapp/secrets/src/aweb_secrets/console_results.py:56`).

- `aw` writes the code only to the controlling terminal, never to stdout,
  stderr, a log or JSON output. Machine-readable output carries `runner_id`
  and `registration_required: true`.
- `aweb-secrets-runner register` reads the code from its own controlling
  terminal when `--code` is absent. The operator runs it as the dedicated
  user, and the runbook uses this prompt. `--code` stays accepted, since it is
  released (secrets §9.2, `docs/design/secrets.md:1025`).
- The code's limits are unchanged: ten minutes, single use, stored as a hash.

## L6: the `aw logs` reader

L6's plan uses a device-style flow on logs' origin with the reader's passkey,
yielding a short-lived session bound to an ephemeral CLI key
(aweb-acgh.16.24). Under this profile:

- the device flow's browser step becomes a native login assertion for the
  reader's holding;
- logs issues the same short-lived session, bound to the ephemeral key;
- the reader is a human-role holder, `logs.reader`, bound by its owner act;
- the human creates one credential, and each installation's owner act binds
  it.

There is no second reader CLI. The browser device flow can stay an optional
client.

## Work this creates

Each item is filed after review, and each is one reviewed change.

- **`aweb_naapp` B3:** the native relying party, the per-credential profile,
  the retained-evidence rp_id rule and the human-kind check at use.
- **Consoles (secrets, logs):** native-session use of the existing JSON
  routes, and the pending-approval list.
- **`aw`:**
  - CTAP2 credential creation and assertion;
  - rendering by action schema;
  - terminal-only input and code output;
  - exclusion from tracing;
  - a test that a redirect from one app's route to another's is refused and no
    assertion is made.
- **The runner:** a terminal prompt for the code.
- **L6:** a native login in place of the browser step.
- **Supported authenticators:** the measured list.
