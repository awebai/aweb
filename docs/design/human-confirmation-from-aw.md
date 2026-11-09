# Human confirmation started from `aw`

Status: **proposed** (aweb-acwd.4, gap G-B for the LF demo epic aweb-acwd).
Juan ruled the browser default and the optional security key. N3 and N4 await
his ruling. This is a contract only. Implementation tasks are filed after
review.

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

## Summary for Juan

| Item | State | Main tradeoff |
| --- | --- | --- |
| Browser passkey by default, opened by `aw` | Ruled | Each app origin is its own relying party, so a human creates one passkey per app origin. Synced passkeys make that one gesture each. |
| A security key from the terminal | Ruled optional | It is accepted only for a holding bound under it, never by default. |
| N3. How an approver finds a pending request | Pending | With no approval email for a human role, the console's own list of the approver's pending approvals is how it finds them. |
| N4. Terminal input and output | Pending | Typing a value, or receiving the runner code, in the terminal keeps them out of the browser. It is a local barrier, not gesture evidence. |

## Trust

- The browser, the authenticator and `aw` are trusted for what they show. A
  compromised one can show one action and confirm another.
- Every login and approval is a user-verified WebAuthn assertion that B3
  verifies at the app's human origin and retains as
  `aweb.passkey-evidence/1`. There is no attestation
  (`naapp-lib/src/aweb_naapp/runtime/passkeys/webauthn.py:37-50`), so the
  evidence proves the credential and the origin the client reported, as for
  any WebAuthn relying party.
- An agent running as the same OS user can drive the browser and the
  terminal. It cannot produce the authenticator's user verification, which
  is why every effect needs a fresh assertion.
- An unsupported configuration refuses. Nothing falls back to an ordinary
  signature, a team-auth request or a member-session assurance.

## The handoff

One mechanism connects `aw` to a browser ceremony. It is L6's planned device
flow (aweb-acgh.16.24), specified here once for every naapp and served on the
installation's pinned `owner_acts.origin`:

1. `aw` makes an ephemeral key, held only in memory, and calls
   `POST <origin>/handoffs` with its purpose, the public key and, for a
   session, the holder's scope. The app answers a handoff id, a short user
   code and a ten-minute expiry. The handoff grants nothing.
2. `aw` shows the user code and opens `<origin>/handoff`. The human types the
   code shown in their terminal; the URL never carries it. The page names the
   purpose, the app and the installation.
3. The browser runs the purpose's ceremony (below) with B3's existing
   routes, challenges and checks.
4. `aw` collects the result from `POST <origin>/handoffs/{id}/result`, signed
   by the ephemeral key. A result is returned once and expires with the
   handoff.

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
  minutes, with its CSRF token, and every request signed by that key. Each
  request re-checks that the principal is a current human member
  ([Use](human-role-holders.md#use)).

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
- **Change set:** the owner's confirm on the console applies the change
  (`naapp/secrets/src/aweb_secrets/console_changes.py:390`, `:513`).
- **Reconciliation:** as secrets §11.4 defines.

**N3 (pending): finding the request.** A human role has no approval email:
its contact is notice-only ([H3](human-role-holders.md#summary-for-juan)).
The console therefore lists the pending approvals for which the signed-in
approver is a candidate: approval id, kind and the page to open, with no
terms. Email locators stay for contact roles.

## N4 (pending). Terminal input and the runner code

By default, values are entered on the console and the runner code is shown
there, as on main. N4 adds a terminal path through a `session` handoff.

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
(`naapp/secrets/src/aweb_secrets/console_results.py:56`). Under N4:

- `aw` writes it only to the controlling terminal. Machine-readable output
  carries `runner_id` and `registration_required: true`.
- `aweb-secrets-runner register` reads it from its own controlling terminal
  when `--code` is absent. `--code` stays accepted (secrets §9.2).
- Its limits are unchanged: ten minutes, single use, stored as a hash.

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
  login; the human-kind check at use.
- **Consoles (secrets, logs):** the `session` handoff; under N3, the pending
  list.
- **`aw`:** opening the browser and running the handoff; under N4, terminal
  input and code output and their exclusion from tracing.
- **The runner:** under N4, a terminal prompt for the code.
- **L6:** the `session` handoff on logs' origin.
- **The optional security key:** the `aweb:` relying party and evidence rule
  in B3; CTAP2 creation and assertion in `aw`; a test that a redirect from
  one app's route to another's is refused and no assertion is made; the
  measured authenticator list.
