# Human confirmation started from `aw`

Status: **decided** (aweb-acwd.4, gap G-B for the LF demo epic aweb-acwd).
Juan ruled every item below. This is a contract; implementation tasks are
filed from [Work this creates](#work-this-creates).

With it, a human finishes every protected naapp operation that `aw` starts:

- confirming a frozen request;
- entering a value or the 1Password service-account token;
- receiving a runner's registration code;
- signing in as a logs reader;
- endorsing a deployment identity
  ([proposed](#endorsing-a-deployment-identity)).

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
   scope. The app accepts only a redirect URI of the form
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
  and a nonce already seen in that session. Each request re-checks that the principal is a current human member
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

## L6: the `aw logs` reader

`aw logs` signs in through a `session` handoff on logs' origin, with the
reader's holding. Logs issues the short-lived session bound to the ephemeral
key, as L6 plans. The reader is a human-role holder, `logs.reader`, bound by
its owner act. There is no second reader CLI.

## Endorsing a deployment identity

Status: **proposed** (aweb-acwd.11). Juan approved the direction on
2026-11-09. Athena ruled the passkey binding (H4 reuse) and the host (the
team server); neither is a guarantee change. The admission side, policy and
the read that direct naapps use are in the deployment endorsement contract
(aweb-acwd.10), whose section (d) this section meets.

A human H endorses a deployment identity D by signing D's ID certificate
([identity certificates](../id-certificates.md)). An ordinary signature
proves only that something used H's key. A **protected endorsement** adds a
fresh, user-verified passkey confirmation of that exact certificate request,
made by a credential that H's team controller bound to H. Policy that
requires protected endorsement accepts nothing less. A certificate that H's
key issued without it, or that a session-only Cloud lane issued, stays an
ordinary endorsement.

### Three authorities, kept apart

- **Personhood:** H's issuer-vouched ID kind `human` (the ID tree).
- **Identity signing:** H's own key signs D's certificate, in `aw`. No
  passkey becomes or replaces an Ed25519 key.
- **Credential provenance:** the team controller's
  [`human-role.designate`](human-role-holders.md#three-acts) act binds the
  passkey H confirms with. H's key never binds a credential to H.

None substitutes for another. The server's install-admin or operator access
binds nothing and confirms nothing.

### The host is the team server

The ceremony runs on the team's aweb server, which every team already has, so
endorsing an identity installs no app and needs no secrets or logs.

- **Origin.** The server's human origin is the origin of `server_url` in the
  controller-signed `aweb.team-server/1` record
  ([team-server discovery](app-team-server-api.md#trust-chain-the-naapp-checks)).
  The full origin is the acts' `aud`; the passkeys' rp_id is its hostname,
  so for `https://coord.example:8443` the rp_id is `coord.example`. It is
  https, as B3's relying party requires. Clients resolve it only from
  that record, never from a caller, a response or a redirect. A changed origin
  hostname orphans the bound passkeys (a new rp_id); rebinding is
  `human-credential.replace`, and there is no migration path.
  When the team server's origin changes, its existing endorsement rows stay
  valid, because their retained assertions verify under their recorded rp_id;
  new confirmations need a credential rebound with `human-credential.replace`. A
  move to a different team server carries no rows, and endorsements there are
  made afresh.
- **The endorser role.** The server is a first-party human-role host with one
  fixed declaration, shipped with the server and known to `aw`: `app_id`
  `team-server`, role `endorser`, label "Deployment endorser", acts
  `human-credential.replace`, `human-role.designate` and `human-role.revoke`,
  and no notice contact. Its `installation_id` for a team is the UUIDv5 of
  `aweb:team-server:` followed by the `team_id`, under the RFC 4122 URL
  namespace. Its generation is 1. There is no manifest and no install.
- **Ceremony bindings.** B3's scope for H's endorser holding is
  `team-server.endorser.` followed by the first 40 hexadecimal characters
  of SHA-256 over the UTF-8 of `installation_id`, `team_id` and H's `did:aw`,
  joined by LF, as secrets derives an owner's scope. B3's subject is H's
  `did:aw`, and `candidate_subject_type` stays `app_local`. The B2 policy is
  `team-server.endorse-deployment`, version 1: passkey assurance, a
  ten-minute lifetime, H's endorser scope as its only approver scope, and
  requester approval allowed, because H both requests and confirms the
  endorsement. The protection is the fresh user-verified assertion by the
  controller-bound credential, not a second approver. The covered request
  travels in B2's existing `aweb.approval-request/1` wrapper.
- **Verification.** The coordination server's owner-act vocabulary
  ([acts and subjects](../owner-act.md#acts-and-subjects)) gains the three
  human-role acts for that `app_id` and that `installation_id` only; an act
  naming any other app or installation is refused with `owner_required`. They
  arrive at `POST <origin>/.well-known/aweb-owner-act` and pass the
  delivery stages of [owner-act delivery](../owner-act-delivery.md#delivery)
  unchanged, including stage 3's membership and kind checks. Stage 3's
  installation is the one derived from the act's `team_id`, for a team the
  server coordinates.
- **One verifier.** The server runs naapp-lib's B2, B3, console sessions, the
  [handoff](#the-handoff) and the delivery stages as a library. It writes no
  second WebAuthn verifier and no second copy of stage 3.
- **Hooks.** The server is not an app producer. It keeps the binding and
  endorsement history in its own tables and emits no `post-governance-hook`.
  Its handoff therefore offers the loopback only; the typed-code fallback,
  which requires that event, refuses with `409 fallback_unavailable`.
- **One origin for both roles.** The server has no separate app origin and
  human origin: its API and its human pages share the record's origin. It
  accepts team-auth on its API paths, including `POST /handoffs`, and applies
  the human origin's refusal (`403 team_auth_refused` for `Authorization`,
  `X-AWEB-*` or `X-AWID-*`) to its handoff page, result, console and
  endorsement paths. The console session cookie is `Secure`, `HttpOnly` and
  `SameSite=Strict`, and the API authenticates by team-auth headers and
  ignores cookies, so the two credentials never stand in for each other.
- **Cost to everyone else.** An operator who never uses protected
  endorsement configures nothing and runs nothing new: the migrations are
  additive, there is no new required setting, and no startup check can fail.
  The routes refuse until a controller binds an endorser.
- **Price.** Binding is one owner act per endorser credential, made once.
  Admission reads one endorsement row and its holding locally, with no AWID
  call; a direct naapp adds only the read that deployment endorsement (c)
  defines.
- **Hosted teams** get the same shape through the aweb pin. Which origin Cloud
  uses is a hosted decision, filed when this lands; it does not block this
  contract.

### Binding the endorser

H's `aw` runs a `credential` handoff on the server's origin. The passkey it
returns authorizes nothing. The team controller signs `human-role.designate`
for (`team-server`, the team's installation, `endorser`, H) with its
`credential_sha256`, after the two clients show the same fingerprint over a
channel that H's custodian does not control. When the controller is H, one
client runs the handoff and signs the act in one sitting, as
[H4](human-role-holders.md#what-the-owners-client-shows-and-signs) says.

### The endorsement

1. **The request.** D exports its certificate request
   (`aweb.id-certificate-request/1`, kind `agent`, parent H), and H's `aw`
   receives it as for any child. When the endorsement must be protected, `aw`
   does not sign yet.
2. **Freezing it.** `aw` opens a `session` handoff for H's endorser holding
   and posts the exact signed request file to `POST /endorsements` in that
   session. The server checks the request's shape and key proof, that its
   parent is H, that H holds a current endorser holding, and that D's
   `subject_key` is D's current key. It then creates one B2 approval whose
   covered request is exactly:
   - `csr_sha256`, the SHA-256 of the request's signing bytes;
   - D's `id`, `domain` and `subject_key`;
   - H's `did:aw`;
   - the team and the server's installation;
   - `disclosure_version`, naming the disclosure text below.

   Its only candidate is H's endorser holding. The response is the
   endorsement id and the approval id.
3. **Confirming it.** The approval page on the server shows D's ID, domain and
   key fingerprint, H, the team, and the disclosure, verbatim: **"Endorsing
   this identity endorses everything it spawns, recursively, until you
   withdraw it."** H approves with an APPROVE assertion by the bound credential.
   B3 verifies it and retains its proof (`aweb.passkey-evidence/1`); B2
   records the decision.
4. **Consuming it.** `aw` reads the endorsement in its session until it is
   approved, then calls `POST /endorsements/{id}/consume`. In one
   transaction the server takes the holding's lock and re-reads the holding;
   then it reads the clock and checks that the approval is approved,
   unexpired and not yet consumed, and that its assertion was made by the
   current holding's credential; then it records the consumption with that
   holding. A consume that waited on a concurrent `human-credential.replace`
   refuses; it never records the new holding. The answer is the covered
   request and `approval_evidence_sha256`.
5. **Signing.** `aw` signs D's certificate with H's key only if the consumed
   covered request's `csr_sha256` equals the request it is about to sign. The
   issuance log records the endorsement id.
6. **Linking.** `aw` posts the issued certificate to
   `POST /endorsements/{id}/certificate`, in H's endorser session. The
   server accepts it only if H's current key signed it, and its `id`, `domain`, `parent` and `kind` equal
   the request's. It records `certificate_sha256`, over the certificate's
   signed bytes, once. The same certificate again returns the same record;
   a different one refuses with `endorsement_certificate_conflict`. D then
   registers the certificate in AWID as for any child.

The endorsement row binds `csr_sha256`, D's id and key, H, the disclosure
version, the approval id, `approval_evidence_sha256`, the holding it was
consumed under, `certificate_sha256`, and its withdrawal state. The original
proof and request bytes stay retained for audit. A row with no linked
certificate endorses nothing.

### Withdrawal

H withdraws an endorsement with `POST /endorsements/{id}/withdraw` in a
`session` handoff for H's endorser holding. Withdrawal narrows, so it needs
no assertion beyond the session's sign-in. Signing in needs a current
holding. When H has none or cannot sign in, D's ID certificate is revoked by
one of the identities
[allowed to revoke it](../id-certificates.md#revocation-authority-and-cascade):
H, as D's current parent, with H's own key; D itself; or the namespace root.
Team authority is not ID authority: the team controller cannot revoke D's
ancestry. The team controller can contain access in that team by revoking
the membership certificates of D and each affected descendant; this does not
revoke their ID ancestry or authority in other teams. The row keeps its
history and records `withdrawn_at`; a withdrawn row never becomes current
again. Admission reads the withdrawal state at the
freshness deployment endorsement (c) bounds.

### What admission verifies

Admission that requires protected endorsement checks D's registered
certificate against a row whose `certificate_sha256` matches it, D's current
registered key against the row's `subject_key`, the row not withdrawn, and
the current H-rooted ancestry (deployment endorsement (c), (d)). The key
check costs nothing extra: the ancestry check already resolves D's current
key.

**Continuity.** A protected endorsement covers one D, one key and one
certificate revision. When D's key rotates, D is re-endorsed. When D is
re-parented or gets a new certificate revision, D is re-endorsed, because no
row matches the new certificate. `resign` does not apply: it is for `did:key`
children, and the covered request names a registered D. An unrelated refresh
of D's ancestry evidence, with the same D, key and certificate, changes
nothing.

A direct naapp verifies the original artifacts, not the row's word:

- the controller act that bound the credential current at consumption,
  under the team key: the holding's `human-role.designate`, or the
  `human-credential.replace` that superseded it once its cooling-off ended.
  The row retains the holding's binding history, so each act in the chain
  verifies;
- the retained assertion against that act's `credential_sha256`, and its
  commitment against `approval_evidence_sha256`;
- the challenge's covered request against the row's `csr_sha256`, D and H.

The proof is valid only against the holding that was current when it was
consumed. Replacing or revoking that credential later does not withdraw the
endorsement: endorsements stand until withdrawn explicitly (deployment
endorsement (e)). The disclosure says so: replacing a lost or compromised
credential does not withdraw what it endorsed, and H or the owner withdraws
those endorsements.

### What this guarantees, and what it does not

This is Athena's statement (`9778950d`, section 3). No release note may claim
more.

Someone who holds only H's key cannot make a protected endorsement. Binding
needs the controller's act, which is refused with `owner_required` when H's
key signs it, and an assertion by a credential other than the current
holding's does not verify. The binding is only as independent as the
controller key's custody is from H's key and from the agents. Keep the
controller key and H's key in different custody if the endorsement is to mean
a human gesture.

A protected endorsement does not hold against:

1. one custodian holding both the controller key and H's key, or controlling
   the owner's signing client: it can bind any authenticator;
2. whoever controls H's client during the `credential` handoff: it can
   substitute a credential and show the substitute's fingerprint, so the
   comparison passes; the owner-is-H single sitting has the same exposure on
   that machine;
3. a fingerprint compared over a channel the custodian controls, such as aweb
   mail, a notice, or a second key under the same custodian.

It claims neither:

4. authenticator attestation: a software authenticator bound by a legitimate
   controller act counts;
5. that two `did:aw` values are two people.

The binding is trust on first use. A later compromise of H's authenticator is
handled by replace or revoke, and is not detected.

### Refusals and negatives

Each is a vector row, for the server and for a direct naapp:

| Case | Result |
| --- | --- |
| The confirmed request differs from the one `aw` signs (changed CSR) | `aw` refuses to sign; a certificate that does not match the request is refused at linking |
| A second consumption of the approval (replay) | refused; one consumption per approval |
| An APPROVE by anyone but H's endorser holding (wrong approver) | refused by B2's candidate check |
| A consumption after the approval expired (stale proof) | refused |
| A binding act signed by H's key | `owner_required` |
| An assertion by a credential that is not the holding's | refused, and no row |
| A certificate from a session-only Cloud lane or plain human-key issuance | no row; protected admission refuses |
| An endorsement made before a `human-credential.replace` | still verifies |
| An endorsement made with the replacement credential, after the cooling-off | verifies against the replace act |
| A confirmation consumed after the replace, using the old credential | refused |
| A withdrawn endorsement | admission denies; history kept |
| D's key rotated after the endorsement | admission refuses; D is re-endorsed |
| D re-parented after the endorsement | admission refuses; no row matches |
| The same D and key after an unrelated refresh of ancestry evidence | admits |
| The team server's origin changed after the endorsement | the row still verifies; a new confirmation needs the replaced credential |
| An owner act naming any other app or installation at the server | `owner_required` |
| The server's handoff in the typed-code fallback | `409 fallback_unavailable` |
| A team-auth header on the server's handoff page, result, console or endorsement paths | `403 team_auth_refused` |

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
  - a replayed session request is refused.
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
- **`aw`:** opening the browser, the loopback listener and the handoff, and
  `--no-browser`; N4's terminal input and code output and their exclusion
  from tracing.
- **The runner:** the registration runbook for the protected journey (the
  operator types the code at the runner's existing terminal prompt), and a
  test that the private-stdin path still reads one line.
- **L6:** the `session` handoff on logs' origin.
- **Deployment endorsement (the server),** once this section is ACKed: the
  `team-server` endorser declaration and owner-act vocabulary row; naapp-lib's
  B2, B3, console sessions, handoff and delivery stages composed into the
  server as a library, with additive migrations; the endorsement routes and
  row; local credential audit with no hook production. Tests: every row of
  [Refusals and negatives](#refusals-and-negatives), and an operator who
  binds no endorser sees no change.
- **Deployment endorsement (`aw`):** the protected path of child approval
  (freeze, confirm, consume, sign only on a matching consumed request, link),
  and resolving the server's origin only from the team-server record.
- **The optional security key**, a separate item that blocks none of the
  above: the `aweb:` relying party and evidence rule
  in B3; CTAP2 creation and assertion in `aw`; a test that a redirect from
  one app's route to another's is refused and no assertion is made; the
  measured authenticator list.
