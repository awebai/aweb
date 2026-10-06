# Existing hosted team: global identity bootstrap and recovery

This is the native `aw` contract reference for an operator authorized to create a
**new** global identity using an existing hosted team's provisioning API key.
It does not select an organization, create a team, or grant provisioning authority.
For the complete OATS journey, use the provider's
[existing-team global resident procedure](https://github.com/awebai/oats-aweb/blob/main/oats-package/capabilities/oats-aweb/skills/oats-aweb/references/existing-team-global-resident.md).
OATS owns resident custody configuration, worker grants, team mapping and launch.

## Choose creation or reuse

| Intent | Native boundary |
| --- | --- |
| Create a new global identity in an existing hosted team | Explicit team provisioning key, service, registry and `aw init --global --name NAME` in a fresh destination. |
| Use a retained global resident | Preserve its identity and custody. Do not run fresh bootstrap over it. The provider consumes the resident and mints a scoped worker grant. |
| Add membership to an existing global identity | The [global invite/join procedure](identity-guide.md#join-an-existing-team) reuses the existing `did:aw`; it is not global identity creation. |
| Continue an incomplete creation | Reconcile the retained partial state and remote effects first; see the recovery limits below. |

A hosted provisioning key is distinct from the returned workspace credential,
resident signing key, worker session key and human browser token. Browser team
admission alone does not create a new global identity. No workspace-specific
team ensure/enroll step is part of this procedure. A separately authorized local
minting root is a separate operation, using its own authority when needed.

## Selected inputs and native effects

Use the owner's selected service and registry, intended global name, and the
correct team's provisioning key. Privately load `AWEB_API_KEY` into only the
bootstrap child environment; never put its value in command arguments, shell
history, tracing, review artifacts or messages. Validate the loader against the
actual private handoff format without printing values.

The destination is a fresh, explicitly chosen directory. Native state lives in
its `.aw/`. Do not target an existing resident, use another identity's ambient
selection, or manufacture native files. An operator runner must remove foreign
`AWEB_*`/`AWID_*`, `AW_CONFIG_PATH`, `AW_DEBUG`, `AW_TRACE` and proxy overrides,
then select only the required inputs. Set `AW_NO_UPDATE_CHECK=1`; check that the
chosen cwd contains neither `.env` nor `.env.aweb` (the latter can override the
child environment). Keep the real HOME; do not borrow another resident's home.

After establishing private capture below, run the selected command once:

```sh
aw init --global --name "$GLOBAL_NAME" \
  --aweb-url "$SERVICE_URL" --awid-registry "$REGISTRY_URL" \
  --do-not-touch-agents-md --json
```

The selected key determines the hosted team. A canonical provider-team ID,
namespace, full address and guessed exact-address collision lookup are **not
required inputs** to this branch. The service returns the canonical team and
assigned global address. A key-bound internal team UUID, if obtained through a
supported hosted read, is provenance; it is not interchangeable with the
certificate's canonical team string. Hosted key entitlement and allocation
semantics belong to the service. A refusal is an actual result to reconcile,
not a reason to guess a namespace, switch keys, or create another team.

The client generates signing material, saves partial state, registers the DID,
then requests hosted bootstrap. It verifies returned certificate/member key,
team, global scope and self custody before persistence/connect. `--json` skips
post-init docs/hooks; do not claim those ran. Docs injection otherwise may target
a Git worktree root rather than the nested custody directory. Successful connect
can update Git exclusions and the machine workspace index. Suppressing docs is
not a promise of no host bookkeeping.

## Retain diagnostics before dispatch

The following **operator capture recipe**, not a native capture flag, runs a
command supplied as its arguments. The caller first creates a fresh owned 0700
`CAPTURE_DIR` under an operator-only parent outside the source/review tree and
establishes the isolated child environment. No other user/process should be able
to replace that directory. Do not reuse a capture directory. Open every capture
before dispatch; failure to establish capture must stop the operation.

<!-- native-capture-example -->
```sh
umask 077
set +x
exec 3>"$CAPTURE_DIR/stdout" 4>"$CAPTURE_DIR/stderr" 5>"$CAPTURE_DIR/exit" || exit 125
set +e
"$@" >&3 2>&4
status=$?
printf '%s\n' "$status" >&5 || exit 125
exit "$status"
```
<!-- /native-capture-example -->

Native stdout, stderr and exit remain independent even on nonzero exit or absent,
malformed or refused JSON. Capture before parsing; never replace raw output with
only a classification. Raw output can contain sensitive material: keep it
operator-only and send only a reviewed public allowlist. Do not log invocation
environment or key input. This shell example is not a power-loss guarantee or a
supervised timeout facility. If the runner dies before recording exit, preserve
available files and report an uncertain outcome; never infer remote rollback.

The native HTTP diagnostic prints `category=hosted_http_failure`,
numeric `status`, a fixed known `error_code` or `unknown`, and a syntactically
validated UUID `request_id` or `unknown`. It omits arbitrary bodies for generic
HTTP failures and 401/404; recognized 409 identity-mismatch guidance retains its
existing message contract. Do not forward whole stderr on that basis. Extract
only the diagnostic fields for handoff; raw native output still stays private.
Request IDs are service-provided correlation values, not authenticated transaction
receipts. Invalid, contradictory or unavailable IDs stay unknown. This summary
does not establish which server stages committed or authorize a retry. Other
native errors are not automatically safe to publish.

## Validate outputs before use

A connected result is an intermediate milestone. Validate `alias` against the
selected name, `identity_scope=global`, the selected `aweb_url`, nonempty canonical
`team_id`, `stable_id`, and assigned `address`. Check native signing/certificate
consistency and self custody; do not equate internal UUIDs with canonical team
strings. Then use the same selected registry, without the provisioning key:

```sh
aw doctor identity --offline --json
aw doctor registry --online --json
```

Require the local `identity.e2ee.assertion_published` check to be present and OK.
Separately require exactly one `awid.did.encryption_key_matches_local` check to
be present, OK and authoritative. `doctor identity --online` does **not** run
registry checks. `aw id encryption-key show` reports local state and paths, not
authoritative publication. Connect can warn about publication and still succeed.
Validate the returned exact address's registry binding to the same stable DID and
current public key. Missing, blocked, unknown or contradictory evidence stops
advancement; a zero process exit alone is insufficient. Review the complete
output privately, distributing only the public facts required by the next stage.

Provisioning keys do not enter subsequent custody services or worker environments.
Remove a successfully consumed temporary handoff only under its owner's cleanup
instruction after validation; a separate unused credential is not consumed by
this operation. Complete provider custody, grant, launch and incoming-message /
signed-reply acceptance before calling an orchestrated workspace usable.

## Partial failure and explicit continuation

Record exact binary version/commit, command, cwd, selected origins, public DID,
exit and sanitized category/status/request ID without copying private keys.
Partial state can exist before registry registration or after hosted/persistence
failure. A registry key mapping proves registration, not hosted allocation; an
empty address list does not prove no hosted request committed.

Native same-context continuation reloads partial signing material and validates
its derived public identities, name, service, registry, role, human, agent type
and provisioning-key fingerprint. It does not require a new name, namespace or
credential. Complete identity/workspace state must not be overwritten. Resume
only after reconciling actual state and the service's same-key repeat contract,
using the same original selection and an explicitly reviewed single operation.
No automatic loop, absent-partial fresh fallback, manual state rewrite or borrowed
key is supplied by this reference.

**Current exception:** a successful hosted response containing a different
nonempty DID causes the native client to remove the partial file before returning
its collision error, before the later snapshot/rollback. In a partial-only target
this can lose the sole persisted signing material. The public registry is not a
backup. Report observed state (removal can fail), stop if material is absent, and
obtain an explicit recovery disposition. Do not describe every failed init as
key-preserving or improvise a copy/restore workaround. This behavior is tested;
changing it requires a separate identity-contract decision.

Same-identity reuse is not exactly-once execution. A service may reuse its agent
and address yet issue another workspace credential on repeated bootstrap. A lost
response may follow commit. Reconcile those effects; no unrequested cleanup or
revocation follows from a client retry. The synthetic real-CLI regression models
this boundary with the original team key and no repository input. It proves
client behavior against that representative service, not any deployed server's
idempotency or the cause of a particular failure.

## Contract anchors

- `cli/go/cmd/aw/init.go`: API-key branch and JSON addon behavior.
- `cli/go/cmd/aw/init_apikey.go`: partial material/context, registry-before-hosted
  ordering, certificate/response validation, mismatch deletion and connect rollback.
- `cli/go/cmd/aw/init_connect.go`: output fields and publication warning behavior.
- `cli/go/cmd/aw/doctor_identity.go`: local publication versus registry comparison.
- `cli/go/cmd/aw/init_apikey_recovery_command_test.go`: real-command diagnostic,
  protected-capture and representative committed-response-loss fixtures.
- `cli/go/cmd/aw/init_apikey_test.go`: existing mismatch-deletion and resume tests.
