# Independent protected server

The existing aweb package provides
`aweb.protected_signing.host:create_app`. Install its `protected` extra and the
coordinator-composed shared signer/AWID/console sources before launching:

```sh
uvicorn aweb.protected_signing.host:create_app --factory --host 0.0.0.0 --port 8080 --no-proxy-headers
```

This is a separate process from the coordination server. Route the profile's
request and human hostnames to it, retaining each original Host header. The
human origin requires TLS, including in the disposable lane. The shared origin
splitter serves only the two configured hosts, refuses agent credentials on the
human origin, and strips cookies on the request origin. Forwarded headers never
select the signed request audience. No other coordination API is mounted here.

Required operator settings (paths below are illustrative container paths):

```sh
export AWEB_PROTECTED_PROFILE_FILE=/config/protected-profile.json
export AWEB_PROTECTED_SCOPE_FILE=/config/protected-scope.json
export AWEB_PROTECTED_DATABASE_URL=postgresql://signer:REPLACE@postgres/protected
export AWEB_PROTECTED_DATABASE_SCHEMA=protected_signer
export AWEB_PROTECTED_CONTROLLER_KEY_FILE=/private-controller/controller.key
export AWEB_PROTECTED_MEMBER_KEYS_FILE=/private-member/members.json
export AWEB_PROTECTED_WORKER_UIDS='[1001]'
export AWEB_PROTECTED_HUMAN_CSRF_KEY=aweb.protected.console.csrf
```

The scope file is exactly one complete `bindings[].scope` from the validated
profile. The profile selects the registry origin and namespace/authority public
keys; there is no second registry URL, Cloud token, DNS fallback or runtime URL
override. See `docs/protected-service-profile.md` and its public synthetic
fixture. Those example public keys do not supply controller custody.

The controller file is the operator-provisioned 32-byte Ed25519 seed encoded as
64 hex characters, optionally followed by one newline. Its directory belongs
to the protected process euid with mode 0700; the regular file belongs to that
euid with mode 0400 or 0600. All declared worker UIDs must be positive and differ
from the protected process euid. Exclude that directory from worker/CLI mounts,
ACLs, backups and debugger access. Runtime neither generates nor imports a key.
The key must match both the selected profile binding and the registry's current
team controller. A mismatch refuses startup and later operations.

The member manifest uses the existing aweb configuration format:

```json
{"engineering:customer.example":"ordinary-member.pem"}
```

Paths resolve relative to the manifest. PEM files use aw's `ED25519 PRIVATE
KEY` seed format. These are registered ordinary member keys with valid team
certificates, required for actual private-team reads. A controller key in this
manifest refuses startup; it cannot substitute for a member. Provisioning the
certificate and protecting member credentials remain the operator's duties.

Notifications use the shared TLS `Mailer` and `PasskeyEmailDelivery`. Required
settings under `AWEB_PROTECTED_` are `EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`,
`EMAIL_USERNAME`, `EMAIL_FROM`, and `EMAIL_PASSWORD_FILE`; `EMAIL_TLS` is
`starttls` (default) or `implicit`, and `EMAIL_CA_FILE` optionally selects a
trusted CA file. The existing mailer requires TLS and SMTP authentication.
Missing configuration fails before a database or registry connection opens.
The small `ProtectedNotifications` adapter also implements B2's notification
port: it sends a retained public handoff locator to the recorded contact, never
a candidate bearer token, request payload or signature. The shared signer
currently retains B2 links privately and does not dispatch these notices from
prepare. Enrollment/contact notices use the existing B3 delivery contract.

For a disposable fixture, configure those same SMTP settings to a private TLS
capture server with a fixture CA/authentication, and keep its mailbox available
only to the test driver. This substitutes the outbound notification transport;
it does not qualify production mail delivery. An in-process host can supply a
configured `mailer` object with asynchronous `send(Message)` at the same port.
No delivery implementation fabricates session, UV or signing success.

The lifespan owns one pgdbm manager/pool and one SDK registry client, runs the
independent module plus shared B2/B3 and console migrations, then checks the
current namespace/H/team evidence, active SQL binding/generation, exact policy
version and live B3 approver subject/scope. Empty or mismatched provisioning
refuses startup. Each operation still performs its own fresh authority checks.
Resources close on startup failure and shutdown. Existing deployments require
their authorized migration procedure; this entry point is not permission to
apply migrations or move keys in a real deployment.

The disposable fixture must explicitly provision its throwaway namespace,
verified human ID chain, team controller, ordinary member/certificate and
requester through the existing registry APIs. Apply migrations, then provision
the declared authorizer/requester rows from
`migrations/001_independent_authority.sql`, and its designated B3 approver with
the same `subject` and `b3_scope`. No worker-facing writer or automatic missing
binding recovery is mounted. The fixture must enroll its real WebAuthn
credential through B3's `reissue_enrolment`/`deliver`, `enrolment_options` and
`complete_enrolment` APIs using an actual browser-generated attestation on the
pinned human origin. A trusted fixture helper can perform those B3 calls
against the same database; it must not insert credential/session/assertion
success rows. The complete existing native provisioning example is
`server/tests/test_independent_protected_signer.py:world`. Bootstrap/admission
HTTP routes are a separate slice and are not exposed by this host.

The host constructs one `composition.protected_sessions()` instance for both
`console_login_router` and `operations_http`. On the human app it mounts the
existing `handoff_page_router(store=HandoffStore(db), limiter=...,
protected_operations=mount)`, which serves its own assets, and
`mount.human_router()`. There is one page and no synthetic installation.
The request app mounts only `mount.api_router()`.

The joined journey is CLI prepare, `/handoff/{id}`, fresh real LOGIN, separate
exact-act UV, retained signed receipt, and CLI exact receipt read. The signer
retains the signed owner act and local transactional audit. It does not apply
the act to the remote app. Deployment isolation, final console dependency
review, native/browser evidence, published pins and the covering release gate
remain separate acceptance evidence; the factory does not establish them.
