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

Behind a proxy, set `AWEB_PROTECTED_TRUSTED_CLIENT_HEADER=X-Real-IP` (or the
equivalent operator-controlled header) so the shared limiter distinguishes
clients. The proxy must remove any incoming value and set its own; restrict
direct access to the protected process to that proxy. This header selects
only rate-limit identity, never authentication, request audience or authority.
With no configured header, forwarded values are ignored and identity is the
connection peer. Behind a single proxy this means one shared 30-per-minute
budget per bucket: a CLI polling every two seconds can use that entire budget.
That default is suitable for a single-human host; configure the trusted header
for multiple clients rather than broadly enabling forwarded-header trust.

Required operator settings (paths below are illustrative container paths):

```sh
export AWEB_PROTECTED_PROFILE_FILE=/config/protected-profile.json
export AWEB_PROTECTED_SCOPE_FILE=/config/protected-scope.json
export AWEB_PROTECTED_DATABASE_URL_FILE=/run/secrets/signer/database-url
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

`DATABASE_URL_FILE` reads the whole UTF-8 DSN through the existing shared
secret-file reader (at most 1 KiB, nonwritable by group/others, one optional
final LF), and passes it unchanged to the existing database adapter. The
existing `AWEB_PROTECTED_DATABASE_URL` input remains supported for current
callers; configuring both refuses. The resolved `settings.database_url` remains
a `SecretStr`; file/error handling never prints its contents.

GET `/readyz` is served on the request origin only, with `no-store` and a fixed
boolean: 200 after owned startup/provisioning validation and route mounting;
503 before startup, on failure and during/after shutdown. It does not refresh
registry evidence or sign anything. Probes must send the configured request
Host, even over Pod-IP/loopback HTTP. Override the base server image's
`/live:8000` healthcheck when this entrypoint runs on8080. The bundle descriptor
is `deploy/team/descriptors/signer.md`; the bundle owns its one configuration
schema and controller private-volume materialization.

The controller file is the operator-provisioned 32-byte Ed25519 seed encoded as
64 hex characters, optionally followed by one newline. Its directory belongs
to the protected process euid with mode 0700; the regular file belongs to that
euid with mode 0400 or 0600. All declared worker UIDs must be positive and differ
from the protected process euid. Exclude that directory from worker/CLI mounts,
ACLs, backups and debugger access. The serving process neither generates nor installs a key.
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
Any future dispatch of the B2 notification port must happen after the prepare
transaction commits: its fresh database read needs the committed handoff row.

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

## First operator enrollment

Use the production package's local administrator command, as the protected
process uid and with the **same** file settings/mounts as the host. This is an
explicit administrator action under `docs/human-assurance-contract.md` section
3; there is no bootstrap HTTP endpoint. The existing team controller, ordinary
member/certificate, registered own-human identity and requester must already
exist in the pinned registry. This command creates no human, team or key and
does not claim to implement protected human issuance or agent admission.

1. Independently verify the selected profile's public controller and namespace
   pins, explicit human stable ID/domain, exact HTTPS human origin/RP and
   request origin. Choose the existing requester stable ID and the human's
   enrollment contact through the operator's trusted provisioning procedure.
   A worker, runtime response, email or ancestry lookup cannot choose them.
2. Mount the private controller and ordinary member files as described below.
   Configure the private database and SMTP password **files**, then run:

   ```sh
   python -m aweb.protected_signing.operator bootstrap \
     --requester did:aw:REQUESTER --contact approver@example.org
   ```

   Replace those public placeholders. The command uses the serving host's
   actual custody/member-key exclusion, pinned registry client, migrations and
   same database. It observes the selected human's own verified human kind,
   current team controller and current requester mapping before its transaction.
   It records the first authority/requester binding and calls B3's public
   `designate_first` API. It records that administrator action locally, freezes
   context/origin/key/policy/contact, and delivers B3's link only after commit.
   Its output contains scope/delivery status, never the bearer link or a key.
3. Start the host with the factory command above. Open the email link on its
   pinned human origin. `/enrolment` uses the existing shared browser page and
   real B3 registration requiring user presence and verification. It creates
   no console session and signs no act. Its effect transaction holds the exact
   bootstrap/authority association, rechecks original link and registry evidence
   deadlines after the final wait, and consumes the bootstrap together with the
   credential, link and local audit. LOGIN and approval remain separate gestures.
4. Run `python -m aweb.protected_signing.operator check` to verify the current
   registry/custody/provisioning configuration, then use the normal approval
   link to sign in. `/readyz` is a lifecycle probe, not proof that a credential
   or remote app role is usable.

If delivery fails or an unused link expires, repeat the **identical** local
bootstrap command. It reissues a link for the same still-pending subject and
contact. Any credential history closes this path, including revoked keys.
Different humans, contacts, requesters, policy, key or origin refuse; existing
or ambiguous authority without this bootstrap record is never adopted. Do not
remove rows or reset the database to replace an authorizer or recover access.
Later credential/authorizer/contact changes and recovery require their own
protected operations and recovery floors; this first-enrollment path cannot
perform them. Unsupported operations refuse. No automatic agent admission is
enabled by this command.

A disposable deployment runs this **same package command** against its declared
throwaway authorities and private captured SMTP transport. It must not seed
credential/session/assertion rows or replace this host with a test-only signer.

## Controller key installation, backup and cutover

The input is the **existing** registered team's controller seed, normally held
by its authorized owner in aw's `ED25519 PRIVATE KEY` PEM format. The aw state
path is `~/.awid/team-keys/<domain>/<team>.key` (legacy installations may retain
`~/.config/aw/team-keys/...`). Obtain the actual path from that owner's configuration;
never copy an ordinary member key or generate a replacement seed merely because
a path is missing. Team creation and controller authority remain the existing
registry procedure; installing this host is not permission to create a team.
The controller public key must already equal the independently checked profile
and current registry team key.

Transfer the PEM through the operator's private provisioning channel to a
short-lived read-only source file accessible only to the protected uid. Never
put the seed in a shell argument, environment variable, terminal output, image
layer, source repository, worker mount or shared backup. Create the destination
private volume directory as its owner, then convert it using the package:

```sh
# Trusted host/init provisioning; replace the source path with a private mount.
install -d -m 0700 -o 1001 -g 1001 /run/secrets/signer/private-controller
# Run as uid 1001 with the same profile/scope/settings as the protected host:
python -m aweb.protected_signing.operator install-controller \
  --source-pem /private-provisioning/team-controller.pem
```

The command validates the existing PEM with AWID's shared loader and compares
its public key to the selected profile. It writes one **new** regular
`CONTROLLER_KEY_FILE` (32-byte seed as 64 hex characters plus LF), exclusively,
mode 0400, under a real 0700 directory owned by the invoking uid. It refuses
existing paths, symlinks, unsafe directory ownership/mode and a mismatched key;
it never overwrites, registers or rotates authority. The serving host also
checks the registry's current key. Remove the short-lived input after successful
checks. This command neither installs ordinary member certificates nor gives
workers access to the controller. Kubernetes projected Secret symlinks/root
ownership cannot be used as the custody file: materialize into the private
volume with a trusted init step; retain the existing custody checks.

The owner's separately protected **offline copy is the controller backup**.
Keep it encrypted under the owner's recovery procedure with access independent
of workers and the online host. The instruction to exclude the live private
volume from generic backups is not an instruction to discard that offline
copy. Back up the private signer database separately through an operator-only
channel: bootstrap consumption, credential/public-key records, bindings and
receipts must survive a restore. Treat the database as sensitive; do not restore
an old pending bootstrap over a completed enrollment. Losing all working human
credentials is recovery, not permission to rerun bootstrap.

This revoke-only binary does not implement protected controller rotation or
recovery. Do not use an unattended raw-key command to bypass that missing floor
act. An authorized controller cutover must preserve the existing authorizer and
credential history, replace the private custody file and public profile pin as
one controlled maintenance change, and reissue ordinary member certificates
against the new team key using the existing registry procedure. Until those
inputs agree, startup/operations correctly refuse `authority_changed`; no old
key, DNS or status-response fallback is accepted. Preserve receipts and do not
delete the bootstrap record. A namespace-controller rotation likewise requires
an independently authorized update of the profile's namespace pin before reads
resume. The host never learns replacement pins from a worker or status response.

The host constructs one `composition.protected_sessions()` instance for both
`console_login_router` and `operations_http`. On the human app it mounts the
existing `handoff_page_router(store=HandoffStore(db), limiter=...,
protected_operations=mount)`, which serves its own assets, and
`mount.human_router()`. There is one page and no synthetic installation.
The request app mounts only `mount.api_router()` and the lifecycle probe.
The human app additionally mounts the shared first-enrollment page/POSTs; it
does not expose a local administrator/bootstrap command over HTTP.

The joined journey is CLI prepare, `/handoff/{id}`, fresh real LOGIN, separate
exact-act UV, retained signed receipt, and CLI exact receipt read. The signer
retains the signed owner act and local transactional audit. It does not apply
the act to the remote app. Deployment isolation, final console dependency
review, native/browser evidence, published pins and the covering release gate
remain separate acceptance evidence; the factory does not establish them.

### Initial bounded admission policy

After the selected team-controller binding and its authorizer are provisioned,
run as the protected service uid with its existing file settings:

```sh
python -m aweb.protected_signing.operator policy-init --file /run/secrets/signer/admission-policy.json
```

This is an explicit local operator action. The file contains the public policy
without `digest`: positive `version`, sorted distinct `teams`,
`root_selector: {"kind":"service_endorsed_root","service_id":"<configured service>"}`,
nonempty sorted `subject_kinds` from `local_agent` and `registered_agent`, literal
`member_role: "member"`, and positive finite integer bounds `max_active`,
`rate_window_seconds`, `max_per_window`. All bounds live inside `bounds`.
Without a key manifest the selected single-controller host requires `teams` to
contain exactly its own team. With `AWEB_PROTECTED_CONTROLLER_KEYS_FILE`, each
listed controller must have its own loaded matching private custody and current
registry/authorizer checks. A namespace pin or another profile reference is not
another team's controller custody. No wildcard, admin role or implicit bound is
accepted.

The service computes `sha256:` plus the lowercase SHA-256 of
`aweb.admission-policy/1` followed by LF and the canonical unsigned policy.
Repeating the exact initial policy returns it without another write. Changing
it, including its version or any bound, refuses `policy_changed`; this command
cannot substitute for the separately approved policy-change operation.

`GET /protected-admission-policies?team_id=<team>` is configuration only. It
requires the current registered key of a requester explicitly admitted for the
selected protected binding. It uses covering-v2 label
`protected_admission_policy_read`, the team's namespace domain, and the exact
scope `{service_id,team_id}`. It returns only `service_id`, `team_id`, `mode`, and
`policy`; the policy includes its immutable version and digest. A known bound
team without a policy returns `policy:null`. Unknown authority, a missing
requester grant, stale proof or unavailable registry evidence refuses; none is
reported as an absent policy. Reading or preparing never creates a policy.

The shared executor connects these policies to `identity.root.endorse/default`
and `team.agent.admit/default`. A root endorsement needs the root's current key
proof and a separate live authorizer LOGIN/UV, freezing the existing policy and
ID-certificate fields. Its committed signature is distinct from registration:
`aw` registers with the root's own subject proof and verifies registry read-back.
Only this service's retained endorsement, now current in the pinned registry,
authorizes bounded admission. An ordinary human-parent issuance is insufficient.
Admission accepts the caller's exact policy version/digest and agent fields;
no browser or synthetic human decision is used for its default variant.

Admission counters are keyed by service, team and stable root ID. Changing the
root key cannot reset them. Reserved uncertain registrations count toward the
bounds. One signature and quota reservation are retained before a single
registry mutation attempt. The result becomes committed only after fresh
registration fields match the frozen certificate ID/member/key/alias/scope.
An ambiguous send is reconciled by reads of that same registration; it never
creates another signature, certificate ID or quota use. An unresolved signed
registration at expiry remains `unknown/external_effect_unresolved`, rather
than claiming it never applied. Operator recovery and membership-removal
operations remain separate from the read/configuration command.

### Multiple explicit private authorities on one host

For root endorsement and team admission on the same request/human origins,
provision the public profile's human-identity and team-controller bindings.
`AWEB_PROTECTED_CONTROLLER_KEYS_FILE` optionally names a JSON object mapping
EACH profile `authority_key_did` to its absolute private seed-file path. It
contains references, not private values. The selected binding's entry must
exactly equal `AWEB_PROTECTED_CONTROLLER_KEY_FILE`; omitted, extra or wrong
keys refuse. Every referenced seed still passes the existing real-file uid,
mode and symlink checks, matches the public pin, and is excluded from ordinary
member keys. Projected Secret symlinks do not replace private-volume custody.

Use the existing `operator install-controller --source-pem` for each selected
scope/key slot, and `operator bootstrap --requester --contact` for each binding
before serving the group. The one existing enrollment page and B3 completion
fence resolve each mailed link's exact stored scope; they cannot select another
authorizer. LOGIN and per-act UV use the same exact context resolution. The
host mounts one shared operations HTTP surface, dispatching only exact trusted
contexts to instances of the same shared executor. No additional signing or
WebAuthn engine, wildcard key selector or worker key import/export is added.

### Bind a later, replacement or second-deployment root

After the human-identity and named controller bindings have completed first
enrollment, run as the signer's local service uid with its normal settings:

```sh
python -m aweb.protected_signing.operator bind-root \
  --human did:aw:H --root did:aw:NEW_ROOT --team engineering:example.org
```

Repeat `--team` for every intended team. The existing key manifest must load
the actual H custody and each named controller under that same H/domain and
service. Every named team must already be in the provisioned policy. The root
must already be registered and eligible: a local `did:key`, a human, a revoked
identity or an enrolled agent under another H refuses. Nothing creates an ID,
imports a worker key, widens the policy or chooses another H on a miss.

This command adds an active requester grant in H's endorsement binding and a
separate grant in each named controller binding. One row does not cover both
B3 scopes. The bootstrap records must already be consumed and their current
authorizers must retain usable credentials. Actual custody, registry authority,
association generation, policy and current B3 checks bind the same transaction
as the grants and audit, under the original evidence deadline. Pending bootstrap
or an unavailable authority cannot grant a requester. This is an OS-authorized
operator action, never a worker HTTP endpoint or a synthetic human approval.

The new root then runs `aw id endorse` with its own key and caller-persisted
operation UUID. H approves that root's exact endorsement with the existing
passkey path. Only the retained, now-registered service endorsement permits
unattended admission. Binding alone grants no child certificate. A second
deployment of the same H/service follows this same command and its own
endorsement; the first root remains usable. This independent-host path is
covered by `human-assurance-contract.md:201-215`, not deferred to hosted .6.

To replace a root, add `--replace-root did:aw:OLD_ROOT`. The old ID need not
remain available: its grants in precisely these H/controller scopes are
deactivated atomically with the new grants. Other roots/scopes are unchanged.
Exact repeat is idempotent, while an inactive grant is never silently
reactivated. No bootstrap, credential, endorsement, admission history or
quota bucket is deleted. Rotating a root's key retains its stable-ID grant
and bucket; replacing its ID is a distinct, explicit operator choice.

The command returns the public service/H/root/key/team/scope selection and
replacement ID. It emits no private key or enrollment link. It does not
implement the separate backup/restore anti-rollback or controller-rotation
work tracked under the queued restore/catalog operations.

For an explicitly cut-over team, provision a distinct attestation key in the
same protected OS/custody volume and configure `AWEB_PROTECTED_SERVICE_KEY_FILE`.
It uses the controller key reader's strict ownership/mode/symlink checks. The
host refuses reuse of any configured controller, namespace, human or ordinary
member key for this role. Omitting it preserves legacy composition; it cannot
produce a protected-team service attestation or authorize cutover.

The registry host's local administrator transition is
`awid_service.protected_teams.provision_team_protection` inside a database
transaction, with the expected current generation and explicit approval/cutover
reference. It has no worker HTTP route. Package .8 must establish authorization,
real custody isolation, consumer drains/invalidation, exact historical baseline
and rollback limits before invoking it. Build/install/test authorization never
invokes that transition automatically.


Service-owned owner-act delivery additionally pins consumer origins in
`AWEB_PROTECTED_OWNER_ACT_ORIGINS` (a JSON array of canonical HTTPS origins).
The registry origin already comes from the selected profile. Only host-owned
clients for these configured origins may send a retained effect or read its
fixed confirmation route. No worker-selected URL, redirect or regenerated
authentication is accepted. Consumers must install the shared hooks ordered
migrations and record the reference after their actual effect in its transaction.
Their fixed receipt route must redact the proof header from all proxy/application
logs and traces and return no-store; it exposes no private delivery headers.
