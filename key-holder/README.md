# Self-hosted key holder

The holder implements [organisation key custody](../docs/human-approval-architecture.md#the-key-holder).
ID issuance, approval-key enrollment and act approval are separate operations.
The approval bytes and checks come from the pinned approval-service library.

Install the locked source environment with `uv sync --frozen --project key-holder`.
The approval library is pinned to a public Git commit; no GitHub credentials
are required. The holder uses the adjacent `../awid` from this same checkout.
The service's standalone development pin does not override that source.

Create a **new** state directory inside a private parent directory:

```sh
uv run --frozen --project key-holder aweb-key-holder --state /private/holder/state init --organisation example.org
```

The result is a public controller descriptor. Namespace and team seeds are
generated inside the holder. Use `descriptor` to read a descriptor and
`create-team-key <name>` to generate a team key. `backup --offline-public-key
<hex>` writes only ciphertext encrypted to the operator's offline X25519 key.
`migrate` explicitly applies ordered holder-store migrations; serving never
applies them. Mount the private state only into the holder, under its own UID.
Keep that state on storage encrypted at rest. It includes the issuer's private
attestation inventory.

Approval is off by default. Start without an approval service:

```sh
aweb-key-holder --state /private/holder/state \
  --registry-origin https://api.awid.ai --origin https://holder.example.org \
  serve --bind 127.0.0.1 --port 8081
```

The first person's certificate is issued by the private operator command
`issue-person --person <did:aw> --identity-key <did:key>` on the holder host.
The person completes `aw id human register FILE` with their keychain key.
There is no enrolment or creation evidence. There is no operator HTTP route.
After that, a current person can use `aw id human add --issuer URL ...` without
an approval key when no requirement is configured. Agents, unrelated keys,
retired people and revoked people are refused on that path.
Local retirement applies only to enrolled people. To stop a never-enrolled
person from adding people, the operator revokes that person's ID at the registry;
`retire-person` has no enrollment row to retire for them.

To require approval, the operator adds the organisation's one section to the
existing deployment.yaml:

```yaml
human_approval:
  service: https://awsign.com
  require:
    organisation.human.add: passkey
```

`deploy/team/teamctl render deployment.yaml` writes the shared
`human-approval.json` snapshot beside the rendered env file. Start the holder
with `--human-approval-config /path/to/human-approval.json`, or set
`HUMAN_APPROVAL_CONFIG_FILE` to that same read-only file. This is a source path,
not a second policy. The source is read again at the locked effect; missing or
invalid configured files refuse, while removing the section and rendering again
writes approval off. Email and unknown actions or levels refuse until supported.
Every applied change is signed into the existing append-only audit.
If the last applied policy required approval, omitting the source path also
refuses startup and effects. Pass the file to keep that policy; to turn approval
off, explicitly render and apply an empty policy instead of omitting the file.

The configuration's service supplies the approval origin and RP ID. The default
enrolment grading is passkey-only; the existing hardware metadata inputs may
select hardware grading. An explicit `--approval-origin` is an equality pin.
A `hardware` requirement refuses startup or effects with passkey-only grading:
start with `--grading hardware --mds-cache DIR` and the existing metadata inputs.
The generic 428 loop and the frozen `human.add` receipt remain unchanged.
The private `issue-person` command cannot bypass a configured requirement;
initial creation with enrolment uses the private first-person `bootstrap` flow.

The former `configure --human-issuance` command is removed, with no alias.
An old approved store refuses startup. Write and render an equivalent
`human_approval` requirement, then run:

```sh
aweb-key-holder --state /private/holder/state \
  --human-approval-config /path/to/human-approval.json migrate
```

This ordered migration preserves the keys, enrollments and signature history.
It cannot turn an old approved store into approval off. An old operator store
can run `migrate` without a requirement. Serving never migrates automatically.

Production operators can instead select `--grading hardware --mds-cache <path>`.
Set `--mds-manifest FILE` to the operator-installed reviewed pin and
`--mds-cache DIR` to its private artifact cache. The shared watcher checks the
file each minute and installs only a fully verified, non-rollback replacement.
It logs the seven-day expiry warning and failed reloads. A bad pin retains the
previous snapshot only until its original expiry. Hardware-attested registration
then refuses with a metadata error; unattested passkeys remain available. The
watcher continues after a bad replacement; the policy remains hardware grading. The initial bundled pin expires on 2026-12-01, or an input CRL's earlier
deadline. Operators install the maintainer-reviewed renewal before that date;
the running holder observes the new file without restarting. The first gate's fixed minimum is
passkey UV. There is no runtime rule-lowering command.

The enrollment and approval interfaces are:

- `bootstrap --person <id> --identity-key <key>` prepares the first fresh
  person's creation-with-enrollment intent. Approved `POST /v1/humans` uses the
  generic 428 request/receipt/presentation path and returns the next person's
  intent. Both name the target person's own current identity key as requester.
- An existing person starts with `POST /v1/enrollments/{person}`, body
  `{"requester":{"kind":"identity","id":"<person>","key":"<current key>"}}`.
  The request must be signed by that person's own current identity key using
  the covering HTTP profile. The holder verifies its current namespace and
  exact committed certificate. Earlier controller epochs remain valid when
  the registry validates them. A foreign person or the organisation controller
  carrying somebody else's enrollment is refused.
- The person carries the signed intent to awsign; their one `aw id human enroll`
  command drives the browser registration and confirmation. After registration,
  signed `POST /v1/enrollments/{person}/binding` takes `material` and the person's
  reported `registration_count`. The holder independently verifies the same raw
  registration before signing B. `/finish` takes the confirmation receipt;
  `/activate` takes `{}` and checks committed current public identity.
- New pending people need no certificate header for their own enrollment calls.
  The holder checks the exact target ID/key against the registry key mapping;
  this admission never applies to an act route. Committed people carry their
  full checked chain. Every request uses the covering identity profile and
  `X-AWEB-DID-AW`; committed chains use `X-AWID-ID-Chain`.
- Creation emits the existing creation statement. Later enrollment emits
  `human_enrolled_later`, with the current binding and confirmation commitment,
  issuer-authenticated grade and issuer-clock `since`. It never changes how the
  ID was created: "can approve since T (issuer's statement), grade G".
  Any activated, currently valid person in the organisation, enrolled at creation
  or later, may approve `human.add` when `organisation.human.add` is configured.


The enforcer never contacts awsign. A signed pending certificate or creation
sidecar alone does not activate a person. Each returned signature has a durable
audit record; creation evidence, its nonce and audit commit together. Caller
admission does not substitute for approval. The holder has no pages, passkeys,
mail routes, arbitrary signing endpoint or registry custody marker.

Enrollment intents and their confirmation requests have a 24-hour window.
The ordinary `human.add` request keeps its 10-minute window. If an enrollment
expires before evidence is committed, a new approved `human.add` can replace
that pending row; an old consumed receipt cannot retrieve the replacement
intent. Old signed intents stay in the append-only audit. Rows with evidence
are never replaced; activation uses current public Trust without reapplying
the completed ceremony's deadline.

Replacing a lost enrolled key is not implemented; today a person who loses their only enrolled key is issued a new ID by the operator and enrols again, and the old ID is revoked. Enrol two keys.

Before starting an existing private volume, apply the ordered schema migrations
as described above, with an explicit policy file for a previously approved holder.

The private `audit --after <sequence> --limit <1..1000>` command pages the
signature record without registry or approval configuration. `retire-person
--person <did:aw>` withdraws a local enrollment without deleting its evidence,
nonces or audit; it cannot be reactivated. This frees a stuck first-person
bootstrap after expiry or an unactivatable evidence-bearing row. For an active
person, revoke the old ID and use `issue-person` for the fresh ID. A target's
`expected_revision` fences only that person's enrollment; an unrelated person
cannot invalidate its outstanding request. Retirement preserves that history.
Authenticated callers receive `enrollment_replacement_unavailable` with the
fresh-ID advice for active or retired people. Mode/configuration and row
existence are disclosed only after the caller's signature and standing checks.

For the one-container runtime, build a complete wheelhouse containing the
reviewed SDK, holder and pinned approval-library wheels and their locked
dependencies, then run:

```sh
docker build -f key-holder/Dockerfile -t aweb-key-holder:local /path/to/wheelhouse
```

The image runs as UID 1001. Its state volume's `state` child is created by
`init`; mount the same private volume for later operator commands and `serve`.
The application receives no state mount. The test component path exercises
real DNS, AWID, PostgreSQL and Redis; its software authenticator is not evidence
of a physical key or completion of the separate Chromium/service journey.
