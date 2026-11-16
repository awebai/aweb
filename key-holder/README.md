# Self-hosted key holder

The holder implements [organisation key custody](../docs/human-approval-architecture.md#the-key-holder).
ID issuance, approval-key enrollment and act approval are separate operations.
The approval bytes and checks come from the pinned approval-service library.

Install the locked source environment with `uv sync --frozen --project key-holder`.
The pinned approval library is fetched from its public HTTPS repository; no GitHub credentials are required.

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

The default issuing rule is `operator`. No awsign configuration is required:

```sh
aweb-key-holder --state /private/holder/state \
  --registry-origin https://api.awid.ai --origin https://holder.example.org \
  serve --bind 127.0.0.1 --port 8081
```

The private operator command issues only a person's signed certificate:

```sh
aweb-key-holder --state /private/holder/state \
  --registry-origin https://api.awid.ai --origin https://holder.example.org \
  issue-person --person <did:aw> --identity-key <did:key>
```

The person registers that certificate with their own identity key. There is no
enrollment or creation evidence. Agents cannot invoke this private command.
To require approval for public human issuance, the operator persists the rule:

```sh
aweb-key-holder --state /private/holder/state configure --human-issuance approved
```

Then restart the same state volume with `--approval-origin https://awsign.com
--rp-id awsign.com --grading passkey_only` in addition to the normal runtime
flags. `approved` without this configuration refuses `approval_not_configured`.
`configure --human-issuance operator` restores private issuance. In operator
mode, `POST /v1/humans` explicitly refuses `human_issuance_operator`.
The operator's `issue-person` command remains available in approved mode for
the first person and recovery, and uses the same signature audit.

Production operators can instead select `--grading hardware --mds-cache <path>`.
That loads the shared pinned metadata policy and refuses unavailable input;
it cannot fall back to passkey-only grading. The first gate's fixed minimum is
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
  or later, may approve `human.add` when the issuing setting is `approved`.
- The old private `authorize`/`bind`/`finish` controller workflow is retained for
  outstanding controller-carried intents only. New enrollment does not call
  the operator authorization callback.

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

**Enroll two people before relying on this slice.** Holder-side
replace/recreate is not implemented: losing the sole activated person's keys
requires a private operator-issued fresh person if the identity key is also lost. This slice also
has no local deactivation command. An approver ceases to qualify when current
registry evidence rejects them, within the shared 60-second freshness bound.

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
