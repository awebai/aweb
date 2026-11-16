# Self-hosted key holder

This is the first-path implementation of [the key holder](../docs/human-approval-architecture.md#the-key-holder).
The approval bytes and checks come from the pinned approval-service library.
The joined service/browser journey is qualified separately under adcl.6.

Install the locked source environment with `uv sync --frozen --project key-holder`.
The pinned approval library is fetched from its public HTTPS repository; no GitHub credentials are required.
Releases remain held; the SDK's current source label is not a release artifact.

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

Start the JSON service (the audience is configured, never taken from Host):

```sh
uv run --frozen --project key-holder aweb-key-holder \
  --state /private/holder/state \
  --registry-origin https://api.awid.ai \
  --origin https://holder.example.org \
  --approval-origin https://awsign.com --rp-id awsign.com \
  --grading passkey_only serve --bind 127.0.0.1 --port 8081
```

Production operators can instead select `--grading hardware --mds-cache <path>`.
That loads the shared pinned metadata policy and refuses unavailable input;
it cannot fall back to passkey-only grading. The first gate's fixed minimum is
passkey UV. There is no runtime rule-lowering command.

The first path uses these interfaces:

1. Operator-only `registry` reads one typed SDK request from stdin, submits it
   to the pinned registry and returns its result. `--team <name>` selects an
   owned team descriptor. Authorization headers remain inside this exchange.
2. Operator-only `bootstrap --person <id> --identity-key <did:key>` prepares the
   first person's signed intent. Live retries retain its original bounds;
   an expired pending intent without evidence can be reissued for that person.
   It cannot bootstrap a second person. The target must be a fresh ID-tree
   enrollment, not an existing ID relabeled with creation evidence.
3. The requester carries the intent to awsign. For controller bootstrap,
   `authorize --person <id> --purpose <enrollment-purpose> --issued-at <unix>`
   reads the exact service body from stdin and returns `{"authorization":…}`.
   This supplies the narrow `approval.Client.Authorize` callback; it accepts
   only this stored bootstrap's closed enrollment operations.
4. Operator `bind --person <id> --registration-count <reported-count>` reads the
   service's material answer from stdin. It verifies the raw registrations and
   returns the binding and frozen confirmation request. `finish --person <id>`
   consumes the assembled creation receipt from stdin and returns the service
   activation body (I, B, C, E and chain). The subject registers its ID using
   its own identity key. Then `activate --person <id>` checks committed public
   identity before admitting this person as an approver.
5. Later callers use `POST /v1/humans` with `person`, `identity_key` and
   `approver`. They authenticate using aw's existing covering identity profile,
   including `X-AWEB-DID-AW` and the current chain in `X-AWID-ID-Chain`. Current
   IDs in this namespace may ask; an already activated, currently valid person
   must approve. A missing enrollment projection is unavailable, never absence.
6. The endpoint returns the shared 428. `aw id request` carries its request to
   awsign and presents the shared presentation body back to the **same**
   endpoint, signed by the **same** identity key. The holder verifies the
   receipt and its own nonce, then atomically records the authorization and
   pending certificate. An idempotent retry returns the retained intent.
7. That requester completes the later enrollment with signed POSTs to
   `/v1/enrollments/{person}/binding` (body: `material`, `registration_count`),
   `/finish` (body: the creation receipt), and `/activate` (body: `{}`). Only
   activation also accepts that exact new person's current key as its carrier.

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
leaves nobody able to approve, and bootstrap remains closed. This slice also
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
