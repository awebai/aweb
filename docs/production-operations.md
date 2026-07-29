# Library production operations

Production changes to Library are executed only through the checked-in Make targets in
this repository. Do not substitute dashboard clicks, inline shell, `curl`, or a temporary
script during a release. A production deploy still requires independent review and
explicit human approval.

## Ownership and profile assets

The executable service tooling lives here with the service so it is versioned, tested,
and available to every operator. The deployer's team-private shelf skill records how to
use these targets. That skill is evolved through Library's reviewed
`propose -> approve -> refresh` asset flow; a locally edited materialized skill is not a
source of truth. The public deployer blueprint carries only the portable rule to use a
service's reviewed targets rather than improvising production mutations.

## Pinned production topology

`ops/render-production.json` is the fail-closed topology allowlist. The tooling refuses
to proceed if Render reports a different service ID, name, region, repository, branch,
origin URL, suspension state, or auto-deploy setting.

The Render API key is read from `~/.aweb-render/env`. The file must have mode `0600` and
contain exactly one nonempty `RENDER_API_KEY`. Commands never print the key, headers, or
raw authenticated materialization responses.

### Why `render.yaml` is not the production identity source

The root `render.yaml` entered the repository unchanged with the initial scaffold
(`c621010`), whose commit records that the Render file was copied from Folio and renamed.
It still carries the inherited `library-api` / `oregon` template values; no later commit
made those values a Library production-topology decision. They do not identify the live
service.

Do not use `render.yaml` to select a production target or derive a deploy plan. Production
is `srv-d8qm4jvavr4c73dhrmgg`, named `library`, in `virginia`, with generated origin
`https://library-02jf.onrender.com` and public edge `https://library.aweb.ai`, as pinned in
`ops/render-production.json`. The checked-in operations validate that allowlist against
Render before acting.

Repository history does not establish whether the scaffold template was ever linked to
the live Render service. Until that relationship is verified from sanitized live
metadata, do not apply the template to production, delete it as presumed inert, or claim
that changing it changes the existing service.

### Credential-less topology boundary

A credential-less reader can identify the pinned production target from this repository
and can verify that both the generated origin and public edge serve the Library health
payload. Those public surfaces and headers do not expose the Render region. Render's
[documented automatic runtime metadata](https://render.com/docs/environment-variables#render-defined-environment-variables)
exposes service identity and origin fields, but no service-region field; a second manually
configured region string would be circular.

Region drift is therefore checked at the credentialed operations boundary, by design.
`make prod-status` reads the live Render API and fails closed unless every field in
`ops/render-production.json` matches, including `virginia`. Run that preflight before any
production operation; do not describe the public health response as region attestation.

## Required release record

Before requesting production approval, record all of the following:

- exact full lowercase 40-character candidate SHA, already at `origin/main`;
- exact current live rollback deploy ID and full commit SHA;
- exact expected developer shelf profile version and `sha256:` digest;
- expected rendered behavior for Claude Code and Pi;
- the independent review verdict;
- the human approval that names this service and candidate.

Never deploy a tag, short SHA, local `HEAD`, or an unmerged commit. Never infer the
rollback artifact after starting the deploy.

## Targets

| Target | Effect |
|---|---|
| `make prod-ops-test` | Mocked operations and gate tests; no network mutation. |
| `make prod-status` | Read-only topology and current-live-deploy preflight. |
| `make prod-health-client-proof ...` | Makes exactly two bounded canonical health requests: the known-blocked baseline UA must return 403 and the honest gate UA must return the exact 200 payload; persists both artifacts. |
| `make prod-deploy ... APPLY=1` | Validates topology and rollback pin, fetches and verifies exact `origin/main`, starts a clear-cache deploy, waits for `live`, then waits boundedly for exact origin and public health readiness. |
| `make prod-wait ...` | Restartable read-only wait for one exact deploy ID and commit. |
| `make prod-verify ...` | Requires the exact deploy to be the sole live artifact, checks origin/public health, then runs raw, released-client, and real-harness gates. |
| `make prod-rollback ... APPLY=1` | Pins the exact current live deployment, validates a distinct known-good rollback deploy ID/commit/state, rolls back, waits, re-checks the sole live artifact, and checks both health surfaces. |
| `make prod-recovery ... APPLY=1` | Performs the pinned rollback and its explicitly selected recovery gate. |

Run `make prod-ops-test` before release planning. The mutation targets deliberately
require `APPLY=1` and `CONFIRM_SERVICE_ID=srv-d8qm4jvavr4c73dhrmgg` in addition to the
artifact pins. Deploy, verify, rollback, and health-client proof also require a fresh
absolute `PROD_EVIDENCE_DIR` outside the repository. The directory must not exist; its
parent must be an existing path with no symlink component. The tooling retains no-follow
directory descriptors, detects path replacement, creates the root at exact mode 0700, and
publishes no-replace mode-0600 versioned JSON artifacts. The initial manifest exists before any
mutation. Each artifact records verified source/config identity, exact nonsecret request
semantics, timing, bounded body bytes and their captured-byte digest/completeness, an allowlist
of diagnostic response headers, and bounded omitted header names/count but never omitted
values. A terminal outcome survives HTTP, DNS, TLS, timeout, and no-response failure. The
operator owns retention and cleanup.

Example variable shape (placeholders only):

```text
make prod-deploy \
  APPLY=1 \
  CONFIRM_SERVICE_ID=srv-... \
  PROD_COMMIT=<40-char-candidate> \
  ROLLBACK_DEPLOY_ID=dep-... \
  ROLLBACK_COMMIT=<40-char-rollback> \
  PROD_EVIDENCE_DIR=/absolute/operator-owned/deploy-run
```

After the command returns the new deployment ID, verification is separate and explicit:

```text
make prod-verify \
  PROD_DEPLOY_ID=dep-... \
  PROD_COMMIT=<40-char-candidate> \
  PROD_EVIDENCE_DIR=/absolute/operator-owned/verify-run \
  AW_SOURCE_HOME=/absolute/path/to/certified-agent-home \
  EXPECTED_PROFILE_VERSION=<approved-shelf-version> \
  EXPECTED_PROFILE_DIGEST=sha256:<64-hex-digest>
```

`AW_SOURCE_HOME` must be an established agent home with the correct team certificate.
The gate clones only into a private temporary directory and removes it on exit.

## Verification surfaces

The isolated stack does not prove production routing, Cloudflare policy, deployed identity or shelf state; the preflight does not prove candidate bytes are live; only exact-ID post-deploy verification can close a deployment.

Render metadata and health do not prove the functional release. Verification requires:

1. Render reports the exact candidate deploy ID and commit as the sole `live` deploy.
2. Generated origin `/health` returns the exact Library health payload without redirecting.
3. Public edge `/health` returns the same exact payload without URL drift.
   Render's `live` transition can precede request readiness. The checked-in gate retries
   only explicitly transient connection, timeout, invalid-JSON, and allowlisted HTTP
   failures for at most 90 seconds with five-second backoff. Redirects, authentication
   failures, and wrong health payloads fail immediately; exhaustion fails closed. Every
   retry and success records its attempt count and elapsed seconds in the release log.
   The 90-second initial bound is provisional rather than an observed Library recovery
   time: Render's documented zero-downtime sequence retains the old process for 60
   seconds after switching networking, and this bound covers that documented transition
   window plus a 30-second operator safety margin. Review observed readiness durations
   after real releases and tighten or extend the bound only from evidence.
4. Authenticated public `POST /v1/materialize` succeeds for `claude-code` and `pi`.
5. `managed_set` is positionally identical to `home_files`, with no duplicates,
   noncanonical paths, broken links, or links resolving outside the generated home.
6. The canonical `/opt/homebrew/bin/aw` strict client matches the reviewed 1.34.0
   SHA-256 plus version/commit/build metadata and materializes both runtimes into fresh
   homes; a self-reported version string alone is insufficient.
7. Real Claude Code and Pi harnesses load the generated title and provenance line.

The harness artifact check has a deliberate boundary. It proves the exact reviewed
Claude native executable and the exact Pi entry script, run by the exact reviewed Node
interpreter through absolute paths and an allowlisted minimal environment and `PATH`.
Claude's pinned artifact is separately verified as a native Mach-O executable with no
interpreter lookup layer. These checks prevent
accidental interpreter interception and half-installed operator environments. It does
not claim per-run integrity of Pi's installed dependency tree; that tree is trusted as
part of the reviewed package installation. This gate does not defend a compromised local
machine that can also rewrite the Makefile or gate itself.

Do not send an authenticated materialization request signed for the generated Render
origin. Library validates the signed audience against its canonical public origin, so a
401 at the generated origin is expected and must not be "fixed" by weakening audience
validation.

## Rollback and recovery

A failed functional gate means the release is not verified. Pin both the exact candidate
deployment currently being rolled away and the pre-recorded known-good rollback ID and
commit; do not choose a convenient artifact from the dashboard. The rollback target
must be a previously live artifact (`live` or Render's historical `deactivated` state),
never a failed build with a matching commit.

For the `aweb-aasb` rollout only, `prod-recovery` has the explicit `legacy-aasb`
fingerprint: both raw runtime responses omit (rather than merely empty)
`runtime_kind` and `managed_set`, and released strict materialization rejects both with
the exact runtime-schema error. An unrelated auth, route, network, or process failure
does not certify recovery:

```text
make prod-recovery \
  APPLY=1 \
  CONFIRM_SERVICE_ID=srv-... \
  CURRENT_DEPLOY_ID=dep-... \
  CURRENT_COMMIT=<40-char-current-live> \
  ROLLBACK_DEPLOY_ID=dep-... \
  ROLLBACK_COMMIT=<40-char-rollback> \
  PROD_EVIDENCE_DIR=/absolute/operator-owned/recovery-run \
  AW_SOURCE_HOME=/absolute/path/to/certified-agent-home \
  EXPECTED_PROFILE_VERSION=<approved-shelf-version> \
  EXPECTED_PROFILE_DIGEST=sha256:<64-hex-digest>
```

Do not reuse `legacy-aasb` for a later release. Add and review the later release's exact
recovery fingerprint before its production approval.

## 2026-07-29 live-transition readiness incident

The approved `aweb-aasb` attempt acquired its production lock at `03:46:38Z` and
created candidate deploy `dep-d9knfetaeets739qep20` at
`f3c0846f4f3ac0ba73503f82dbedce7eb5aee13b`. Render reported it `live`, but the
immediate no-redirect public health check raised `HTTPError`, so the reviewed plan
correctly initiated recovery before functional verification. The safe command output
recorded the build, update, and live sequence but not an exact timestamp for each
candidate transition; recovery was already requested by `03:48:20Z`. Recovery created
`dep-d9kng0vqj5pc73dlk52g` at the known-good
`3376af7ee4a571488441794047018af94b06057f`; Render records that rollback as created at
`03:48:20Z` and live at `03:48:43Z`. Its identical immediate public health check also
raised `HTTPError`.

An exact-ID `prod-wait` 15 seconds later confirmed only that the rollback remained
`live`; it does not check health, and the initial operator report was corrected after
code inspection. `prod-gate-recovery` then successfully sent authenticated public
materialization requests for both runtimes and passed the exact legacy fingerprint,
which proves public application traffic recovered without another deploy. The
coordinator independently observed public `/health` return 200 later, but did not time
that observation. Therefore the health-specific recovery interval is unmeasured.

Because the known-good artifact exhibited the same immediate failure and then served
both authenticated application traffic and health without another deploy, the evidence
ruled out a candidate-specific persistent defect. The initial readiness-race explanation
was an unconfirmed hypothesis, not the incident cause. A later controlled comparison
established that Cloudflare on the canonical zone returned browser-signature error 1010 only
for the default `Python-urllib/3.12` User-Agent; the same exact client reached the generated
origin, while multiple honest User-Agents reached the canonical health URL. The four evidenced
canonical probe failures plus the controlled one-variable responses rule out rate limiting and
a Python-client class block. The rejected requests never reached Library. A third deploy
attempt preserved exact HTTP 403 for both candidate and rollback but still discarded the
response artifact. The gate now identifies itself as
`aweb-library-deploy-gate/1.0`, persists bounded sanitized evidence before raising,
and retains the bounded readiness retry only as preventive hardening for a distinct
plausible failure class. The candidates were not verified and must not be reported as
deployed.

Initial-bound basis: Render documents that after updating networking to route traffic to
the new instance it waits 60 seconds before signaling the original instance to stop:
<https://render.com/docs/deploys#zero-downtime-deploys>. Render health checks can take up
to 15 minutes to certify a new instance, but this incident occurred after Render had
already marked each deploy live, so that larger pre-live limit is not used as the
post-live gate bound: <https://render.com/docs/health-checks>.
