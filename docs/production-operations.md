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
| `make prod-deploy ... APPLY=1` | Validates topology and rollback pin, fetches and verifies exact `origin/main`, starts a clear-cache deploy, waits for `live`, then waits boundedly for exact origin and public health readiness. |
| `make prod-wait ...` | Restartable read-only wait for one exact deploy ID and commit. |
| `make prod-verify ...` | Requires the exact deploy to be the sole live artifact, checks origin/public health, then runs raw, released-client, and real-harness gates. |
| `make prod-rollback ... APPLY=1` | Pins the exact current live deployment, validates a distinct known-good rollback deploy ID/commit/state, rolls back, waits, re-checks the sole live artifact, and checks both health surfaces. |
| `make prod-recovery ... APPLY=1` | Performs the pinned rollback and its explicitly selected recovery gate. |

Run `make prod-ops-test` before release planning. The mutation targets deliberately
require `APPLY=1` and `CONFIRM_SERVICE_ID=srv-d8qm4jvavr4c73dhrmgg` in addition to the
artifact pins.

Example variable shape (placeholders only):

```text
make prod-deploy \
  APPLY=1 \
  CONFIRM_SERVICE_ID=srv-... \
  PROD_COMMIT=<40-char-candidate> \
  ROLLBACK_DEPLOY_ID=dep-... \
  ROLLBACK_COMMIT=<40-char-rollback>
```

After the command returns the new deployment ID, verification is separate and explicit:

```text
make prod-verify \
  PROD_DEPLOY_ID=dep-... \
  PROD_COMMIT=<40-char-candidate> \
  AW_SOURCE_HOME=/absolute/path/to/certified-agent-home \
  EXPECTED_PROFILE_VERSION=<approved-shelf-version> \
  EXPECTED_PROFILE_DIGEST=sha256:<64-hex-digest>
```

`AW_SOURCE_HOME` must be an established agent home with the correct team certificate.
The gate clones only into a private temporary directory and removes it on exit.

## Verification surfaces

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
rules out a candidate-specific persistent defect and is consistent with a deployment-
transition readiness race. It does not identify Render as the exact failing layer. The
historical command preserved only the exception class `HTTPError`, not its HTTP status,
so it also does not prove that the new transient-status allowlist would have matched that
specific response. Future structured logs preserve exact safe status, attempts, and
elapsed time to establish that match. The candidate was still not verified and must not
be reported as deployed. The durable correction is a bounded, instrumented treatment
for the observed failure class, not removal of health verification, redirect following,
or an unreviewed retry.

Initial-bound basis: Render documents that after updating networking to route traffic to
the new instance it waits 60 seconds before signaling the original instance to stop:
<https://render.com/docs/deploys#zero-downtime-deploys>. Render health checks can take up
to 15 minutes to certify a new instance, but this incident occurred after Render had
already marked each deploy live, so that larger pre-live limit is not used as the
post-live gate bound: <https://render.com/docs/health-checks>.
