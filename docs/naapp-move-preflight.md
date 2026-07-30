# naapp move preflight record

Epic aweb-aauv moves `library`, `folio` and `aweb-naapp` into aweb. This records
the state that the move gives up or changes, so those become visible decisions
rather than things discovered afterwards.

Measured 2026-07-29 by frank, read-only, against the GitHub and Render APIs and
the repositories at `origin/main`. Nothing here was copied from an earlier audit;
every value was read at the time of writing. Two checks in `scripts/` demonstrate
the file-level and image-level properties:

- `scripts/check-naapp-move-addable.sh` — every tracked file arrives intact
- `scripts/check-naapp-move-images.sh` — both production images build

Paths belonging to a mover are given as they are in its own repository today, not
at its destination in aweb, because nothing has moved yet.

## 1. Branch protection, before and after

Read from `repos/{repo}/branches/main/protection` and `repos/{repo}/rulesets`.

| repo | `main` protected | required check | force pushes | deletions | admins enforced |
|---|---|---|---|---|---|
| `awebai/library` | **yes** | `Lint, test, and real-stack e2e`, strict | blocked | blocked | yes |
| `awebai/folio` | no | — | allowed | allowed | — |
| `awebai/aweb-naapp` | no | — | allowed | allowed | — |
| `awebai/aweb` | no | — | allowed | allowed | — |

Repository-level rulesets are empty (`[]`) for all four, so classic branch
protection is the only mechanism in play at repository level.

`library` main is protected with `strict: true`, meaning the branch must be up to
date with base before merging, and `enforce_admins: true`, so the owner is not
exempt. There is no `required_pull_request_reviews` block: the gate is the status
check and the force-push/deletion ban, not a review requirement.

**What the move gives up.** library's code moves to `awebai/aweb`, whose `main`
is unprotected and — per rulings recorded twice — cannot be protected, because it
is the shared sync branch many agents merge to. So after the move:

- nothing blocks a merge to main on a failing check
- nothing prevents a force push to main, or its deletion
- `folio` and `aweb-naapp` lose nothing, because they have no protection today

**What detection remains.** library's required check is the `quality` job of
`Library CI` (`library/.github/workflows/ci.yml`), triggered on `pull_request` and
on `push` to main. If that workflow moves into `aweb/.github/workflows/`, it still
*runs* and still reports; it simply cannot *block*. Detection survives the move;
enforcement does not. Whether anything replaces the enforcement is a separate
decision and deliberately not part of aweb-aauv.1.

`folio` has no `.github` directory at all — no CI workflow, and therefore no
check to lose and none to inherit.

### One thing I could not establish

`orgs/awebai/rulesets` returns HTTP 404 together with a message that the call
needs the `admin:org` scope, which this token does not have. A 404 there means
either "no organization rulesets" or "cannot see organization rulesets", and
those are not distinguishable from the response. So the table above is complete
at repository level and unverified at organization level. Anyone relying on
"aweb main has no protection" for a decision that matters should confirm the
organization level with a token that carries `admin:org`.

## 2. folio's rollback target

The epic records that folio has no rollback target anywhere in git or in ops
notes. Confirmed: `folio` has no `ops/` directory, no service id in the
repository, and no deploy workflow. The minimum needed to return folio to its
current state, read from the Render API:

| field | value |
|---|---|
| service id | `srv-d8o229r7uimc73a8vsr0` |
| service name | `folio` |
| region | `virginia` |
| deploys from | `https://github.com/awebai/folio`, branch `main`, root dir `''` |
| build | `./Dockerfile`, docker context `.` |
| health check | `/health` |
| origin url | `https://folio-tmd1.onrender.com` |
| public url | `https://folio.aweb.ai` |
| currently live deploy | `dep-d96buv5ckfvc73f8ldl0` |
| live commit | `aaa15cd7dceb…`, which is folio `origin/main` |
| that deploy finished | 2026-07-07T08:58:12Z, trigger `api` |
| suspended | `not_suspended` |

folio production is at its `main` tip. library's is not — see below.

**`folio/render.yaml` is not the authority and does not describe the live
service.** It declares `name: folio-api` and `region: oregon`; the live service
is `folio` in `virginia`. library carries the same template with an explicit
warning at the top that it was inherited from folio and does not describe
production. folio's copy has no such warning, so it reads as authoritative and is
not. Anyone rolling folio back from `render.yaml` would target a service that does
not exist.

## 3. Deploy triggers and autoDeploy, per live service

Read from `services/{id}`. `autoDeployTrigger` is the field that decides whether a
push deploys.

| service | id | autoDeploy | trigger | repo / branch | root dir |
|---|---|---|---|---|---|
| `library` | `srv-d8qm4jvavr4c73dhrmgg` | **no** | `off` | `awebai/library` / `main` | `''` |
| `folio` | `srv-d8o229r7uimc73a8vsr0` | **no** | `off` | `awebai/folio` / `main` | `''` |

Both live services are deployed explicitly, not by pushing. Every deploy in their
recent history has trigger `api` or `rollback`, none `new_commit`. For library
that path is `library/scripts/render_ops.py`, which requires `--apply` and an
exact service-id confirmation; folio has no equivalent script.

This is the value that matters for the cutover: **repointing a Render service can
reset `autoDeploy` to its default, which is on.** Both are currently off. If a
repoint silently turns either on, the shared aweb main branch becomes able to
deploy a live service on every merge — which is precisely what the epic's
sequencing exists to prevent.

library's live deploy is `dep-d9l1ob5bedkc73bmo260` on commit `2662b89087f9…`,
which is an ancestor of library `origin/main` but **7 commits behind it**. So
library production is deliberately not at main tip, consistent with
`autoDeploy: no`. Its two prior deploys, both today, were a `rollback` to
`3376af7ee4a5…` and an `api` deploy back to `2662b89087f9…`.

### The trigger the epic did not anticipate: aweb main already auto-deploys

The epic frames this hazard as triggers keyed to the old repos silently ceasing
to fire. The reverse is also true and is the more dangerous half:

| service | id | autoDeploy | trigger | repo / branch | root dir | build filter |
|---|---|---|---|---|---|---|
| `awid.ai` | `srv-d799jqc50q8c73feu4t0` | **yes** | `commit` | `awebai/aweb` / `main` | `awid/site` | **none** |

`awid.ai` is a static site that already deploys from `awebai/aweb` main on every
commit. Its `buildFilter` is `null`, so there is no path filter: the trigger does
not care that the commit touched `naapp/` rather than `awid/site`. It is the only
Render service pointed at `awebai/aweb`.

So the subtree merge — the epic's stated point of no return — fires a production
deploy of `awid.ai` as a side effect. The epic's requirement that "a bad merge
must not be able to become a bad deploy in the same action" does not hold on aweb
main today, for a service that is not one of the two movers.

This is a finding for the merge task, not something aweb-aauv.1 changes. What it
means concretely: whoever performs the merge should expect an `awid.ai` deploy,
and should know its current live deploy so it can be rolled back independently of
the merge:

**This capture is perishable and a recorded one is worse than none.** `awid.ai` deploys
on every commit to `main` with no path filter, so its live deploy changes whenever
anything lands — including the reversible work of this very programme. The values below
were live when recorded and are not now:

| field | value when recorded | still live? |
|---|---|---|
| deploy | `dep-d9j7rhpoagis738kuhi0` | no |
| commit | `c35409066b0e…` | no — 318 commits have landed on `main` since it |
| finished | 2026-07-26T21:36:23Z, trigger `new_commit` | |

A rollback target for a continuously-deploying service is valid only until the next push.
Rolling back to the deploy above would now restore a tree from before three days of work.

So the capture is a step of the merge procedure, not a prerequisite recorded ahead of it:
read the live deploy id and commit immediately before pushing the merge, and read them
again afterwards to identify the deploy the merge itself triggered. Two reads, both in the
same session as the push. Anything recorded earlier describes a deploy that has already
been replaced.

## 4. Dependency pins, recorded because the move changes what they mean

Both movers reach awid and aweb-naapp by git pin today, and the two do not agree
on awid:

| mover | `awid-service` pin | `aweb-naapp` pin |
|---|---|---|
| `library` | `awebai/aweb` @ `0de73deb…`, subdirectory `awid` | `awebai/aweb-naapp` @ `4dbeb4bc…` |
| `folio` | `awebai/aweb` @ `d0baafa3…`, subdirectory `awid` | `awebai/aweb-naapp` @ `4dbeb4bc…` |

Both resolve awid-service **0.5.12** in their production images. aweb's in-repo
`awid/pyproject.toml` is **0.5.13**. So converting the pins to in-repo path
sources upgrades awid in both live services by a patch release. That is a change
to what production runs, not only a change to the Docker context, and
`scripts/check-naapp-move-images.sh` demonstrates both arrangements building so
the choice can be made on evidence.

`aweb-naapp`'s local checkout is not a safe source for the move: its local `main`
is 2 commits behind the pinned commit, and its checked-out branch is a third ref
again. The pinned commit `4dbeb4bc…` equals `origin/main`.
`origin/naapp-source-link-polish` holds one commit not contained in the pin, which
a merge of the pin drops — probably correct, but a decision rather than an
accident.
