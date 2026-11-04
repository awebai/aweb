# Standing public user paths

`make e2e-user-paths` runs the `user-paths` candidate stage immediately after
`checks`, before `unit`. Its services use an internal Docker network with no
published ports: real PostgreSQL, Redis, AWID, owned TXT DNS and one primary
aweb server. A second reachable server has one connected recipient solely to
distinguish an intentional cross-server refusal from an outage. Identity rows
are never inserted by the fixture. Database initialization only creates the
databases and the pgcrypto extension; the products run their own migrations.

Each lane provisions actors using the public CLI: controller preparation and
real TXT verification, identity creation, team creation/invitation/acceptance,
workspace initialization, delivery-origin publication and encryption-key setup.
The two local actors are distinct identities in the first global actor's team.

| Directed path | Relationship | Mail | Chat |
| --- | --- | --- | --- |
| G1 → G2 | Separate global identities and teams | Plaintext, v2 | Plaintext, v2 |
| G2 → G1 | Reverse global direction | Plaintext, v2 | Plaintext, v2 |
| T1 → T2 | Distinct local identities, same team | Plaintext, v2 | Plaintext, v2 |
| T2 → T1 | Reverse local direction | Plaintext, v2 | Plaintext, v2 |
| T1 → G1 | Local to same-team global recipient | Plaintext, v2 | Plaintext, v2 |
| G1 → T1 | Global to same-team local recipient | Plaintext, v2 | Plaintext, v2 |

Every cell runs with both the CLI built from this checkout and the exact npm
`latest` CLI: 48 flows. Each flow sends an initial message, a reply and a
continuation. Mail uses a subject for the initial send and `aw mail reply
<message-id>` for both subsequent turns. Chat discovers the existing session
normally and continues with `aw chat send --session-id`. The basic matrix uses
an explicit zero wait; a separate control starts a waiting CLI, receives its
message through channel-core and answers concurrently. A separate intentional
new-session control exercises plaintext → v2 → plaintext without changing the
ordinary session-discovery cases.

The receiver is real channel-core, started before any message. It records the
presentation callback, including verified metadata and original body. The
callback remains outstanding while the independent CLI inbox/pending/history
assertions run, and then completes so core performs its ordinary acknowledgement.
This keeps a list/read acknowledgement distinct from actual channel presentation.
Both sides' local literal DIDs and global sender addresses are checked; local
team labels do not become global address claims. Public read responses are
retained with each message's evidence. Every send, reply and continuation result
is bound to the presented message ID and the original conversation/session ID.
Inbox and history message IDs, pending-session IDs and history content modes
are checked independently; signed payload/envelope IDs are also checked when
exposed. Chat pending is a session summary and has no message ID or content mode.

Refusal controls check the actual user-facing diagnostic and no delivery:

- A local sender to a global `contacts_only` recipient without a contact.
  Same-team `team_and_contacts` delivery remains a positive neighbor.
- An address published in real AWID whose identity has not connected residence.
- A local first-contact sender to the real second-server recipient without an
  already stored return route. Both lanes must expose the current acst server's
  `local_sender_route_mismatch` refusal with HTTP 422; actf-only certificate and
  team-server discovery errors are not this server's contract.

Released 1.36.53/1.36.54 diagnose a nonresident target during CLI preflight;
the current client reaches the server's `recipient_identity_not_found` response.
The suite checks each documented release's exact diagnostic rather than
requiring a historical binary to produce a newer error envelope. Transport
errors never count as these refusals.

## Required human coverage

Human coverage is **NOT COVERED: pending aweb-actu**, not skipped or passed.
Per coordinator decision 6a00bc5b, the 48 runnable agent flows and 18 controls
determine the stage's PASS/FAIL. Every invocation prints all human cells and
retains them in the stage result, including infrastructure failures. A reused stage reprints its human coverage
gap from the retained log. The stage summary says **incomplete: human paths not covered**, even when runnable cases
pass. The human cells become required for admission in the same change that
implements the real public surface in aweb-actu:

| Required path | Outcome |
| --- | --- |
| G/T → human by address | Mail, reply and continuation through the real human surface |
| Human → G/T | Mail, reply and continuation through the real human surface |
| Chat reply to an authoritative human | `recipient_human_mail_only` refusal |
| Explicit E2EE to a hosted human, if a hosted human is provisioned | Refusal, no delivery |

Each client lane must exercise the supported human surface. A self-custodial
human's encryption is distinct from hosted managed v2 and its explicit-E2EE
refusal. Public human init requires a real PTY; an agent key, SQL type change,
copied human key or bespoke test signer cannot substitute for the missing
human connect/mail/reply selector. The existing human HTTP tests remain until
the real user paths cover their property.

## Artifacts, evidence and budget

Every candidate entry, including a focused stage selection, resolves npm
`latest` once before its ledger key. This preserves reuse between focused and
full invocations on the same tree, versions and released artifact. The metadata
is content-addressed beside the ledger, outside the run log directory that
setup resets. The gate copies it into mounted evidence, checks its digest, and
the stage verifies that digest again before consuming the exact bytes. Changing
the released artifact changes the key; the stage never resolves the tag again.
The explicit artifact-fetch container selects its **own executing platform**, verifies both
wrapper and platform SHA512 tarballs, packed names/versions, exact platform pin,
source gitHeads and executable version/source stamp. It reads checked regular
archive members without extraction, install scripts or source fallback.
Artifact fetch has network access; messaging services and clients stay internal.

Evidence includes the frozen artifact provenance, named outcomes for every
attempted case in both lanes, required human status, public failure/read records,
source revision and harness bytes, service logs and phase timings. Artifact
failure, absent lane, unexpected case failure, timeout or failed cleanup keeps
the stage red. A failed case does not prevent later cases or the other lane
from running. Evidence excludes actor identity homes and private keys.

The candidate image build prepares the locked server/AWID environment, HEAD
CLI, compiled channel-core and CoreDNS. `user-paths` consumes that image and
the parent gate's already local `postgres:17` and `redis:7`, resolved to exact
local image IDs. It checks the runtime's source-tree label, performs no image
build or dependency installation, and uses `--pull=never`. A missing image or
source binding is an infrastructure failure; it never triggers a pull or retry.
For a standalone invocation, supply this prepared image as
`USER_PATHS_RUNTIME_IMAGE`; the gate passes `CANDIDATE_GATE_IMAGE` itself.

The stage budget is 600 seconds from entry through owned cleanup, including
latest resolution. Timings separate local prerequisites, fetch, setup, each
lane and cleanup; the shared candidate-image build retains its own build log.
Cleanup removes only this run's project, resources and scratch homes, preserving
the prepared images. It verifies absence and surfaces cleanup failures. No
retry or coverage reduction makes a stage pass.

## Reviewed released-client issue budget

Coordinator decision d51223e6 permits these measured released-client failures
while HEAD must pass both cells. Each case still runs; its observed failure
is retained as `KNOWN_ISSUE`, never counted as a passed case:

| Cell | Released versions (inclusive) | Task | Exact expected failure |
| --- | --- | --- | --- |
| released/t1->t2/chat/v2 | 1.36.53–1.36.54 | aweb-actw | First `chat send-and-wait t2 ... --e2ee --wait 0`, exit 1, diagnostic below |
| released/t2->t1/chat/v2 | 1.36.53–1.36.54 | aweb-actw | First `chat send-and-wait t1 ... --e2ee --wait 0`, exit 1, diagnostic below |

The JSON error must contain exactly `code=error` and this message, also emitted
on stderr: "sending message: recipient has no published E2E encryption key; ask
them to upgrade aw/Pi/channel and run `aw id encryption-key setup`, or explicitly
send a server-readable upgrade note with --plaintext". The originating actor,
exact command/flags and that case's body are checked as well. Failure on a later
reply, a different diagnostic, unexpected success, unsupported version or any
undeclared failure is red. The parent stage rechecks the version and failure
receipt. Remove both entries in the change that promotes the fixed aw to npm
latest; a version outside the reviewed range is red until the budget is updated
or removed. These are the two released cells; the four original failures were
these same two directions across HEAD and released lanes.

For an additional author-only version comparison, set
`USER_PATHS_COMPARISON_METADATA` to immutable npm metadata for that exact
version. It uses the same artifact verification and records a separate
comparison; it never replaces the required npm-latest lane.

Two author diagnostic modes retain red/green regression evidence without
replacing any standing case. `USER_PATHS_BASELINE_WHEEL` overlays an exact
previously hash-checked server wheel using an offline install into its own
scratch directory, verifies that the running module comes
from that wheel, and runs the fresh-chat order control. It is a historical
failure measurement, never an expected-failure row in the gate.
`USER_PATHS_CANDIDATE_BIN` with `USER_PATHS_CANDIDATE_SHA` runs the two local
plaintext-then-v2 directions on separate fresh actor sets using that exact
candidate binary and its checked source stamp. Both diagnostic modes refuse
to run under `CANDIDATE_SOURCE_SHA`; neither qualifies the standing matrix.
