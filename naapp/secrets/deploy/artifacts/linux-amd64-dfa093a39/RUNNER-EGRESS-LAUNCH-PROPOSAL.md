# Runner egress readiness: bounded launch-gate proposal (aweb-acwd.19)

Status: proposal for R, Athena and Hestia review. No implementation, artifact
replacement, host change or execution is authorized by this document. It
describes a future Linux deployment change; the reviewed dfa runner payload,
native-install handoff and current synthetic proof are unchanged. The profile
and this gate require qualification before non-synthetic credentials.

## Placement: the installed supervisor

Add the gate to the existing standalone `e2e/runner_supervisor.py` policy and
networked-launch path, rather than adding a sudo wrapper. Keep the installed
entry point, exact no-argument sudo command, private JSON protocol, guardian,
three-second grace period and cleanup unchanged. The wrapper would add another
installed executable and a check before the supervisor's input wait; it would
still need the later check described below.

For the hardened Linux deployment, `register` and `run` require the fixed
marker `/run/aweb-secrets-runner/egress-ready`. There is no marker path, skip
flag or synthetic/real selector in driver input, environment, job/1 or
RunnerConfig. This gate applies to every networked launch of the new hardened
artifact. The existing synthetic-only artifact is not retroactively changed.
Non-Linux deployment policy is outside this Linux profile's qualification.

`doctor` and the existing installed-code verifier remain local diagnostics;
they must not require a network-readiness marker. Preserve the distinction
between the current filesystem `Policy.check()` and a proposed separate
`Policy.require_egress_ready()` called for networked launches.

## Root-owned marker interface

Hestia's existing root-managed profile lifecycle owns publication and removal.
The agent, runner, supervisor and job never create or repair the marker.

- `/run/aweb-secrets-runner` is a root-owned directory, mode 0755,
  beneath root-owned, non-symlink, non-group/other-writable ancestors.
- `egress-ready` is a root-owned regular file, mode 0644, containing only the
  observed runner UID in canonical ASCII decimal plus LF. It contains no
  credential, endpoint list or caller-controlled path.
- Before accepting it, the supervisor opens without following links, checks
  the opened file and ancestors, refuses writable/incorrect owners or types,
  bounds the read, and matches the UID to the deployed policy's runner UID
  and the actual effective UID. Missing, malformed, wrong-UID, linked or
  writable material refuses launch.
- `/run` makes the assertion boot-local. Publishing is an atomic root-side
  replacement only after the profile owner has checked the loaded
  `inet runner_egress` table, its observed UID binding and required forwarder
  configuration. A failed load or check publishes nothing.

This is a readiness assertion by the trusted host operator, not proof of the
kernel table obtained by an unprivileged runner. Its truth is the host
profile's responsibility. A checksum or UID in a file alone cannot establish
that the table is still loaded.

## Last-wait placement and refusal

Current source dfa `supervise()` checks its filesystem policy before reading
the initial JSON line, then forks the guardian. A driver can wait on that
input, so extending only the initial `Policy.check()` is insufficient.

For `register` and `run`, require readiness:

1. after the complete initial JSON has been validated and the fixed command
   selected, before forking or forwarding registration input;
2. again in the child immediately before `execve`, after inherited-descriptor
   setup, so an earlier parent check is not reused across intervening work.

Use existing nonzero/failed-launch reporting and cleanup. Do not claim worker
readiness or release a job credential because the marker existed. There is
no new signing key, network request, daemon, wire field or runner-state
schema. The supervisor-to-guardian/worker path uses pipes and signals, not
loopback TCP; it needs no egress exception.

## Host lifecycle obligations and limits

The profile owner must remove readiness before managed unload, rollback,
reconfiguration or UID rebinding. Load/start failure leaves it absent;
`check-state` also removes it on detected absence or drift instead of merely
ALERTing. A host reboot cannot retain an assertion from the previous boot.
The supported shutdown sequence stops/drains owned runner processes before
removing their network enforcement.

A five-minute monitor alone does not make a stale marker fail closed at
launch. An unmanaged `nft` deletion after publication can leave the assertion
stale until detection; the supervisor cannot observe that deletion through a
plain file. Hestia/R/Athena must check how the supported profile lifecycle
keeps publication truthful, and retain this limit for changes outside it.
Do not claim an atomic marker-to-kernel guarantee or continuous enforcement
for already-running jobs. If the qualified lifecycle leaves a marker while
its table is absent, the requested launch gate is not qualified and
non-synthetic credentials remain stopped.

## Bounded implementation and qualification handback

- Root: supervisor policy/checkpoint change and actual-process regression
  coverage, without changing the sudo command or adding a runtime bypass.
- Hestia/servers: the existing profile's root-only publish/remove hooks,
  observed-account binding, failure paths and supported stop/rollback order.
- Runner owner: consumer FIT for the installed entry point, private stdin,
  guardian reporting and Linux artifact closure before implementation lands.
- R and Athena: exact source/profile delta review. The installed supervisor
  and archive/manifest hashes must be rebuilt and re-reviewed through the
  existing native artifact route; do not overwrite the retained dfa archive
  or reuse its hash for new bytes.

Required real-process cases: a correct marker admits the intended networked
launch; absent, malformed, linked, writable and wrong-UID markers refuse
before worker exec; removal while the parent waits for input is not hidden by
its initial policy check. Demonstrate the detector fails on the ungated
source. Run local diagnostics without a marker as a positive control. The
native lifecycle receipt also proves failed profile load, managed unload and
UID drift remove readiness and refuse the real sudo-line launch, with exact
owned-resource cleanup. No qualification is claimed by this proposal.

Source basis: dfa093a396409e4132cf96127a3c30a48e71f7f8,
`naapp/secrets/e2e/runner_supervisor.py` (`Policy`, `_worker`, `supervise`) and
`supervised_launcher.py`; Hestia's profile proposal rev 1 at ai.aweb
5357e49b34ff5b95f2112c0ab05ce9580cfbbe2e. This root proposal changes neither
that profile nor the retained payload.
