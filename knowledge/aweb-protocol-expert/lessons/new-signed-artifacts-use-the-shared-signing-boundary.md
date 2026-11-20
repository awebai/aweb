---
type: Lesson
title: New signed artifacts use the shared signing boundary, and the guard runs before review
description: New Ed25519 signing or verification in aweb-oss goes through the shared in-process signer (awid.KeySigner) and the shared strict verifier (idStrictVerify) with its own domain prefix, never raw ed25519.Sign/Verify or a new entry in the released-code exception list; run make test-identity-primitives and the coordinator's other cheap targets on the exact head before review, because a reviewed and ACKed branch was landed and reverted for skipping them.
tags: [lesson, identity, ed25519, signing, review, process]
timestamp: 2026-11-13
---

`make test-identity-primitives` refuses raw `ed25519.Sign` and `ed25519.Verify`
(and their Python equivalents) anywhere except the shared verifiers and the
released legacy files named in `docs/identity-tree-coverage.json`. A branch
that adds a new signed artifact with its own raw calls fails it.

# What happened

The local-log key branch signed and verified its log-key record with raw Go
crypto in `cli/go/awid/local_log.go`. It was ACKed by security review and
merged (430ad10b5), then reverted (0ec41850f) because the guard refused it.
Neither the author nor the security reviewer had run the guard: both reviewed
the code path, not the repository's guard. The fix (ba35aa6fd, merged as
c2e32f476) signs with `KeySigner(teamKey)` and verifies with `idStrictVerify`
and was ACKed again.

# How to apply

- **A new signed artifact** signs through the shared in-process signer,
  `awid.KeySigner` (an `IDCertificateSigner`), and verifies through the shared
  strict verifier, `idStrictVerify` in `cli/go/awid/id_certificates.go`. It
  keeps its own domain-separation prefix; only the primitive call is shared.
- **Never add a new file to the exception list** in
  `docs/identity-tree-coverage.json`. That list holds only released code that
  keeps its existing verification contract; adding unreleased code to it
  defeats the guard instead of meeting it.
- **Before handing a branch to review**, run these five targets from the
  repository root on the exact head, and put their pass lines in the handback,
  as the OSS coordinator requires for landing requests:
  `test-identity-primitives`, `test-vector-provenance`,
  `test-sot-source-inventories`, `test-python-locks` and `lint-naapp`. They take
  minutes and need no database. An ACK on the code path is not evidence that
  the repository guards pass.

The guard is already code; this lesson exists because a passing review did not
imply that the guard had run.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-local-log-encryption, 2026-11-13; notes/identity-primitive-guard.md. Verified by the harvester on main: 430ad10b5, 0ec41850f (whose message names the failing guard and file) and c2e32f476, with `KeySigner` and `idStrictVerify` used in `cli/go/awid/local_log.go`; the Makefile targets; and the released-legacy wording of `docs/identity-tree-coverage.json`.
