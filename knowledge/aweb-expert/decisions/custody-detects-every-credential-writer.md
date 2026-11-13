---
type: Decision
title: Custody detects every credential writer instead of trusting writers to announce
description: A long-running custody service compares, at request admission, a digest of exactly the inputs its client is built from, because aw has dozens of writers of a home's credential inputs; only the supported update path is transactional, unpublished changes fail closed, and that strictness applies only while a reader holds the home.
tags: [decision, aw-cli, custody, identity, concurrency]
timestamp: 2026-11-13
---

Decided on 2026-11-13 for `aw custody serve` picking up credential changes in
place (OATS C-7), after a design NACK from the security reviewer and a second
design round agreed by the OSS aweb reviewer and the security reviewer. The
behaviour itself is in `CHANGELOG.md` and the code; this records why it has
that shape.

# The problem

An identity home's credential inputs (identity, signing key, team
memberships, team certificates, the custody workspace file and the identity
chain) are written by many production paths. The inventory taken for the
design found about 50 writers across about 25 commands: accept, join, ensure
and create, `doctor --fix`, team switch and leave, certificate reissue, key
replace and rotate, hosted creation, `aw run`, heartbeat and role-name
metadata, and a team-state loader that migrates on read. Only a handful are
the supported update path.

# Decision

- **Detect, do not enumerate.** At each request admission custody computes a
  canonical projection (a digest) of exactly the inputs its client is built
  from, resolved the way the loader resolves them, and compares it with the
  published generation. The projection covers every membership, so it does
  not depend on which team is selected. Any writer, announced or not, changes
  the digest.
- **Only the supported path is transactional:** a generation manifest, an
  update marker, an exclusive update lock and exact-operation recovery.
- **One snapshot per request.** Custody serves each request from one
  published snapshot and fails closed on an incomplete update, a home held
  busy past the wait, an unpublished change, or a changed resident identity.
- **Strictness is scoped to a live reader (decision A).** Custody holds a
  shared reader lease for its lifetime. A supported writer that cannot take
  the lease exclusively refuses to publish over an unpublished base. A writer
  in a home no custody serves validates the base and publishes over it, as
  it always did.
- **Status is a bounded admission**, like any other request.
- **App signing uses only the selected team's admitted certificate**, so a
  grant for another team fails closed rather than reaching for the live home.

# Rejected

- **Writer-announced reloads** (each writer signals custody to reload): they
  miss most writers, and every new writer would have to remember to announce.
- **Strict refusal everywhere**, refusing any supported update over an
  unpublished base even with no reader: it broke ordinary CLI flows, such as
  the native child exchange, in homes nothing serves.
- **A decision-time ordering stamp** for admissions: both reviewers rejected
  it; see
  [a served credential snapshot is fenced by every observation](/aweb-expert/lessons/a-served-credential-snapshot-is-fenced-by-every-observation.md).

# How to apply

Any future reload-in-place feature (custody, the channel, a daemon) starts
from detection of the inputs it actually consumes, keeps the transactional
path narrow, and keeps strict refusal scoped to while a reader is live. Write
the writer inventory before proposing the design, and do not start code on
one reviewer's approval while another named reviewer still has the design.

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/credential-writers-are-many.md. Landed on main at c938f7244 (task
aweb-acxy.18); the reader-lease lock order is documented in
`cli/go/awconfig/credential_generation.go` and the user-facing behaviour in
`CHANGELOG.md`. The writer count, the broken child-exchange flow and the
reviewers' rulings are the source's report.
