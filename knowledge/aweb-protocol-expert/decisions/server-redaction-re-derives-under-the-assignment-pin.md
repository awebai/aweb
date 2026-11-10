---
type: Decision
title: Server redaction re-derives under the assignment pin
description: The secrets runner's server-side known-value redaction reopens each slot at result time under the version or 1Password observation pinned at assignment, checks it against a full-value keyed digest sealed per assignment, and withholds on any failure; a transient in-process context, a keyed-digest matcher, runner-only redaction, replica affinity and a durable decryptable snapshot were rejected. Ruled; under review, not on main.
tags: [decision, secrets, runner, redaction, custody]
timestamp: 2026-11-10
---

**Status (verified 2026-11-10):** ruled in task acxc.13 on 2026-11-10 by the
owner of the secrets design (source-reported). The amendment to runner protocol
§4.3, `secrets.md` §9.6, `secrets-dispatch-interfaces.md` and
`secrets-onepassword-binding.md` is on the review branch
`agents/aweb-protocol-expert-secrets-docs-redaction-rederive` (39bb95132), not
on main. Main's §4.3 still says to keep the context only in transient memory
and never to reopen a secret for output.

# Why the transient context is not enough

A runner result is a fresh signed request. Nothing routes it to the process
that published the assignment. A redaction context held only in that process's
memory is therefore missing for about (N-1)/N of results across N replicas or
worker processes, and for every result in flight at a restart or rollout. The
"lost context withholds output" trade is the normal path in a multi-replica
deployment, not the rare worker-loss case the transient rule was written for.

# Decision

- **At release:** for each credential slot, generate a random key for this
  assignment, seal it through custody under a context naming the installation,
  the dispatch and the slot's secret, and store it with one keyed digest of the
  **whole** released value. Never store a prefix or partial digest. No
  plaintext and no other sealed value is persisted.
- **At result:** reopen each slot under the context pinned at assignment (the
  exact sealed version, or the pinned 1Password observation checked before and
  after the read), never the current version. The reopen is not a use and
  grants no send authority. Each value must match its digest in constant time,
  and the result transaction rechecks that the slot is enabled, active and
  still at the pinned version.
- **Withhold** all returned streams (`release_context_unavailable`) on any
  failure: late report, disposed digest row, unreadable custody or vault,
  changed 1Password observation, digest mismatch or failed recheck.
- **Dispose** of the digest row, and with it the sealed key, in the same
  transaction as every terminal state (final result, `outcome_unknown`,
  reconciliation, sweep) and every destroy, rotate, disable, containment or team
  retirement affecting the secret. Destroy wins by construction: once the row
  is gone, nothing can confirm the value.
- **Minted values** (§9.5 `short_lived` or `mint` slots) cannot be re-derived,
  so their output is withheld; admitting such slots needs a redaction context
  of their own.

What stood against re-derive was §4.3's wording ("never reopen"), not a
security property. The full-value digest makes equivalence checked rather than
assumed. Changing that wording went through a ruling, as
[accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)
requires.

# Rejected alternatives

- **A keyed-digest matcher with no reopen.** Every matched form can be written
  as a keyed PRF over normalized windows, giving identical output with no
  decryptable copy. But interior matching needs one PRF call per position per
  distinct (form, length): about 25 per output byte. A reviewer measured keyed
  BLAKE2s in CPython at about 1.2 µs per call, and a job may return up to
  16 MiB, so one result costs minutes of server CPU. A cheap rolling hash is
  not a PRF. The prefix digests needed for the truncated-tail rule would also
  let a custody-key holder recover a destroyed value until disposal. Check an
  interior-matching cost estimate against the server's implementation language
  before proposing a digest scheme.
- **Runner-only redaction.** The runner's flags and counts are untrusted by
  contract; the server pass is defence in depth.
- **Replica affinity.** Nothing guarantees it, and restarts still lose results.
- **A durable decryptable snapshot of the released values.** It is a second
  decryptable copy, and destroy no longer wins by construction.

# When to revisit

Admitting minted slots requires designing their own redaction context first;
do not relax the withhold for them.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-10; notes/redaction-context-keyed-digest-matcher.md. The cost figure is a reviewer's measurement as relayed by the source and was not reproduced. Verified by the harvester on 2026-11-10: the rules above are in the review branch's §4.3 diff against main at 07b554c1f.
