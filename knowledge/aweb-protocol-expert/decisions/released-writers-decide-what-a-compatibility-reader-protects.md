---
type: Decision
title: Released writers decide what a compatibility reader protects
description: A reader of stored state is kept when any released writer, importer or supported administrative operation could have produced that state; a column, a reader, a fixture or one installation's zero count settles nothing, and removing the reader does not decide dropping the storage.
tags: [decision, compatibility, release, storage, migrations, testing]
timestamp: 2026-11-23
---

A chat participant departure marker had a column and readers in released
servers, and tests that hand-wrote the marker made those readers look
required. No released product path ever set it. The readers and the
hand-written worlds were removed, the tests kept the real deletion lifecycle,
and the column stayed for a separate migration decision.

# Decision

- **Reachability comes from writers.** Trace every supported producer through
  the published versions: product writes, importers, embedding hosts,
  supported administrative operations and earlier migrations. A column and a
  reader show only that the state was contemplated.
- **Any supported producer keeps the reader.** If one could have written the
  state in any release, compatibility is owed, whatever is stored today.
- **An exhaustive negative audit permits removal** without a production
  measurement. If the audit cannot cover a producer, it does not settle the
  question.
- **Reader and storage are two decisions.** Removing an unreachable reader
  changes no observed behaviour. Dropping the column is a schema migration with
  its own release decision.
- **Preserve the real behaviour.** Replace the synthetic-state tests with tests
  of the lifecycle the product performs.

The result is bounded by the audited inventory. It says nothing about rows
edited directly in a database outside any supported contract.

# Rejected evidence

- **A zero count in production.** One installation at one time does not speak
  for other installations or versions.
- **A fixture that sets the state.** It can manufacture the state under review.
- **Commit ancestry alone.** A writer can be added and removed between
  releases, so its commit can later sit in a release's ancestry without its
  code ever shipping. Read the tree at each published tag, and the separately
  released embedding hosts.

# Relation to the released-client rule

[Released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
governs shapes a published client sends, and still requires measurement before
one is removed. This decision covers stored state with no released producer;
it authorises no narrowing of a released shape. It also applies
[tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md)
to the worlds a test builds.

# Status and evidence

The reader removal is on main (959675383), and the first final server release
with it is server-v1.27.51. Checked 2026-11-23 on the 675 tags in the
repository: the only write of the marker in non-test code is the participant
merge in migration 045, which carries an existing value forward and cannot
originate one. Writers added on the release branch (2314bc341, 2c5b6f011) were
removed (8091ac4d1) before any tag. The embedding-host and importer inventory,
and the review ruling relayed by the coordinator, are source-reported; the
commit message of 959675383 also names the ruling. The storage drop is tracked
in `aweb-adje.32`.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-delivery, 2026-11-23; notes/release-history-can-establish-an-unused-state.md.
