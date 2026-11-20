---
type: Lesson
title: A host driver's stub harness models the host's file ownership
description: A stub harness for a driver that acts on a real deployment run directory must include files and directories the operator cannot read, because the run directory holds service-owned secrets; a preservation check takes an lstat metadata digest of the whole tree, hashes contents only for a screened readable allowlist, never reads secrets, and does not claim content equality from metadata.
tags: [lesson, testing, harness, shared-host, permissions, secrets]
timestamp: 2026-11-13
---

Observed on 2026-11-13. A teardown driver for a held deployment host passed 40
stub-harness cases and a review. Its first real run then failed closed before
it removed anything. The driver's evidence-preservation check hashed the
contents of every file in the previous run's directory. That directory held 36
secrets owned by service uids (for example 1001, 10001 and 70) with modes 0400
and 0600, so the operator account could not read them. In the stub harness
every file was readable by the test user, so no case could show the problem.
The failure cost a full live attempt on the held host.

# The rules

- **Census the host before the first real run.** Before a driver touches a
  real run directory, take a read-only census of it on the host: owner, mode
  and whether the operator can read each entry (lstat, not open).
- **Put unreadable entries in the harness.** Add a mode-000 file and a
  mode-000 directory to the stub tree. Assert that the test process really
  cannot read them. A test run as root bypasses the mode, and the control is
  then vacuous.
- **Preserve by metadata, hash only what is allowed.** A preservation check
  records lstat metadata (type, owner, mode, size, mtime) for the whole tree.
  It hashes contents only for a screened allowlist of files the operator can
  read. It never reads a secret.
- **Refuse an unlistable directory.** A directory the check cannot list is a
  refusal, never a shorter list. A shorter list would quietly drop the entries
  the check exists to protect.
- **Say what metadata proves.** Equal metadata digests do not prove equal
  contents. The report states that limit and does not call it content
  equality.

# Evidence that it worked

The corrected wrapper's harness had 48 cases. Five of them failed against the
earlier wrapper, which shows the new cases can fail
([a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)).
The second live attempt passed, with both digests unchanged before and after.

# Elimination route

The unreadable-entry control and the metadata-digest check belong in the
shared harness for host drivers, so that a new driver gets them by default.
Until a shared harness exists, each driver's review asks for the census and
the unreadable-entry cases.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13;
notes/stub-harness-must-model-the-hosts-permissions.md. The wrapper commit,
its review and the live attempts are source-reported. The harvester did not
find the wrapper on aweb main at ba2edfad3.
