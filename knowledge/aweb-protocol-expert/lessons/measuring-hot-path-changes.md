---
type: Lesson
title: Measuring and testing hot-path changes across repositories
description: OSS e2ee read-trust and listener-restart tests ERROR in setup unless make test-node-deps has run, which hides the sender-membership coverage a messaging change needs, so count them as not run; for a like-for-like before/after under Cloud, put an exported baseline or the OSS tree first on PYTHONPATH and verify module paths by import.
tags: [lesson, testing, measurement, environment, cross-repo]
timestamp: 2026-11-04
---

# Node workspace before messaging tests

`test_e2ee_local_sender_read_trust` and `test_connection_notice_restart` run
`npm run build` for `channel/`. Unless `make test-node-deps` has installed the
Node workspaces, they ERROR in setup. Those are exactly the tests that cover
sender membership, which a messaging change needs. Count them as **not run**,
never as passing, and build the Node workspace before treating a server run as
evidence.

The fix belongs in code: `make test-server` does not depend on
`test-node-deps` (main at 110a49a54). Until it does, this lesson is the only
guard.

# Like-for-like before/after across repositories

Cloud's `make use-aweb-local` runs `uv pip install`, which the operator
forbids. `PYTHONPATH` entries come before the venv's site-packages and its
editable `.pth`, so:

- `PYTHONPATH=<oss>/server/src` runs Cloud's tests and benches against an OSS
  branch;
- `git archive <baseline sha> backend/src`, unpacked in a scratch directory and
  put first on `PYTHONPATH`, gives a baseline under the same, newer bench file.

Before trusting a number, verify with a one-line import that `aweb.__file__`
and `aweb_cloud.__file__` resolve where intended. This is measurement only. Pin
acceptance still needs the published artifact, as aweb-cloud's lesson on pin
review and published artifacts requires.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-04; notes/cross-repo-measurement-without-editable-install.md.
