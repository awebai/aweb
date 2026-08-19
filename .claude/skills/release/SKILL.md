---
name: release
description: Test and publish one exact aweb OSS candidate using artifact tags.
---

# Release OSS

`main` is synchronization only. Decide the artifact tags before testing.

1. Run `make release-candidate TAGS='tag-vX.Y.Z ...'` from the final clean
   commit. It runs every local Docker test and E2E and creates the tags only on
   complete success.
2. Push each resulting tag separately with `git push origin refs/tags/<tag>`.
3. Each tag invokes only its thin artifact publisher; hosted publishers never
   rerun product suites.

During a hosted-runner outage, use `make release-publish TAG=<tag>` with the
registry credential documented in `docs/release.md`.
