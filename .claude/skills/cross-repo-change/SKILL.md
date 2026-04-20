---
name: cross-repo-change
description: Coordinate changes that touch both the aweb OSS repo and the aweb-cloud repo. OSS lands first, releases to PyPI, cloud pins and deploys.
---

# Cross-repo change coordination

Changes that affect both aweb (OSS) and aweb-cloud must be
coordinated carefully because the cloud embeds aweb as a PyPI
package.

## Principle

The cloud imports aweb. Both deploy in the same Docker image.
There is no transition period — when the cloud pins a new aweb
version, both the old and new code deploy atomically.

## Sequence

1. **Design** — agree on the contract change between OSS and cloud.
   Identify which side goes first.

2. **OSS first** — land the OSS change on aweb main. Run all tests.

3. **Release** — bump version, tag, push. Wait for PyPI to publish.
   Verify with:
   ```bash
   curl -s https://pypi.org/pypi/aweb/<VERSION>/json | python3 -c "import sys,json; print(json.load(sys.stdin)['info']['version'])"
   ```

4. **Cloud pins** — update `backend/pyproject.toml` to `aweb>=<VERSION>`,
   run `uv lock`, run tests.

5. **Cloud change** — land the cloud-side change in the same commit
   or immediately after the pin bump.

6. **Verify** — cloud tests pass against the real aweb package (not
   editable/sibling source).

## Anti-patterns

- Do NOT land the cloud change before the OSS release. The cloud
  CI will fail on import errors.
- Do NOT use editable/sibling source installs as a permanent
  workaround. They mask version pinning issues.
- Do NOT accept both old and new formats "during transition" when
  both sides deploy atomically. Pick one format.

## Example: aweb-aaje (proxy auth team_id format)

1. OSS: changed X-Team-ID validation from UUID to colon-form,
   deleted _resolve_proxy_team_id (cde8889, 0fbe3d9, 78794ff)
2. Released: aweb 1.10.1
3. Cloud: bob pinned 1.10.1, changed bridge to send colon-form
   (2761d0a5, 1f6e4797)
4. Both deploy together in the cloud Docker image

## Notes

- The aweb-cloud repo is at `../aweb-cloud` relative to the aweb
  workspace.
- Alice and bob own the cloud repo. Dave reviews OSS changes,
  they review cloud changes.
- Henry reviews OSS changes before release.
