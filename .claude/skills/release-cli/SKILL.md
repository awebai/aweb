---
name: release-cli
description: Release the aw CLI. Tags aw-vX.Y.Z on aweb, which triggers sync to awebai/aw repo + goreleaser (GitHub Releases) + npm (@awebai/aw).
argument-hint: [version]
---

# Release aw CLI

The CLI release is triggered by pushing an `aw-vX.Y.Z` tag on aweb.
The workflow at `.github/workflows/aw-release.yml` syncs `cli/go/`
to the `awebai/aw` repo and tags it as `vX.Y.Z`, which triggers
goreleaser + npm publish in that repo.

## Flow

1. Determine the version.
   The CLI version matches the server version in `server/pyproject.toml`.
   Usually tagged alongside a server release.

2. Run CLI tests.
   ```bash
   cd cli/go && GOCACHE=/tmp/go-build go test ./cmd/aw ./chat ./awid ./run ./internal/conformance -count=1
   ```

3. Tag.
   ```bash
   git tag aw-v<VERSION>
   ```

4. Push the tag.
   ```bash
   git push origin aw-v<VERSION>
   ```

5. Verify publication.
   ```bash
   # GitHub Releases (goreleaser binaries)
   curl -s https://api.github.com/repos/awebai/aw/releases/tags/v<VERSION> | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('name','NOT FOUND'), d.get('published_at','N/A'))"

   # npm
   curl -s https://registry.npmjs.org/@awebai/aw/latest | python3 -c "import sys,json; d=json.load(sys.stdin); print('npm:', d.get('version','N/A'))"
   ```

## Notes

- The CLI tag is usually created alongside the server tag in the same
  release commit.
- The `aw-release.yml` workflow requires the `AW_REPO_TOKEN` secret.
- Do NOT retag — goreleaser creates GitHub Releases which are immutable.
