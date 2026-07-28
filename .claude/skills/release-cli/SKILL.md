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

1. Determine and verify the version.
   aw CLI releases have independent semver; never derive the CLI version from
   `server/pyproject.toml`. The Makefile proposes the next patch after the
   latest stable `aw-v*` tag published on `origin`:
   ```bash
   make release-cli-version-check
   ```
   The check fails unless the proposal is strictly greater than the latest
   published CLI tag. Override `CLI_VERSION=X.Y.Z` only for an intentional
   larger bump; the same monotonicity guard still applies.

2. Run CLI tests.
   ```bash
   cd cli/go && GOCACHE=/tmp/go-build go test ./cmd/aw ./chat ./awid ./run ./internal/conformance -count=1
   ```

3. Tag through the guarded helper.
   ```bash
   make release-cli-tag
   ```

4. Push the tag.
   ```bash
   make release-cli-push
   ```

5. Verify publication.
   ```bash
   # GitHub Releases (goreleaser binaries)
   curl -s https://api.github.com/repos/awebai/aw/releases/tags/v<VERSION> | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('name','NOT FOUND'), d.get('published_at','N/A'))"

   # npm
   curl -s https://registry.npmjs.org/@awebai/aw/latest | python3 -c "import sys,json; d=json.load(sys.stdin); print('npm:', d.get('version','N/A'))"
   ```

## Notes

- CLI and server tags may point at the same source commit, but their version
  numbers are independent and must not be forced to match.
- The proposal comes from published `origin` tag history, so a locally created
  but unpushed candidate remains the version selected by the later push step.
- A command-line override does not persist between Make invocations. For an
  intentional minor/major release, pass the same value to both commands (or
  export it): `make release-cli-tag CLI_VERSION=X.Y.Z`, then
  `make release-cli-push CLI_VERSION=X.Y.Z`.
- The `aw-release.yml` workflow requires the `AW_REPO_TOKEN` secret.
- Do NOT retag — goreleaser creates GitHub Releases which are immutable.
