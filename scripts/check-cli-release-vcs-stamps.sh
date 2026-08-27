#!/usr/bin/env bash
# Exercise the release build's VCS stamping in a derived awebai/aw repository.
# GoReleaser creates dist/metadata.json before compiling. That generated file must
# not mark release binaries dirty, while an unrelated unignored file still must.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_MOD="$ROOT/cli/go/go.mod"
RELEASE_VERSION="1.34.3"
GO_BINARY="${GO_BINARY:-go}"

fail() {
  printf 'FAIL: %s\n' "$1" >&2
  exit 1
}

export GOTOOLCHAIN=local
expected_go="go$(awk '$1 == "go" { print $2; exit }' "$GO_MOD")"
actual_go="$($GO_BINARY env GOVERSION)"
[[ "$actual_go" == "$expected_go" ]] \
  || fail "CLI release VCS-stamp check requires $expected_go, but the runner is $actual_go"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
repo="$tmp/aw"
mkdir -p "$repo"

# Reproduce the release workflow's derived repository using the current tracked
# cli/go bytes. Keeping builds outside the fixture ensures only the two explicit
# probes below can affect the VCS stamp.
while IFS= read -r -d '' tracked; do
  relative="${tracked#cli/go/}"
  mkdir -p "$repo/$(dirname "$relative")"
  cp -pP "$ROOT/$tracked" "$repo/$relative"
done < <(git -C "$ROOT" ls-files -z -- cli/go)

git -C "$repo" init -q -b main
git -C "$repo" config user.email release-vcs-stamp@example.invalid
git -C "$repo" config user.name release-vcs-stamp
git -C "$repo" add -A
git -C "$repo" commit -qm 'derived release fixture'
git -C "$repo" tag "v$RELEASE_VERSION"
revision="$(git -C "$repo" rev-parse HEAD)"
printf 'ok   release identity: github.com/awebai/aw v%s at %s\n' "$RELEASE_VERSION" "$revision"

mkdir -p "$repo/dist"
printf '{"project_name":"aw","tag":"v%s","version":"%s","commit":"%s","runtime":{"goos":"linux","goarch":"amd64"}}\n' \
  "$RELEASE_VERSION" "$RELEASE_VERSION" "$revision" >"$repo/dist/metadata.json"
ignore_rule="$(git -C "$repo" check-ignore -v dist/metadata.json || true)"
[[ "$ignore_rule" == *":/dist/"$'\t'"dist/metadata.json" ]] \
  || fail 'GoReleaser-owned dist/metadata.json is not ignored by the exact rooted /dist/ rule'
[[ -z "$(git -C "$repo" status --porcelain --untracked-files=all)" ]] \
  || fail 'GoReleaser-owned dist/metadata.json makes the derived repository dirty'

# Root the exception to the one directory GoReleaser owns. A similarly named
# source-tree path remains an input and must not disappear behind the fix.
mkdir -p "$repo/release-source-probe/dist"
printf 'nested unignored input\n' >"$repo/release-source-probe/dist/input"
if git -C "$repo" check-ignore -q release-source-probe/dist/input; then
  fail 'root /dist/ rule also ignores a nested source-tree dist directory'
fi
rm -rf "$repo/release-source-probe"

assert_build_info() {
  local binary="$1" package_path="$2" expected_version="$3" expected_modified="$4"
  local info
  info="$($GO_BINARY version -m "$binary")"
  grep -Fq $'\tpath\t'"$package_path" <<<"$info" \
    || fail "$binary has the wrong package path; expected $package_path"
  grep -Fq $'\tmod\tgithub.com/awebai/aw\t'"$expected_version"$'\t' <<<"$info" \
    || fail "$binary has the wrong module/version; expected github.com/awebai/aw $expected_version"
  grep -Fq $'\tbuild\tvcs.revision='"$revision" <<<"$info" \
    || fail "$binary has the wrong VCS revision; expected $revision"
  grep -Fq $'\tbuild\tvcs.modified='"$expected_modified" <<<"$info" \
    || fail "$binary has vcs.modified other than $expected_modified"
}

build_one() {
  local phase="$1" goos="$2" goarch="$3" name="$4" package="$5"
  local suffix='' output
  [[ "$goos" == windows ]] && suffix='.exe'
  output="$tmp/build/$phase/${goos}_${goarch}/${name}${suffix}"
  mkdir -p "$(dirname "$output")"
  (
    cd "$repo"
    # An interrupted earlier gate can leave a shared module cache only partly
    # extracted. Keep this release proof independent of that mutable state.
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      GOCACHE="$tmp/go-build-cache" \
      GOMODCACHE="$tmp/go-mod-cache" \
      "$GO_BINARY" build -modcacherw -buildvcs=true -o "$output" "$package"
  ) || fail "$phase release build failed for $goos/$goarch $name"
  printf '%s\n' "$output"
}

platforms=(
  'darwin amd64'
  'darwin arm64'
  'linux amd64'
  'linux arm64'
  'windows amd64'
  'windows arm64'
)
builds=(
  'aw ./cmd/aw github.com/awebai/aw/cmd/aw'
  'aweb-a2a-gw ./cmd/aweb-a2a-gw github.com/awebai/aw/cmd/aweb-a2a-gw'
)

clean_count=0
for platform in "${platforms[@]}"; do
  read -r goos goarch <<<"$platform"
  for build in "${builds[@]}"; do
    read -r name package package_path <<<"$build"
    binary="$(build_one clean "$goos" "$goarch" "$name" "$package")"
    assert_build_info "$binary" "$package_path" "v$RELEASE_VERSION" false
    printf 'ok   clean stamp: %s/%s %s\n' "$goos" "$goarch" "$name"
    clean_count=$((clean_count + 1))
  done
done
[[ "$clean_count" -eq 12 ]] || fail "clean release matrix built $clean_count binaries, expected 12"

# The fix must be narrow. A generated release directory is ignored, but a
# different untracked input remains visible to Go and must dirty both products.
printf 'unignored release input\n' >"$repo/release-provenance-probe"
if git -C "$repo" check-ignore -q release-provenance-probe; then
  fail 'unrelated provenance probe is ignored; /dist/ fix is too broad'
fi
grep -Fq '?? release-provenance-probe' < <(git -C "$repo" status --porcelain --untracked-files=all) \
  || fail 'unrelated unignored probe is not visible in derived repository status'

host_goos="$($GO_BINARY env GOOS)"
host_goarch="$($GO_BINARY env GOARCH)"
for build in "${builds[@]}"; do
  read -r name package package_path <<<"$build"
  binary="$(build_one dirty "$host_goos" "$host_goarch" "$name" "$package")"
  assert_build_info "$binary" "$package_path" "v$RELEASE_VERSION+dirty" true
  printf 'ok   unignored change detected: %s\n' "$name"
done

printf 'CLI release VCS stamps clean for all %d binaries; unignored changes dirty both products.\n' "$clean_count"
