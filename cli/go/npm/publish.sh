#!/usr/bin/env bash
set -euo pipefail

# Get version from git tag (v0.10.0 -> 0.10.0)
VERSION="${GITHUB_REF_NAME#v}"
if [ -z "$VERSION" ]; then
  echo "Error: GITHUB_REF_NAME not set or has no version" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ARTIFACTS_DIR="$REPO_ROOT/artifacts"

echo "Publishing aw v${VERSION} to npm..."

# Map goreleaser platform names to npm package directory names and archive extensions
declare -A PLATFORM_MAP=(
  ["linux_amd64"]="aw-linux-x64:tar.gz:aw:aweb-a2a-gw"
  ["linux_arm64"]="aw-linux-arm64:tar.gz:aw:aweb-a2a-gw"
  ["darwin_amd64"]="aw-darwin-x64:tar.gz:aw:aweb-a2a-gw"
  ["darwin_arm64"]="aw-darwin-arm64:tar.gz:aw:aweb-a2a-gw"
  ["windows_amd64"]="aw-windows-x64:zip:aw.exe:aweb-a2a-gw.exe"
  ["windows_arm64"]="aw-windows-arm64:zip:aw.exe:aweb-a2a-gw.exe"
)

# Step 1: Extract binaries and place them in the right directories
for goreleaser_platform in "${!PLATFORM_MAP[@]}"; do
  IFS=':' read -r npm_dir ext aw_binary gw_binary <<< "${PLATFORM_MAP[$goreleaser_platform]}"

  archive="$ARTIFACTS_DIR/${goreleaser_platform}.${ext}"
  target_dir="$SCRIPT_DIR/$npm_dir/bin"
  mkdir -p "$target_dir"

  echo "  Extracting $goreleaser_platform -> $npm_dir/bin/$aw_binary and $gw_binary"

  tmp_dir=$(mktemp -d)
  if [ "$ext" = "tar.gz" ]; then
    tar -xzf "$archive" -C "$tmp_dir"
  else
    unzip -q "$archive" -d "$tmp_dir"
  fi

  cp "$tmp_dir/$aw_binary" "$target_dir/$aw_binary"
  cp "$tmp_dir/$gw_binary" "$target_dir/$gw_binary"
  chmod +x "$target_dir/$aw_binary" "$target_dir/$gw_binary"
  rm -rf "$tmp_dir"
done

# Step 2: Update version in all package.json files
echo "  Setting version to $VERSION in all packages..."
for pkg_dir in aw aw-linux-x64 aw-linux-arm64 aw-darwin-x64 aw-darwin-arm64 aw-windows-x64 aw-windows-arm64; do
  pkg_json="$SCRIPT_DIR/$pkg_dir/package.json"
  sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$VERSION\"/" "$pkg_json"
done

# Also update optionalDependencies versions in main package
main_pkg="$SCRIPT_DIR/aw/package.json"
sed -i "s/\"@awebai\/aw-\([^\"]*\)\": \"[^\"]*\"/\"@awebai\/aw-\1\": \"$VERSION\"/" "$main_pkg"

# Step 3: Publish platform packages first (so they exist when main package is installed)
for pkg_dir in aw-linux-x64 aw-linux-arm64 aw-darwin-x64 aw-darwin-arm64 aw-windows-x64 aw-windows-arm64; do
  echo "  Publishing @awebai/$pkg_dir@$VERSION..."
  cd "$SCRIPT_DIR/$pkg_dir"
  npm publish --access public
  cd "$REPO_ROOT"
done

# Step 4: Publish the main wrapper package last
echo "  Publishing @awebai/aw@$VERSION..."
cd "$SCRIPT_DIR/aw"
npm publish --access public
cd "$REPO_ROOT"

echo "Done! All packages published at version $VERSION."
