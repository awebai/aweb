#!/usr/bin/env bash
#
# aw (aweb CLI) installation script
# Usage: curl -fsSL https://raw.githubusercontent.com/awebai/aw/main/install.sh | bash
#
# Security note: For maximum security, download and inspect the script first:
#   curl -fsSL https://raw.githubusercontent.com/awebai/aw/main/install.sh > install.sh
#   less install.sh  # Review the script
#   bash install.sh
#
# IMPORTANT: This script must be EXECUTED, never SOURCED
# WRONG: source install.sh (will exit your shell on errors)
# CORRECT: bash install.sh
# CORRECT: curl -fsSL ... | bash

set -e

REPO="awebai/aw"
RELEASE_BASE_URL="${AW_RELEASE_BASE_URL:-https://github.com/awebai/aw/releases/download}"
REQUESTED_VERSION="${AW_VERSION:-}"

# Track where we installed for PATH warning messages
LAST_INSTALL_PATH=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}==>${NC} $1"
}

log_success() {
    echo -e "${GREEN}==>${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}==>${NC} $1"
}

log_error() {
    echo -e "${RED}Error:${NC} $1" >&2
}

# Detect OS and architecture
detect_platform() {
    local os arch

    case "$(uname -s)" in
        Darwin)
            os="darwin"
            ;;
        Linux)
            os="linux"
            ;;
        FreeBSD)
            os="freebsd"
            ;;
        MINGW*|MSYS*|CYGWIN*)
            os="windows"
            ;;
        *)
            log_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)
            arch="amd64"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        armv7*|armv6*|armhf|arm)
            arch="arm"
            ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac

    echo "${os}_${arch}"
}

# Re-sign binary for macOS to avoid slow Gatekeeper checks
resign_for_macos() {
    local binary_path=$1

    # Only run on macOS
    if [[ "$(uname -s)" != "Darwin" ]]; then
        return 0
    fi

    # Check if codesign is available
    if ! command -v codesign >/dev/null 2>&1; then
        log_error "Cannot sign $binary_path. Install the macOS command line tools and retry the installer."
        return 1
    fi

    log_info "Re-signing binary for macOS..."
    if codesign --force --sign - "$binary_path"; then
        log_success "Binary re-signed for this machine"
    else
        log_error "Cannot sign $binary_path. Install the macOS command line tools and retry the installer."
        return 1
    fi
}

# Get the latest release version
get_latest_version() {
    local response

    log_info "Fetching latest release..."

    local metadata
    metadata=$(mktemp) || return 1
    if ! download_release_file "https://api.github.com/repos/$REPO/releases/latest" "$metadata"; then
        rm -f "$metadata"
        log_error "Could not read the latest release. Set AW_VERSION to a published version and retry the installer."
        return 1
    fi
    response=$(cat "$metadata")
    rm -f "$metadata"

    # Extract version from tag_name field (vX.Y.Z -> X.Y.Z)
    VERSION=$(echo "$response" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/' | head -1)

    if [ -z "$VERSION" ]; then
        log_error "Could not determine latest version"
        exit 1
    fi

    log_info "Latest version: v$VERSION"
}

# Require exactly one well-formed SHA-256 entry for this exact archive name.
verify_checksum() {
    local file="$1" checksums_file="$2" filename expected actual
    filename=$(basename "$file")
    expected=$(awk -v name="$filename" '$2 == name || $2 == "*" name { if (NF != 2) print "invalid"; else print $1 }' "$checksums_file") || return 1
    if [[ ! "$expected" =~ ^[[:xdigit:]]{64}$ ]]; then
        log_error "Cannot verify $filename: missing, duplicate or invalid checksum. Retry the installer when the release includes a valid checksums.txt."
        return 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        log_error "Cannot verify $filename. Install sha256sum or shasum, then retry the installer."
        return 1
    fi
    expected=$(printf '%s' "$expected" | tr 'A-F' 'a-f')
    if [ "$expected" != "$actual" ]; then
        log_error "Digest mismatch for $filename. Retry the installer to download a fresh archive."
        return 1
    fi
    log_success "Checksum verified for $filename"
}

# HTTPS is required for every hop, including redirects.
download_release_file() {
    local url="$1" dest="$2"
    if [[ "$url" != https://* ]]; then
        log_error "Refusing insecure release URL. Retry the installer with an HTTPS release source."
        return 1
    fi
    if command -v curl >/dev/null 2>&1; then
        local status=0 code
        code=$(curl --proto '=https' --proto-redir '=https' --max-redirs 10 --max-time 300 -fsSL -w '%{http_code}' -o "$dest" "$url") || status=$?
        if [ "$code" = 404 ]; then return 44; fi
        return "$status"
    else
        local status=0 response
        response=$(mktemp) || return 1
        wget --https-only --max-redirect=10 --timeout=300 --server-response -q -O "$dest" "$url" 2>"$response" || status=$?
        if awk '$1 ~ /^HTTP\// { code=$2 } END { exit code != 404 }' "$response"; then status=44; fi
        rm -f "$response"
        return "$status"
    fi
}

# BEGIN GENERATED RELEASE VERIFIER
verify_signed_release() {
    if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
        log_error "Cannot verify $1. Install Python 3 and OpenSSL with Ed25519 support, then retry the installer."
        return 1
    fi
    python3 - "$1" "$2" "$3" "$4" <<'PY'
from __future__ import annotations

import argparse
from enum import Enum
import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse
import urllib.request

SCHEMA = "aw-release-manifest-v1"
STATEMENT_SCHEMA = "aw-release-statement-v1"
MAX_STATEMENT_BYTES = 256


class ManifestCommand(Enum):
    CREATE = "create"
    VERIFY = "verify"
    READBACK = "readback"
    STATEMENT = "statement"
    ATTACH = "attach-signature"


HERE = Path(__file__).resolve().parent


def version_key(value):
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-rc\.([1-9]\d*))?", value)
    if not match:
        raise ValueError("invalid release version")
    major, minor, patch, rc = match.groups()
    return int(major), int(minor), int(patch), rc is None, int(rc or 0)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest JSON key")
        result[key] = value
    return result


def parse_statement(statement):
    """Enforce docs/install-integrity.md:28-39, the bounded canonical statement."""
    if len(statement) > MAX_STATEMENT_BYTES:
        raise ValueError("release statement exceeds 256 bytes")
    match = re.fullmatch(
        rb"aw-release-statement-v1\nversion=(v?[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?)\n"
        rb"source_commit=([0-9a-f]{40}(?:[0-9a-f]{24})?)\n"
        rb"manifest_sha256=([0-9a-f]{64})\n",
        statement,
    )
    if not match:
        raise ValueError("invalid canonical release statement")
    return tuple(field.decode("ascii") for field in match.groups())


def create_statement(manifest_bytes):
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
    statement = (
        f"{STATEMENT_SCHEMA}\nversion={manifest['version']}\n"
        f"source_commit={manifest['source_commit']}\n"
        f"manifest_sha256={hashlib.sha256(manifest_bytes).hexdigest()}\n"
    ).encode("ascii")
    parse_statement(statement)
    return statement


def verify_manifest(
    *, manifest_bytes, signature_bytes, keys, requested_version, running_version=""
):
    signature = json.loads(signature_bytes, object_pairs_hook=unique_object)
    if not isinstance(signature, dict):
        raise ValueError("release signature envelope must be an object")
    public = base64.b64decode(keys.get(signature["key_id"], ""), validate=True)
    signed = base64.b64decode(signature["signature"], validate=True)
    statement = base64.b64decode(signature["statement"], validate=True)
    if len(statement) > MAX_STATEMENT_BYTES:
        raise ValueError("release statement exceeds 256 bytes")
    if len(public) != 32 or len(signed) != 64:
        raise ValueError("release signing key is not pinned or signature is malformed")
    # Ed25519 SubjectPublicKeyInfo prefix followed by the pinned public key.
    with tempfile.TemporaryDirectory(prefix="aw-release-verify-") as tmp:
        directory = Path(tmp)
        (directory / "key.der").write_bytes(
            bytes.fromhex("302a300506032b6570032100") + public
        )
        (directory / "statement").write_bytes(statement)
        (directory / "signature").write_bytes(signed)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                str(directory / "key.der"),
                "-rawin",
                "-in",
                str(directory / "statement"),
                "-sigfile",
                str(directory / "signature"),
            ],
            capture_output=True,
        )
        if result.returncode:
            raise ValueError(
                "invalid publisher signature (OpenSSL with Ed25519 support is required)"
            )
    statement_version, statement_commit, statement_digest = parse_statement(statement)
    if hashlib.sha256(manifest_bytes).hexdigest() != statement_digest:
        raise ValueError("release manifest digest does not match signed statement")
    manifest = json.loads(manifest_bytes, object_pairs_hook=unique_object)
    if (
        manifest.get("version") != statement_version
        or manifest.get("source_commit") != statement_commit
    ):
        raise ValueError(
            "release statement version or source commit differs from manifest"
        )
    if manifest.get("schema") != SCHEMA or not re.fullmatch(
        r"[0-9a-f]{40}(?:[0-9a-f]{24})?", manifest.get("source_commit", "")
    ):
        raise ValueError("invalid release manifest schema or source commit")
    version = version_key(manifest["version"])
    if version < version_key(requested_version) or (
        running_version
        and running_version != "dev"
        and version < version_key(running_version)
    ):
        raise ValueError(
            "release manifest is older than requested_version or running version"
        )
    if version != version_key(requested_version):
        raise ValueError(
            "release manifest version does not match requested_version version"
        )
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict) or not artifacts:
        raise ValueError("release manifest must name its artifacts")
    for name, entry in artifacts.items():
        if (
            not name
            or Path(name).name != name
            or any(c in name for c in "\\\r\n")
            or not re.fullmatch(r"[0-9a-fA-F]{64}", entry["sha256"])
            or type(entry["size"]) is not int
            or entry["size"] < 0
        ):
            raise ValueError("invalid artifact entry")
    return manifest


def stream_digest(stream):
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def verify_artifact(file, manifest):
    entry = manifest["artifacts"].get(file.name)
    if entry is None:
        raise ValueError(f"{file.name} is absent from the signed manifest")
    with file.open("rb") as stream:
        digest = stream_digest(stream)
    if file.stat().st_size != entry["size"] or digest != entry["sha256"].lower():
        raise ValueError(f"digest mismatch for {file.name}")


import sys
try:
    keys = json.loads('{}', object_pairs_hook=unique_object)
    artifact, manifest_path, signature_path, requested = sys.argv[1:]
    manifest = verify_manifest(manifest_bytes=Path(manifest_path).read_bytes(), signature_bytes=Path(signature_path).read_bytes(), keys=keys, requested_version=requested)
    verify_artifact(Path(artifact), manifest)
except (OSError, ValueError, KeyError, TypeError) as error:
    print(f"Cannot verify {sys.argv[1]}: {error}. Retry the installer from a current signed release.", file=sys.stderr)
    raise SystemExit(1)
PY
}
# END GENERATED RELEASE VERIFIER

# Returns a list of full paths to 'aw' found in PATH (earlier entries first)
get_aw_paths_in_path() {
    local IFS=':'
    local -a entries
    read -ra entries <<< "$PATH"
    local -a found
    local p
    for p in "${entries[@]}"; do
        [ -z "$p" ] && continue
        if [ -x "$p/aw" ]; then
            # Resolve symlink if possible
            local resolved
            if command -v readlink >/dev/null 2>&1; then
                resolved=$(readlink -f "$p/aw" 2>/dev/null || printf '%s' "$p/aw")
            else
                resolved="$p/aw"
            fi
            # avoid duplicates
            local skip=0
            local existing
            for existing in "${found[@]:-}"; do
                if [ "$existing" = "$resolved" ]; then skip=1; break; fi
            done
            if [ $skip -eq 0 ]; then
                found+=("$resolved")
            fi
        fi
    done
    # print results, one per line
    local item
    for item in "${found[@]:-}"; do
        printf '%s\n' "$item"
    done
}

warn_if_multiple_aw() {
    # Bash 3.2-compatible approach (no mapfile, no process substitution)
    local paths_output
    paths_output=$(get_aw_paths_in_path)
    local -a aw_paths=()
    while IFS= read -r line; do
        [ -n "$line" ] && aw_paths+=("$line")
    done <<< "$paths_output"

    if [ "${#aw_paths[@]}" -le 1 ]; then
        return 0
    fi

    log_warning "Multiple 'aw' executables found on your PATH. An older copy may be executed instead of the one we installed."
    echo "Found the following 'aw' executables (entries earlier in PATH take precedence):"
    local i=1
    local p
    for p in "${aw_paths[@]}"; do
        local ver
        if [ -x "$p" ]; then
            ver=$("$p" version 2>/dev/null || true)
        fi
        if [ -z "$ver" ]; then ver="<unknown version>"; fi
        echo "  $i. $p  -> $ver"
        i=$((i+1))
    done

    if [ -n "$LAST_INSTALL_PATH" ]; then
        echo ""
        echo "We installed to: $LAST_INSTALL_PATH"
        # Compare first PATH entry vs installed path
        local first="${aw_paths[0]}"
        if [ "$first" != "$LAST_INSTALL_PATH" ]; then
            log_warning "The 'aw' executable that appears first in your PATH is different from the one we installed."
            echo "To make the newly installed 'aw' the one you get when running 'aw', either:"
            echo "  - Remove or rename the older $first from your PATH, or"
            echo "  - Reorder your PATH so that $(dirname "$LAST_INSTALL_PATH") appears before $(dirname "$first")"
            echo "After updating PATH, restart your shell and run 'aw version' to confirm."
        else
            echo "The installed 'aw' is first in your PATH."
        fi
    else
        log_warning "We couldn't determine where we installed 'aw' during this run."
    fi
}

# Verify installation
verify_installation() {
    # If multiple 'aw' binaries exist on PATH, warn the user before verification
    warn_if_multiple_aw || true

    if command -v aw >/dev/null 2>&1; then
        log_success "aw is installed and ready!"
        echo ""
        aw version 2>/dev/null || echo "aw (development build)"
        echo ""
        echo "Get started:"
        echo "  aw run claude      # Guided onboarding + coordination runtime"
        echo "  aw --help          # See all commands"
        echo ""
        return 0
    else
        log_error "aw was installed but is not in PATH"
        return 1
    fi
}

# The archive and output paths are explicit so refusal never loses its context.
extract_release_binary() {
    local archive="$1" output="$2" binary="${2##*/}" filename="${1##*/}"
    case "$archive" in
        *.tar.gz)
            if ! tar -xzf "$archive" -O "$binary" > "$output"; then
                log_error "Cannot extract $filename. Retry the installer to download a fresh archive."
                return 1
            fi
            ;;
        *.zip)
            if ! command -v unzip >/dev/null 2>&1; then
                log_error "Cannot extract $filename: unzip is missing. Install unzip and retry the installer."
                return 1
            fi
            if ! unzip -p "$archive" "$binary" > "$output"; then
                log_error "Cannot extract $filename. Retry the installer to download a fresh archive."
                return 1
            fi
            ;;
    esac
}

stage_verified_binary() {
    local candidate="$1" destination="$2" archive_name="$3" staged
    local install_dir="${destination%/*}"
    if ! staged=$(mktemp "$install_dir/.aw-install.XXXXXX"); then
        log_error "Cannot stage $archive_name for $destination. Check destination directory permissions and retry the installer."
        return 1
    fi
    if ! cp "$candidate" "$staged" || ! chmod 755 "$staged" || ! mv -f "$staged" "$destination"; then
        rm -f "$staged"
        log_error "Cannot replace $destination from $archive_name. Check destination directory permissions and retry the installer."
        return 1
    fi
}

# Download and install from GitHub releases
install_from_release() {
    local platform=$1
    local tmp_dir
    tmp_dir=$(mktemp -d)

    # An explicitly selected release never silently becomes latest.
    if [ -n "$REQUESTED_VERSION" ]; then
        VERSION="${REQUESTED_VERSION#v}"
    else
        if ! get_latest_version; then rm -rf "$tmp_dir"; return 1; fi
    fi
    if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[1-9][0-9]*)?$ ]]; then
        log_error "Invalid release version. Set AW_VERSION to a published version and retry the installer."
        rm -rf "$tmp_dir"
        return 1
    fi

    # Construct download URL
    local ext="tar.gz"
    local binary="aw"
    if [[ "$platform" == windows_* ]]; then
        ext="zip"
        binary="aw.exe"
    fi

    local archive_name="aw_${VERSION}_${platform}.${ext}"
    local url="${RELEASE_BASE_URL%/}/v$VERSION/$archive_name"
    local checksums_url="${RELEASE_BASE_URL%/}/v$VERSION/checksums.txt"


    if ! download_release_file "$checksums_url" "$tmp_dir/checksums.txt"; then
        log_error "Cannot verify $archive_name: checksums.txt is unavailable. Retry the installer when the release includes checksums.txt."
        rm -rf "$tmp_dir"
        return 1
    fi
    log_info "Downloading $archive_name..."
    if ! download_release_file "$url" "$tmp_dir/$archive_name"; then
        log_error "Could not download $archive_name. Retry the installer to download a fresh archive."
        rm -rf "$tmp_dir"
        return 1
    fi
    if ! verify_checksum "$tmp_dir/$archive_name" "$tmp_dir/checksums.txt"; then
        rm -rf "$tmp_dir"
        return 1
    fi

    local manifest_status=0
    download_release_file "${RELEASE_BASE_URL%/}/v$VERSION/release-manifest.json" "$tmp_dir/release-manifest.json" || manifest_status=$?
    if [ "$manifest_status" -eq 44 ]; then
        log_warning "release-manifest.json is missing; publisher authentication is unavailable. This install requires the release SHA-256 digest. Retry the installer after signed releases are published for publisher verification."
    elif [ "$manifest_status" -ne 0 ]; then
        log_error "Cannot verify $archive_name: release-manifest.json could not be fetched. Retry the installer to fetch the complete release."
        rm -rf "$tmp_dir"
        return 1
    else
        if ! download_release_file "${RELEASE_BASE_URL%/}/v$VERSION/release-manifest.sig" "$tmp_dir/release-manifest.sig" || ! verify_signed_release "$tmp_dir/$archive_name" "$tmp_dir/release-manifest.json" "$tmp_dir/release-manifest.sig" "$VERSION"; then
            log_error "Cannot verify $archive_name: signed manifest verification failed. Retry the installer from a current signed release."
            rm -rf "$tmp_dir"
            return 1
        fi
    fi
    cd "$tmp_dir"

    log_info "Extracting $archive_name..."
    if ! extract_release_binary "$tmp_dir/$archive_name" "$tmp_dir/$binary"; then
        rm -rf "$tmp_dir"
        return 1
    fi

    # Determine install location
    local install_dir
    if [[ -w /usr/local/bin ]]; then
        install_dir="/usr/local/bin"
    else
        install_dir="$HOME/.local/bin"
        mkdir -p "$install_dir"
    fi

    # Complete the private candidate before the single same-directory rename.
    if ! resign_for_macos "$tmp_dir/$binary"; then
        rm -rf "$tmp_dir"
        return 1
    fi
    if ! stage_verified_binary "$tmp_dir/$binary" "$install_dir/$binary" "$archive_name"; then
        rm -rf "$tmp_dir"
        return 1
    fi

    LAST_INSTALL_PATH="$install_dir/$binary"
    log_success "aw installed to $install_dir/$binary"

    # Check if install_dir is in PATH
    if [[ ":$PATH:" != *":$install_dir:"* ]]; then
        log_warning "$install_dir is not in your PATH"
        echo ""
        echo "Add this to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
        echo "  export PATH=\"\$PATH:$install_dir\""
        echo ""
    fi

    cd - > /dev/null || cd "$HOME"
    rm -rf "$tmp_dir"
    return 0
}

main() {
    echo ""
    echo "⚡ aw (aweb CLI) Installer"
    echo ""

    log_info "Detecting platform..."
    local platform
    platform=$(detect_platform)
    log_info "Platform: $platform"

    # Try downloading from GitHub releases first
    if install_from_release "$platform"; then
        verify_installation
        exit 0
    fi

    log_error "Verified release installation failed. Retry the installer when the release is available with checksums.txt."
    echo "For an explicit source build, choose a reviewed version and run:"
    echo "  go install github.com/$REPO/cmd/aw@<version>"
    exit 1
}

main "$@"
