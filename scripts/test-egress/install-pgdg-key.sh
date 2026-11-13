#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
  echo "usage: $0 <armored-key> <output-keyring>" >&2
  exit 2
fi

key=$1
keyring=$2
expected=B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8

# Inspect only this file, without reading a developer's GnuPG configuration.
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
fingerprints=$(gpg --no-options --batch --with-colons --show-keys "$key" |
  awk -F: '$1 == "pub" { primary = 1; next }
           $1 == "sub" { primary = 0 }
           $1 == "fpr" && primary { print $10; primary = 0 }')
if [[ "$fingerprints" != "$expected" ]]; then
  echo "PGDG signing key fingerprint mismatch: expected $expected, got $fingerprints" >&2
  exit 1
fi

gpg --no-options --batch --yes --dearmor --output "$keyring" "$key"
chmod 0644 "$keyring"
