#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_FILE="$ROOT/docs/cli-command-reference.md"
TMP_BIN="$(mktemp "${TMPDIR:-/tmp}/aw-cli-ref.XXXXXX")"
TMP_OUT="$(mktemp "${TMPDIR:-/tmp}/aw-cli-ref-doc.XXXXXX")"
MODE="write"

cleanup() {
  rm -f "$TMP_BIN" "$TMP_OUT"
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)
      MODE="check"
      shift
      ;;
    --output)
      OUT_FILE="$2"
      shift 2
      ;;
    --self-test)
      MODE="self-test"
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

(
  cd "$ROOT/cli/go"
  go build -o "$TMP_BIN" ./cmd/aw
)

python3 "$ROOT/scripts/generate_cli_reference.py" \
  --binary "$TMP_BIN" \
  --output "$TMP_OUT"

check_reference() {
  local candidate="$1"
  if ! diff -u "$candidate" "$TMP_OUT"; then
    echo "cli command reference is out of date; run scripts/regenerate-cli-reference.sh" >&2
    return 1
  fi
  echo "cli command reference is up to date"
}

self_test() {
  if ! check_reference "$OUT_FILE" >/dev/null; then
    echo "SELF-TEST FAIL: the clean committed CLI reference did not pass" >&2
    return 1
  fi
  AW_CLI_REFERENCE_BIN="$TMP_BIN" python3 -m unittest discover \
    -s "$ROOT/scripts" \
    -p "test_generate_cli_reference.py" \
    -v
  echo "self-test passed: clean generation plus visible-addition, removed-command, and stale-output controls"
}

case "$MODE" in
  check)
    check_reference "$OUT_FILE"
    ;;
  self-test)
    self_test
    ;;
  write)
    mv "$TMP_OUT" "$OUT_FILE"
    echo "wrote $OUT_FILE"
    ;;
esac
