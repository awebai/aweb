#!/usr/bin/env bash
# Gate boundary for release-prepare: runs the clean-Docker gate (or the one
# compatibility cell) and emits ONLY the JSON evidence contract on stdout -
# {"suites": [...], "reference": "<log path>"}. All run output goes to stderr
# and the retained logs; prepare parses stdout as the evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GATE_SCRIPT="${AWEB_PREPARE_GATE_SCRIPT:-$ROOT/scripts/release-local-gate.sh}"
COMPAT_COMMAND="${AWEB_PREPARE_COMPAT_COMMAND:-}"
SOURCE_SHA="${AWEB_SHA:-$(git -C "$ROOT" rev-parse HEAD)}"

emit_evidence() {
  local reference="$1"; shift
  python3 - "$reference" "$@" <<'PY'
import json, sys
print(json.dumps({"suites": sys.argv[2:], "reference": sys.argv[1]}))
PY
}

if [[ "${1:-}" == "compat-pairing" ]]; then
  shift
  pairing="$*"
  [[ -n "$pairing" ]] || { echo "compat pairing not named" >&2; exit 2; }
  log="/tmp/aweb-release-compat-$SOURCE_SHA.log"
  installed="$(command -v aw)" || { echo "published aw CLI is not installed" >&2; exit 2; }
  aw_version="$("$installed" version 2>/dev/null | head -1)" \
    || { echo "installed aw is not runnable" >&2; exit 2; }
  if [[ -n "$COMPAT_COMMAND" ]]; then
    bash -c "$COMPAT_COMMAND" >"$log" 2>&1 \
      || { echo "compat cell failed; log: $log" >&2; exit 1; }
  else
    make -C "$ROOT" cli-e2e AW_BIN="$installed" >"$log" 2>&1 \
      || { echo "compat cell failed; log: $log" >&2; exit 1; }
  fi
  emit_evidence "$log" "cli-e2e ${pairing} (installed ${aw_version})"
  exit 0
fi

log_dir="/tmp/aweb-release-gate-$SOURCE_SHA"
verdict="$log_dir/wrapper-verdict.log"
# Gate-result adoption (resume path only): a green verdict at the EXACT
# source SHA with its summary present is the same evidence a fresh run would
# produce, so re-executing it is waste. Fail-closed: absent, red, or
# other-SHA evidence runs the gate; the verdict and summary checks below
# apply to adopted evidence exactly as to fresh evidence.
if grep -qs "release gate PASSED at $SOURCE_SHA" "$verdict" && [[ -s "$log_dir/summary.tsv" ]]; then
  echo "adopting prior green gate evidence at $SOURCE_SHA: $log_dir" >&2
else
  RELEASE_SOURCE_SHA="$SOURCE_SHA" "$GATE_SCRIPT" >&2
fi
grep -q "release gate PASSED at $SOURCE_SHA" "$verdict" \
  || { echo "gate verdict does not name a pass at $SOURCE_SHA" >&2; exit 1; }
suites=()
while IFS=$'\t' read -r name _rest; do
  suites+=("$name")
done < "$log_dir/summary.tsv"
[[ "${#suites[@]}" -gt 0 ]] || { echo "gate summary is empty" >&2; exit 1; }
emit_evidence "$log_dir" "${suites[@]}"
