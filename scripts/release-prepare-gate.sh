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
# Gate-result adoption (resume path only). The verdict line alone is not a
# green run - a killed run can leave a verdict above an incomplete summary -
# so adoption re-applies every red condition: exact-SHA verdict, summary
# present with zero FAILED/NOT RUN rows and exactly the suite map's row
# count, and evidence younger than 24h (base-image tags are mutable; the SHA
# does not pin them). Anything less runs the gate. Inputs not compared are
# named in the skip line so the adoption is honest about its scope.
inputs_match() {
  # Test seam: an explicit override command replaces the comparison.
  if [[ -n "${AWEB_PREPARE_INPUTS_CHECK:-}" ]]; then
    "${AWEB_PREPARE_INPUTS_CHECK}"
    return
  fi
  local rec="$log_dir/inputs.tsv" ref recorded current rec_locks cur_locks
  [[ -f "$rec" ]] || return 1
  ref="$(awk -F'\t' '$1=="base"{print $2; exit}' "$rec")"
  recorded="$(awk -F'\t' '$1=="base"{print $3; exit}' "$rec")"
  [[ -n "$ref" && -n "$recorded" && "$recorded" != "unresolved" ]] || return 1
  docker pull -q "$ref" >/dev/null 2>&1 || return 1
  current="$(docker image inspect "$ref" --format '{{join .RepoDigests ","}}' 2>/dev/null)"
  [[ "$current" == "$recorded" ]] || return 1
  rec_locks="$(awk -F'\t' '$1=="locks"{print $2; exit}' "$rec")"
  cur_locks="$(git -C "$ROOT" ls-files -s -- '*uv.lock' | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.read().encode()).hexdigest())')"
  [[ "$rec_locks" == "$cur_locks" ]]
}

adoptable=0
if grep -qs "release gate PASSED at $SOURCE_SHA" "$verdict" \
   && [[ -s "$log_dir/summary.tsv" ]] \
   && ! grep -qE $'\t(FAILED|NOT RUN)\t' "$log_dir/summary.tsv" \
   && [[ "$(grep -c . "$log_dir/summary.tsv")" -eq "$(grep -vc '^#' "$ROOT/release-gate/suite-map.tsv")" ]] \
   && [[ -n "$(find "$log_dir/summary.tsv" -mtime -1 2>/dev/null)" ]] \
   && inputs_match; then
  adoptable=1
fi
if [[ "$adoptable" -eq 1 ]]; then
  echo "adopting prior green gate evidence at $SOURCE_SHA: $log_dir (age < 24h; inputs compared: base-image digest, lock set; not compared: package-manager fetches inside builds)" >&2
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
