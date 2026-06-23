#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/aw-launch-demo-check.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

FAKE_AW="$TMP/fake-aw"
cat >"$FAKE_AW" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "${FAKE_AW_EXPECT_API_KEY:-unset}" in
  absent)
    if [[ -n "${AWEB_API_KEY+x}" ]]; then
      echo "fake-aw: unexpected AWEB_API_KEY in environment" >&2
      exit 97
    fi
    ;;
  present)
    if [[ -z "${AWEB_API_KEY:-}" ]]; then
      echo "fake-aw: expected AWEB_API_KEY in environment" >&2
      exit 98
    fi
    ;;
  *)
    echo "fake-aw: set FAKE_AW_EXPECT_API_KEY to absent or present" >&2
    exit 99
    ;;
esac

case "${1:-}" in
  plugin)
    echo '{"status":"installed"}'
    ;;
  team)
    case "${2:-}" in
      create)
        echo '{"status":"created"}'
        ;;
      add)
        spec="${3:?missing agent spec}"
        agent="${spec%@*}"
        mkdir -p "agents/instances/$agent/.aw/profile"
        printf 'fake profile for %s\n' "$agent" >"agents/instances/$agent/AGENTS.md"
        printf '{}\n' >"agents/instances/$agent/.aw/profile/ref.json"
        echo '{"status":"added"}'
        ;;
      *)
        echo "fake-aw: unexpected team command: $*" >&2
        exit 96
        ;;
    esac
    ;;
  agent)
    case "${2:-}" in
      start)
        echo '{"status":"running","pid":12345}'
        ;;
      status)
        echo '{"status":"running","pid":12345}'
        ;;
      logs|stop)
        ;;
      *)
        echo "fake-aw: unexpected agent command: $*" >&2
        exit 95
        ;;
    esac
    ;;
  *)
    echo "fake-aw: unexpected command: $*" >&2
    exit 94
    ;;
esac
EOF
chmod +x "$FAKE_AW"

# Self-hosted e2e mode must clear any inherited hosted/shared API key before
# invoking aw. This protects disposable-stack validation from accidentally using
# or leaking a live hosted key.
FAKE_AW_EXPECT_API_KEY=absent \
AW_BIN="$FAKE_AW" \
AWEB_API_KEY="inherited-hosted-secret-must-not-reach-fake-aw" \
AW_LAUNCH_SELF_HOSTED=1 \
AWEB_URL="http://127.0.0.1:18000" \
AWID_REGISTRY_URL="http://127.0.0.1:18010" \
AW_LAUNCH_LIBRARY_MANIFEST_URL="http://127.0.0.1:18765/.well-known/aweb-app.json" \
AW_LAUNCH_WORK_ROOT="$TMP/self-hosted-parent" \
"$ROOT/scripts/launch-demo-path.sh" >"$TMP/self-hosted.out" 2>"$TMP/self-hosted.err"

# Hosted mode still requires and passes AWEB_API_KEY through to aw subprocesses.
FAKE_AW_EXPECT_API_KEY=present \
AW_BIN="$FAKE_AW" \
AWEB_API_KEY="hosted-secret-required-for-hosted-mode" \
AW_LAUNCH_LIBRARY_MANIFEST_URL="http://127.0.0.1:18765/.well-known/aweb-app.json" \
AW_LAUNCH_WORK_ROOT="$TMP/hosted-parent" \
"$ROOT/scripts/launch-demo-path.sh" >"$TMP/hosted.out" 2>"$TMP/hosted.err"

# Hosted mode without a key must fail before invoking aw.
set +e
FAKE_AW_EXPECT_API_KEY=present \
AW_BIN="$FAKE_AW" \
AW_LAUNCH_WORK_ROOT="$TMP/hosted-no-key-parent" \
"$ROOT/scripts/launch-demo-path.sh" >/dev/null 2>"$TMP/hosted-no-key.err"
status=$?
set -e
if [[ "$status" -ne 2 ]]; then
  echo "expected hosted no-key guard to exit 2, got $status" >&2
  exit 1
fi

printf 'launch demo path checks passed\n'
