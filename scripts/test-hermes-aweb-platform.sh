#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source_dir=${HERMES_AGENT_SOURCE:?use make hermes-test-sync or make test-hermes-aweb-platform}
hermes_commit=3b421578588243f920886e6fe79a6faa87ea026e

verify_source() {
    local revision status
    revision=$(git -C "$1" rev-parse --verify HEAD)
    status=$(git -C "$1" status --porcelain --untracked-files=all)
    if [[ "$revision" != "$hermes_commit" || -n "$status" ]]; then
        printf 'Hermes source at %s must be clean and at %s\n' "$1" "$hermes_commit" >&2
        return 1
    fi
}

if [[ "${1:-}" == --prepare ]]; then
    if [[ ! -e "$source_dir" ]]; then
        source_parent=$(dirname "$source_dir")
        mkdir -p "$source_parent"
        checkout=$(mktemp -d "$source_parent/.fetch.XXXXXXXX")
        trap 'rm -rf "$checkout"' EXIT
        git init -q "$checkout"
        git -C "$checkout" fetch --depth=1 --no-tags \
            https://github.com/NousResearch/hermes-agent.git "$hermes_commit"
        git -C "$checkout" checkout --detach FETCH_HEAD
        verify_source "$checkout"
        mv "$checkout" "$source_dir"
    fi
    verify_source "$source_dir"
    exec uv sync --frozen --python 3.14 --project "$source_dir"
fi

verify_source "$source_dir"
printf 'Hermes test source %s\n' "$hermes_commit"
scratch=$(mktemp -d "${TMPDIR:-/tmp}/aweb-hermes-tests.XXXXXXXX")
trap 'rm -rf "$scratch"' EXIT
export HERMES_HOME="$scratch/home"
tests=packages/hermes-aweb-platform/tests

# Isolate module-level Hermes registry and transport fixtures from each other.
status=0
for test_file in "$tests"/test_*.py; do
    pattern=${test_file##*/}
    case "$pattern" in
        test_live_chat.py|test_live_delivery.py)
            printf '%s requires the disposable live stack documented in the plugin README\n' "$pattern"
            ;;
        test_fixture_registry.py)
            uv run --offline --frozen --no-sync --project server python -m unittest discover \
                -s "$tests" -p "$pattern" -v || status=1
            ;;
        *)
            "$source_dir/.venv/bin/python" -m unittest discover \
                -s "$tests" -p "$pattern" -v || status=1
            ;;
    esac
done
exit "$status"
