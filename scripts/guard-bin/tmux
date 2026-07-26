#!/bin/sh
# PATH-shim guard for tmux. Sits before the real tmux in PATH for every
# agent process tree, so scripts, exit traps, and subshells inherit it.
# Refuses server-wide teardown unless a human explicitly overrides.
# Three fleet outages were caused by kill-server reaching the default
# socket; command-string hooks cannot see kills inside scripts — this can.

for arg in "$@"; do
  case "$arg" in
    kill-serv*)
      if [ "${AWEB_TMUX_KILL_OK:-}" != "1" ]; then
        echo "tmux-guard: kill-server REFUSED. It destroys every session on the socket (three fleet outages)." >&2
        echo "tmux-guard: kill only named throwaway sessions under an isolated TMUX_TMPDIR." >&2
        echo "tmux-guard: a human may override with AWEB_TMUX_KILL_OK=1." >&2
        exit 86
      fi
      ;;
  esac
done

self_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) || exit 127
clean_path=
old_ifs=$IFS
IFS=:
for dir in $PATH; do
  canonical_dir=$(CDPATH= cd -- "${dir:-.}" 2>/dev/null && pwd -P) || canonical_dir=
  [ "$canonical_dir" = "$self_dir" ] && continue
  if [ -z "$clean_path" ]; then
    clean_path=$dir
  else
    clean_path=$clean_path:$dir
  fi
done
IFS=$old_ifs
PATH=$clean_path
export PATH

real_tmux=$(command -v tmux 2>/dev/null || true)
if [ -z "$real_tmux" ] || [ ! -x "$real_tmux" ]; then
  echo "tmux-guard: real tmux executable not found after removing $self_dir from PATH" >&2
  exit 127
fi
exec "$real_tmux" "$@"
