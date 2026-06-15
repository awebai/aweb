---
name: spawn-instance
description: Add a teammate — create an instance of a soul with its own new aweb identity and home, plus its own git worktree for developers. Use when a human asks for a teammate or assigned work needs one.
---

# Spawn an instance of a soul

Souls (`agents/souls/<role>/`) are the canonical agent bodies. An
**instance** is a runnable copy with its **own new aweb identity**:

- **Home** — `agents/instances/<name>/`: holds the body (`AGENTS.md`
  symlinked to the soul) and the identity (`.aw`). The session runs here.
- **`work`** — where it does the job, per the soul's `soul.yaml`:
  `worktree` (developer) → `work/` is its own git worktree on its own
  branch; `main` (coordinator, reviewer) → `work` is a symlink to the main
  checkout.

**Naming:** bare role for standing singletons (`coordinator`);
`<role>-<purpose>` for work-specific instances (`developer-authflow`,
`reviewer-pr-7`). Spawn when a human asks, or when assigned work needs a
teammate — not on your own initiative to "get help".

## Prepare — run as one block, from your own instance home

`aw` reads your identity from the current directory's `.aw`, so run this
from your own home:

```bash
role=<role>; name=<name>          # e.g.  role=developer  name=developer-authflow

REPO="$(cd "$(git rev-parse --git-common-dir)" && cd .. && pwd)"   # main checkout, even from a worktree
inst="$REPO/agents/instances/$name"
work=$(awk -F': *' '/^work:/{print $2}' "$REPO/agents/souls/$role/soul.yaml" | awk '{print $1}')

# 1) Invite from your own identity; capture the token.
TOKEN="$(aw id team invite 2>&1 | awk '/^Token:/{print $2}')"
[ -n "$TOKEN" ] || { echo "no token — run from your OWN instance home"; exit 1; }

# 2) Make the home; the new identity joins the team there.
mkdir -p "$inst"
( cd "$inst" && aw id team accept-invite "$TOKEN" --alias "$name" && aw init --do-not-touch-agents-md --alias "$name" )

# 3) Wire the body, and harness links (Claude Code shown).
ln -sfn "$REPO/agents/souls/$role/AGENTS.md" "$inst/AGENTS.md"
ln -sfn AGENTS.md "$inst/CLAUDE.md"

# 4) The work location.
if [ "$work" = worktree ]; then
  git -C "$REPO" worktree add "$inst/work" -b "$name"
else
  ln -sfn "$REPO" "$inst/work"
fi

echo "ready — home: $inst"
```

If you have no connected instance yet (or your CLI predates
`aw id team invite`), use the dashboard instead of steps 1–2: create the
home directory and run the dashboard-generated
`AWEB_API_KEY=... AWEB_URL=... aw init ...` from it. The rest is the same.

> ⚠️ **Never move or rename an instance home after `aw init`** — aweb
> registers the workspace at its path. Re-mint in place to relocate.

## Launch

Hand the human the launch command (don't start sessions a human will
drive):

```bash
cd agents/instances/<name> && claude    # or pi/codex, per the soul's runtime
```

When the teammate is no longer needed, use the `retire-instance` skill.
