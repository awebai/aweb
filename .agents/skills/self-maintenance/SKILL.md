---
name: self-maintenance
description: How any agent grows its soul as it works — adding to its docs, decisions, memory, and skills (but never its AGENTS.md or role). Use whenever you learn something durable mid-work that a future instance of you should keep.
---

# Maintain your soul

Your **soul** (`agents/souls/<your-role>/`) is your durable body — it
travels and grows with the repo, so a fresh session of you keeps what
earlier sessions learned. As you work, when you hit something durable worth
keeping, write it into your soul. That's how the team gets short, focused
sessions without losing knowledge between them.

## What you grow

- **Docs** (`docs/`) — reference notes on how things actually work.
- **Decisions** (`decisions/`) — durable choices/stances you commit to.
- **Memory** (`memory/<slug>.md`, indexed in `MEMORY.md`) — single durable
  facts.
- **Skills** (`.agents/skills/<name>/SKILL.md`) — reusable procedures you'll
  need again; create or change them when a real, recurring procedure
  appears.

## What you must NOT change

**Never edit your `AGENTS.md` or your role.** Those define who you are and
how you operate — deliberate, human/review-owned, not something you rewrite
mid-work. Grow your *knowledge*; leave your *identity* alone.

Never store secrets, invite tokens, private keys, `.aw` state, DIDs,
addresses, or certificates in a soul.

## The bar — useful, not noisy

Recording costs context every future instance must read and keep true. Write
something down **only when both are true**: (1) it really matters and is
durable, and (2) it would change what a future instance of you does. If it
wouldn't, leave it in chat. Don't journal routine work, don't duplicate the
code or git history, and prune what goes stale. A small, true soul beats a
large, rotting one.

Soul changes are commits like any other — they reach the main branch through
the team's normal review path.

## Reviewer exception

The **reviewer** keeps *no* memory or decisions — it reviews with fresh eyes
every time, so accumulated context would only bias it. Its one persisted
artifact is `patterns/common-failure-patterns.md` (generalized
recurring-issue categories), never verdicts or memory about a specific
change. If you're the reviewer, that overrides the "grow your
memory/decisions" guidance above.
