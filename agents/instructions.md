# Simple dev team

This team was created from the `simple-dev-team` blueprint: a coordinator,
developers in git worktrees, and a fresh-eyes reviewer. The model is one
page: `agents/docs/team-architecture.md`.

## Ground rules

- `agents/souls/<role>/` are the committed agent bodies; they grow with the
  team and are reviewed like code (`self-maintenance` skill). Never edit
  your own AGENTS.md or role.
- `agents/instances/<name>/` are gitignored runnable copies with their own
  identities. Add teammates with `spawn-instance`, remove them with
  `retire-instance` — on human request or when assigned work needs them.
- Keep tasks small and reviewable; prefer the shared task board over
  private notes.
- Implementation gets independent review before merge; verdicts travel
  over chat.
- Use mail for handoffs and status; chat when someone needs an answer
  soon.
- Don't touch another agent's worktree, home, or `.aw/` state.

## Session start (every agent)

```bash
aw workspace status
aw mail inbox
aw chat pending
aw roles show
```
