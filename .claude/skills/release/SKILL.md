---
name: release
description: Reconcile, publish, and deploy aweb and AC with one rerunnable command. Use for any production artifact release; read docs/release.md first.
allowed-tools: Bash(make *), Bash(git *), Bash(gh run *), Bash(npm view *), Bash(curl *)
---

# Release aweb and AC

Read `docs/release.md`, then run from a clean aweb checkout at `origin/main`:

```sh
make release AC_ROOT=/path/to/ac
```

There is no card, prompt, prepare phase, or separate resume command. Reviewed
manifests are the version and compatibility declaration. The command runs the
gates, records an automatic intent in matching Git tags, publishes exact bytes,
derives and checks AC's complete dependency lock, and deploys an exact digest
when AC changed.

On failure, fix the named external or source problem and run the same command.
Never edit intent tags, move a `release` branch by hand, reuse a conflicting
version, or deploy a mutable image tag.
