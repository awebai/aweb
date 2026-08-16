---
name: release
description: Reconcile and publish aweb OSS artifacts with one rerunnable command. Read docs/release.md first.
allowed-tools: Bash(make *), Bash(git *), Bash(gh run *), Bash(npm view *), Bash(curl *)
---

# Release aweb OSS artifacts

Read `docs/release.md`, then run from a clean aweb checkout at `origin/main`:

```sh
make release
```

There is no card, prompt, prepare phase, or separate resume command. Reviewed
manifests are the version and compatibility declaration. The command runs the
gate, records an automatic intent in Git tags, and publishes exact OSS artifacts.
Hosted products own their dependency locking and deployment from their own
repositories.

On failure, fix the named external or source problem and run the same command.
Never edit intent tags, move a `release` branch by hand, reuse a conflicting
version, or publish a mutable image tag by hand.
