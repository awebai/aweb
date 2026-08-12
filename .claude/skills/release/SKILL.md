---
name: release
description: Release aweb and AC artifacts through the two-command train - prepare, one human go, continue. Use for any publication, and read docs/release.md before authorizing one.
allowed-tools: Bash(make *), Bash(git *), Bash(gh run *), Bash(npm view *), Bash(curl *)
---

# Release aweb and AC artifacts

`docs/release.md` is the authoritative specification. Exactly two operator
commands exist, both run from the aweb repository root:

```sh
PURPOSE="..." COMPAT_BREAK="none" make release-prepare
# Juan reviews the script-generated release card and gives ONE go
make release-continue
```

## What prepare does

Selects the exact aweb and AC main commits (tips, or `AWEB_SHA=`/`AC_SHA=`
older pushed commits), computes which artifacts move (a component moves iff
its manifest version is absent from its registry), runs the aweb clean-Docker
gate once, records the reviewed AC base, and writes the transient git-local
release card. It performs no outward mutation; a failed prepare leaves no
valid card.

## What continue does

Reads only the fixed unconsumed card - no arguments, no prompts - and executes
the hardcoded ten-edge train idempotently: aweb `release` fast-forward, thin
publication workflows in DAG order, marketplace pointer, public registry
polling, the derived dependency-only AC commit at the recorded base, the AC
clean-Docker gate, AC `release`, exact-digest Render deployment with
migrations first, and site branch pushes. Exact matches adopt; conflicts stop
named; a failure leaves pointers put and keeps the card for retry. At DONE it
prints versions/digests/final AC SHA and consumes the card.

## Hazards

- Never edit the card, force a `release` branch, or rerun tests to make a
  gate green. A material change means a fresh prepare and a fresh go.
- GitHub outage stops the train. The kept `scripts/*-exact-publish.sh`
  primitives may be used only under an explicit human risk override, and
  bookkeeping resumes by exact-match adoption when GitHub returns.
- Publication is not delivery, publication is immutable.
