---
type: Lesson
title: Fix the harness, do not route around it
description: When a seat's harness fails to spawn, check the installed CLI itself before reasoning about packages, and reinstall it rather than switching harness; new seats keep their soul's declared launch, because a ruling to restart particular seats on another runtime does not extend to new spawns.
timestamp: 2026-10-24
---

Every spawn of one harness hung and previews reported the package "not
verifiable". The coordinator had already worked around it once by spawning a
seat on a different runtime, extending a ruling that had only said to restart
particular seats on that runtime. The cause was trivial: a test fixture had
overwritten the globally installed harness CLI with an 85-byte stub that
printed a fixture message and slept. A plain reinstall fixed it. The operator:
"if we cannot spawn [it] that is a big problem. confirming whether the package
is installed and isntalling it if not should be absolutely trivial."

## How to apply

- When a harness spawn or preview fails, first check the installed CLI:
  `--version`, then the size and modification time of the file its symlink
  resolves to. Reinstall if it is wrong.
- Keep each soul's declared launch for new spawns unless the operator says
  otherwise; a runtime switch for named seats does not carry over.
- The real fix belongs in code: a test must write fixtures to a temporary path,
  never over a global install (tracked as aweb-acle).

Related: [resolve the component before diagnosing it](resolve-the-component-before-diagnosing-it.md).

## Provenance

Harvested 2026-10-25 from the `naapps` coordinator seat (note
`pi-cli-clobbered-by-fixture.md`; operator turn of 2026-10-24T16:35Z in its
session transcript).
