# aw Go CLI plugin dispatch status

As of 2026-06-16, `cli/go` has no implemented `aw plugin ...` command and no kubectl/gh-style unknown-command fallback from `aw <name>` to an external `aw-<name>` binary. The folio plugin brief defines the target shape (`aw-<name>` dispatch plus `AW_DID`/`AW_TEAM`/`AW_SERVER`/`AW_HOME`/`AW_HELPER` env); the only current generic signed app-call primitive is `aw id request --team-auth`, which builds and signs a v2 team-bound request envelope.
