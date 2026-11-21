---
type: Decision
title: Context-changing init remedies go to a new directory
description: After a failed hosted aw init, a refusal whose remedy needs a different name, key, scope or setup command tells the user to keep .aw/partial-init.yaml and run the changed command in a new directory, because the partial state refuses any changed context and holds the only copy of the new key; retryable refusals keep "rerun the same command in this directory". Decided; on a review branch, not yet on main.
tags: [decision, aw-cli, init, hosted, diagnostics, identity]
timestamp: 2026-11-17
---

**Status (checked 2026-11-17):** on the review branch
`agents/aweb-protocol-expert-team-key-trust` at c9f8f8738e, not yet on main.

# Decision

- Every entry in the
  [hosted init refusal vocabulary](/aweb-protocol-expert/decisions/hosted-init-refusals-use-a-fixed-vocabulary.md)
  says whether its remedy needs a different bootstrap context: another name,
  key, scope or setup command.
- For those entries, aw ends the error with: "this attempt's state stays in
  .aw/partial-init.yaml (do not delete it); run the changed command in a new
  directory".
- Retryable refusals keep "rerun the same command in this directory; do not
  delete .aw/partial-init.yaml".
- A test walks every vocabulary entry and checks its suffix, so a new entry
  cannot skip the choice.

# Why

- A failed hosted init leaves `.aw/partial-init.yaml`. It holds the only copy
  of the new signing key, and under `--global` that key's did:aw is already
  registered.
- On resume, the partial state refuses any other bootstrap context: name,
  alias, scope, inbound mode, team, URLs, role, human name, agent type or API
  key. So the user cannot follow a "choose a new name" remedy in that
  directory.
- The general rule: a remedy aw prints must be one the user can follow given
  aw's own local state. A remedy that aw then refuses is worse than none.

# Rejected alternatives

- **One "rerun the same command" suffix, with "choose a new name" in the
  remedy.** It tells the user to do something aw then refuses.
- **Telling the user the directory is safe to delete.** The partial state
  holds the only copy of the key.

Acceptance: ruled by Antares on 2026-11-17 under Juan's delegation of
identity-path calls, relayed by the coordinator. Source-reported (coordinator
mail e4aa9c19).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-17; notes/hosted-init-refusal-display.md. Checked by the harvester against c9f8f8738e: partialInitGuidance and the changesContext flag in cli/go/cmd/aw/init_apikey_diagnostic.go, validateAPIKeyPartialInitContext in cli/go/cmd/aw/init_apikey.go, and the resumable-failure paragraphs of docs/hosted-global-bootstrap.md.
