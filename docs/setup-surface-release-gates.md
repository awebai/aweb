---
title: "CLI setup surface release gates"
kicker: "Release checklist"
description: "Regression gates for the primitive-first aw team/identity/setup surface."
weight: 25
---

# CLI setup surface release gates

Run these gates before releasing changes that affect `aw` team, identity,
workspace setup, bootstrap compatibility, skills, or resource-pack templates.

## Fast setup-surface gate

```bash
scripts/check-setup-surface.sh
```

This checks:

- generated CLI reference is current;
- resource-pack manifests and paths are valid;
- root help still exposes the intended command buckets;
- the retired `aw agents` command family stays absent from help;
- resource-pack role application stays novice-friendly through `aw roles add`.

## Full CLI gate

```bash
scripts/regenerate-cli-reference.sh --check
scripts/check-resource-packs.sh
cd cli/go && go test ./cmd/aw
```

Use this before pushing or asking for review on CLI behavior changes.

## Manual review checklist

- Top-level `aw --help` keeps these buckets visible:
  - Workspace Setup;
  - Identity;
  - Messaging & Network;
  - Coordination & Runtime;
  - Obsolete / Legacy Compatibility;
  - Utility.
- Everyday setup commands are prominent: `aw init`, `aw team`, `aw workspace
  connect`, `aw check`, `aw workspace status`, `aw whoami`.
- Protocol/admin commands use protocol/admin language, especially BYOT
  namespace/team controller operations.
- The retired `aw agents bootstrap`, `provision`, `add`, `add-worktree`, and
  related layout commands are not documented as callable setup paths.
- Setup commands do not overwrite or delete `.aw` identity state, signing keys,
  encryption keys, namespace controller keys, or team controller keys.
- Any command that spans more than one authority boundary has a dry-run, a
  preflight, rollback, or explicit recovery path.
- Public docs and dashboard copy do not teach bootstrap-era templates as the
  product center.
- Resource-pack templates keep canonical resources harness-neutral and do not
  include DIDs, certificates, aliases, `.aw` state, generated work symlinks, or
  canonical `CLAUDE.md` as the source of truth.

## Review handoff

When requesting review, include:

- commit range;
- commands run;
- whether generated CLI reference changed;
- whether retired-bootstrap/recoverability tests changed;
- any hosted vs BYOT authority decision that was deferred.
