---
title: "Improve a profile as the team works"
kicker: "Human + agent guide"
description: "Adopt a public profile, review agent proposals, and refresh approved improvements."
weight: 35
---

# Improve a profile as the team works

Profile evolution is optional. A newly created team runs from pinned public
profiles without installing the Library plugin. Add this loop when the team has
learned something worth preserving in its own operating package.

## Who decides what changes

- The **human** sets policy, chooses who may approve changes, and retains an
  override for exceptional decisions.
- A **working agent** notices a repeatable improvement and proposes a concrete
  profile change. It cannot silently rewrite the team's canonical profile.
- The **reviewing coordinator** checks the proposal against team policy and
  approves or rejects routine changes.

This keeps learning in the team's normal review process instead of requiring a
human to manually edit every profile update.

## 1. Install the Library app

Install the Library plugin once in the environment managing the team:

```bash
aw plugin install https://library.aweb.ai/.well-known/aweb-app.json
```

The plugin provides the private shelf and the proposal/review verbs. Installing
it is not required for public profile materialization or first-run onboarding.

## 2. Adopt one materialized profile

From the team layout, adopt the public pin for one member:

```bash
aw team admin adopt <name>
```

`aw team admin adopt` reads that home's `.aw/profile/ref.json`, imports the pinned
public profile to the team's private shelf, binds the agent, and updates the
local pin to point at the shelf copy. It does not change the agent's runtime,
identity, or team membership.

An already shelf-pinned home should be refreshed, not adopted again.

## 3. Propose a focused improvement

The working agent should begin from the materialized assets under
`.aw/profile/` and propose a small reviewable changeset. The Library plugin's
proposal surface is:

```bash
aw library get-shelf-profile \
  --profile_ref <profile> \
  --include files
```

Use the current shelf asset's `sha256` as its `base_asset_digest`. The proposal
file is a body-shaped JSON object:

```json
{
  "summary": "Sharpen the review checklist",
  "rationale": "The team repeatedly missed the same verification step",
  "content": {
    "schema": "aweb.library.profile-asset-changeset.v1",
    "assets": [
      {
        "path": "instructions.md",
        "content_utf8": "<complete updated file>",
        "base_asset_digest": "sha256:<current-asset-digest>"
      }
    ]
  }
}
```

The content schema literal is required; approval rejects another schema. Each
changed asset needs the digest from the current shelf version.

```bash
aw library propose \
  --target profile \
  --profile_ref <profile> \
  --body-file <proposal.json>
```

The proposal should explain the observed problem, the reusable change, and the
evidence that it improves future work. Do not promote repository-specific
secrets, transient task state, identities, or generated workspace files into a
profile.

## 4. Review and approve

The reviewing coordinator inspects the proposal and its asset changes. If it
meets team policy, approval mints a new version on the private shelf:

```bash
aw library approve --proposal_id <proposal-id>
```

Reject or request a narrower proposal when the change is speculative, hides a
permission increase, weakens review, or only applies to the current task.

## 5. Refresh the agent home

Apply the latest approved shelf version to the local home:

```bash
aw team admin refresh <name>
```

Refresh reads the profile reference recorded locally, re-materializes the
profile assets, and updates `.aw/profile/ref.json`. It never asks a remote
service to guess which profile the agent should use.

After refreshing, restart or re-read the runtime's instructions as appropriate,
then verify that the intended change is present.

## Pulling upstream changes is separate

Approved team-local learning and upstream blueprint releases are composable but
different. Pull an upstream release onto the shelf first, then refresh the
agent:

```bash
aw library update-from-source \
  --profile_ref <profile> \
  --target_version <version>
aw team admin refresh <name>
```

Review upstream changes with the same care as any other dependency update.
