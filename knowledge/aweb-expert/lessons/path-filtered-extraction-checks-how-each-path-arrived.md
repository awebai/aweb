---
type: Lesson
title: A path-filtered extraction checks how each path arrived
description: Extracting part of aweb with its history loses two things a path filter cannot see, the pre-merge history of directories that came in by subtree merge and the history of files renamed in from outside; prefix the subtree commits in the same filter-repo pass, and find inbound renames with a scan that has no pathspec.
tags: [lesson, git, repository-split, history, extraction]
timestamp: 2026-11-25
---

When the applications were extracted from aweb into their own repository
(aweb main at d8ee9ed31ad2, November 2026), a plain
`git filter-repo --path <dir> ...` would have kept the paths and silently
dropped part of their history, in two ways.

# Subtree merges store the earlier history at the root

`naapp-lib/`, `naapp/folio/` and `naapp/library/` entered aweb on 2026-07-29
as subtree merges ("Merge aweb-naapp into naapp-lib at ...", c97e90af1;
"Merge folio into naapp/folio at ...", da3e33632; "Merge library into
naapp/library at ...", 3d2861ee2). Each merge's second parent is the original
repository, with its files at the root: 12, 125 and 174 commits whose paths
are not under the directory being kept. A path filter discards all of them.

- Before an extraction, find how each kept directory arrived: the first commit
  that touches it. A "Merge X into <dir>" first commit is a subtree merge.
- Rewrite those commits' paths under their directory and select paths in the
  same pass. The source reports that filter-repo applies `--path` before
  `--commit-callback`, so a commit callback does both the prefixing and the
  path selection.

# A pathspec hides renames into the paths it names

`git log -M --diff-filter=R -- <kept paths>` cannot report a file renamed into
the kept paths from outside them: the pathspec removes the rename's source
before rename detection, and the commit shows only an addition. The check
returns nothing whatever the history is, so it is a detector that cannot fire
(see [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)).
The source's first "no inbound renames" check used that form and was invalid.

- Scan every non-merge commit with no pathspec,
  `git log --no-merges -M --diff-filter=R --name-status`, and keep the rows
  whose destination is inside the kept paths and whose source is outside.
- In the apps extraction that scan found two inbound renames,
  `docs/vectors/hook-delivery-credential-v1.json` to `-v2.json` and
  `docs/vectors/egress-url-v1.json` to `-v2.json`.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-25;
notes/extraction-preserves-subtree-history.md and
notes/pathspec-hides-inbound-renames.md. Checked at harvest on aweb main
1378733f0: the three merges' subjects and dates, their second parents' root
layout and commit counts (12, 125, 174); the no-pathspec scan reports both
`docs/vectors` renames, and the same scan with those two files as the pathspec
reports no rename (`hook-delivery-credential-v2.json` appears as an addition
in 6c9b85bee). The filter-repo callback ordering is the source's report.
