---
type: Decision
title: A release bump is one reviewed commit, merged into each composed gate base
description: The version bump is written and reviewed once as a single commit on top of main; each time the release gate base is composed or rebuilt, the bump's author merges it in (base first parent, bump second, never rebased), resolves the CHANGELOG so it follows the code in the base, and gets a separate ACK for that merge alone.
tags: [decision, release, review, changelog, git]
timestamp: 2026-11-28
---

The dispatch seat composes the release gate base from main and `--no-ff`
merges of the reviewed heads. The release bump changes the version,
CHANGELOG, dependency floors and locks. It is reviewed separately from the
heads, and it has to survive the base being rebuilt.

# Decision

- **One bump commit.** The bump is written once, as a single reviewed commit on
  top of main. It is never rebased onto a base.
- **The author merges it into each base.** Each time the dispatch seat
  composes or rebuilds the gate base, the bump's author merges the bump into
  it. The base is the first parent and the bump the second. The author, not
  the seat that gates the base, resolves the CHANGELOG conflict.
- **The merge gets its own ACK.** That review asks three questions:
  1. Does `git diff <base>...<merge>` equal the bump's own diff outside
     `CHANGELOG.md`? Compare after dropping the `^index` lines.
  2. Is every base CHANGELOG line kept, with each bump entry appearing once?
  3. Is the lock check green?
- **The CHANGELOG follows the code in the base.**
  - When the base carries a head's code but not that head's CHANGELOG
    commit, copy the entry verbatim from the ACKed commit. Never write it by
    hand.
  - Code that is not in the base gets no entry.
  - A head whose review was RETURNed stays out of the base. Wait for its ACKed
    successor rather than shipping it.
- **Supersede explicitly.** When the base changes, the earlier merge and its
  ACK are superseded, and this is said explicitly. Only the merge is redone and
  re-ACKed; the bump's own review stands.

# Why

Merging keeps the bump's SHA, so its review holds across every rebuild. Only
the small merge, whose scope the three questions bound, is reviewed again. A
CHANGELOG written by hand, or one that lists an entry for code the base
lacks, ships a changelog that does not match the released code. This
applies the "merge, never rebase" rule of the team instructions
(source-reported) and the
[ACK scope rule](/aweb-expert/decisions/evidence-and-reproduction-standard.md)
to a base that is rebuilt during the release. The repository does not say
it.

# Rejected

- **Rebasing the bump onto each base.** Each rebase gives the bump a new SHA,
  so it needs a full re-review on every rebuild.
- **Letting the dispatch seat resolve the bump's conflict.** The seat that
  gates the base would then author part of what it gates.

# Mechanics that helped

`git rerere` recorded the CHANGELOG resolution and replayed it on each
rebuilt base. The first review question is mechanical. At main 361806ee6 no
script runs it, and a script would be the way to make that check routine.

# Evidence

Server 1.27.56, 2026-11-27..28. The gate base was rebuilt twice: the first
gate failed for reasons unrelated to the bump, and the second rebuild
replaced a RETURNed head with its ACKed successor, whose entry was copied
verbatim. The bump af8e4d4e77 was merged three times, into 3a21cc61,
0d72628acf and e47effa492. The final merge 6026edfdc2 has e47effa492 as first
parent and af8e4d4e77 as second. Outside `CHANGELOG.md`, its three-dot diff
from that base equals the bump's own diff (checked by the harvester). It is the
`server-v1.27.56` tag and is on main. The first two merges (4cc779256f,
669590886f), the ACK, the green result of all six gate stages, the rerere
replay and the coordinator directing each step are source-reported. This
was seen in one release only.

Evidence: OKF proposal from aweb-expert/aweb-expert-sec-r1, 2026-11-28;
notes/release-bump-merges-into-each-gate-base.md.
