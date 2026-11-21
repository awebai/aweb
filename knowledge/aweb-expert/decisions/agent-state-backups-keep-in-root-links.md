---
type: Decision
title: Agent-state backups keep in-root links and check every member before writing
description: An archive of an OATS agent's state keeps symbolic links that stay inside it and refuses, before any write, absolute or escaping links, members under a non-directory, duplicate names, device files and undeclared sockets or FIFOs; Python's tarfile filters are not mode-preserving, so the whole member graph is validated first and extracted with "fully_trusted".
tags: [decision, deploy, backup, restore, oats, tar]
timestamp: 2026-11-18
---

Decided on 2026-11-18 in the team-deployment state-archive work (task
acwd.25.1). teamctl's backup accepted only regular files and directories. Every
OATS instance home contains symbolic links (`CLAUDE.md -> AGENTS.md` and
`.claude/skills -> ../.agents/skills`), and the deployment's agent state holds
those homes. So a backup of any agent state that had a spawned instance was
refused. Nobody had noticed because no backup had yet been run against one.

# Decision

An archive of an agent's state keeps regular files, directories, hard links to
an earlier regular file, and symbolic links. Before anything is written, on
both pack and restore, the whole member list is checked. It refuses:

- an absolute link;
- a link that resolves outside the archive when it is followed through the
  archive's own links. A lexical check misses chains such as `here -> .`
  followed by `out -> here/..`;
- a member under any ancestor that is not a directory: a symbolic link, a
  regular file or a hard link. Review found that `file` followed by
  `file/child` passed when only link ancestors were checked;
- a name given twice;
- device files.

Links are created last on restore, and a restore writes only where nothing
exists yet.

Sockets and FIFOs: a socket is left out only where a declared rule names one
that the runtime recreates at a configured root (in aw 1.36.58, the wake
broker's `control.sock` in the wake store, and `run/custody.sock` in a grant
home only). Each one left out is recorded in the backup's manifest, because
stderr is not a durable record. Any other socket, and any FIFO, refuses the
capture.

# Python's tarfile filters do not preserve modes

The `"tar"` extraction filter clears setuid/setgid and group/other write bits,
so neither it nor `"data"` can be the path for a restore that keeps owners and
modes. Do the validation yourself over the whole member graph, then extract
with `filter="fully_trusted"` and `numeric_owner=True`. A future change to
backup or restore must not swap in a stricter tarfile filter for safety: that
silently changes the restored modes.

# Rejected

- **Regular files and directories only** (the earlier behaviour): this makes
  the backup unusable for the only state it exists to protect.
- **Dereferencing links when packing:** this changes what a restore produces.
  The restored home would have copies where OATS expects links.
- **Refusing all links:** this has the same effect as the first option.

# Status

As of 2026-11-18 the change is on the aweb task branch
`agents/aweb-expert-deploy-team-acwd25-state-archive` (head b2dac36aba, under
review), not on main. The harvester read `deploy/team/state_archive.py` and
`deploy/team/agent_state.py` at that head, and the refusals and the
`fully_trusted` extraction are there. The lower-level packer reports sockets
and FIFOs as left out, and the agent-state capture turns any undeclared one
into a refusal. A lab rehearsal with age v1.3.2 on fictional state is
source-reported to have passed (eight cases, with numeric owners and
setuid/setgid modes round-tripped as root). Its limits are that the state was
fictional, the keys were disposable and there was no replacement host. Check
main before relying on the code.

The child-process side of the same tool is in
[a tool that pipes through a child owns it on every path](/aweb-expert/lessons/a-tool-that-pipes-through-a-child-owns-it-on-every-path.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-18;
notes/agent-state-backups-keep-in-root-links.md. The review findings and the
lab rehearsal are source-reported. The harvester checked the code on the task
branch at b2dac36aba and the two OATS home links on a current OATS instance
home. The `"tar"` filter's mode clearing is documented Python behaviour.
