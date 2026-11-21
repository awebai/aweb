---
type: Decision
title: After a team-create conflict, a failed read is "could not confirm"
description: When aw id team create gets a 409 and the read of the existing team fails without an answer, it refuses with team_name_unconfirmed and sets its newly created key aside by hard link and unlink, never deleting it or leaving it in place, and settles it on the first read that answers; a 403 team_private on a read signed with that key is a definite answer (taken), not a failure. On a handed-back branch, not yet on main.
tags: [decision, teams, key-custody, registry, errors, aw-cli]
timestamp: 2026-11-21
---

After a 409 on team create, aw reads the existing team to learn whether the
registry pins the key this run just created. That read can fail with a
network error or a 5xx. Reporting `team_name_taken` then claims knowledge the
run does not have.

# Decision

- A read that fails without an answer is "could not confirm": refuse with
  `team_name_unconfirmed`.
- Set the key this run created aside at `<key>.unconfirmed`. While that file
  exists, loading the team key refuses (`ErrTeamKeyUnconfirmed`), so no path
  uses it as the team key. While reads keep failing, no new key is created.
- The next registration run settles it on the first read that answers:
  restore the key if the registry pins it, remove it if the registry pins
  another key.
- The move is a hard link followed by an unlink, not a rename. A rename would
  silently replace a key already set aside; a link fails with EEXIST, is
  atomic, copies nothing and keeps the 0600 mode.

# A refusal can be an answer

A private team's 403 `team_private` is not a failed read. The registry
verifies a supplied signature first (a bad one is refused, never read as
anonymous), and answers `team_private` only when the verified key is neither
the team key nor an unrevoked member key. So `team_private` on a read signed
with the key this run holds is definite: the registry pins another key. It
settles as `team_name_taken` and the unregistered key is removed, which main's
`TestOATSRealTeamNameTakenPreservesThePrivateTeamBoundary` pins. Classing it
as unconfirmed first turned that test red.

Before classing a refusal as "could not confirm", check what the server must
know to send it. A refusal that only a knowledgeable server can send is an
answer.

# Rejected

- **Deleting the created key.** Another run on the same machine may have
  loaded that key from the file and registered it first; deleting it would
  destroy a registered controller key and lose custody in the race.
- **Keeping the key in place.** A later run would take it as the team's key
  on the strength of a read that never answered.

The general rule behind "unconfirmed" is
[a read that cannot tell is not the permissive answer](/aweb-protocol-expert/lessons/a-read-that-cannot-tell-is-not-the-permissive-answer.md).

Status: chosen by the coordinator and the task's reviewer (option b of
02ce0dd6, source-reported) and implemented on branch
`agents/aweb-protocol-expert-chat-verify-adje3` (commits c5e0296bb2,
524af73b62, 00ee8709fd; head 5e758c7bb5, handed back 2026-11-21); not yet on
main or released.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-21; notes/a-failed-read-is-not-absence-for-key-custody.md. The registry's signed-read rule in `awid/src/awid_service/routes/teams.py` and the link-based set-aside in `cli/go/awconfig/team_keys.go` verified on the branch.
