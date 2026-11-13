---
type: Lesson
title: A refusal test snapshots the home, not only outbound requests
description: A test that a command refuses before acting asserts both halves of "nothing happened", no outbound request and a byte-identical home; locks and markers come only after the read-only checks that can refuse, which are repeated under the lock, and a real-binary refusal fixture also runs a positive control.
tags: [lesson, testing, review, aw-cli, identity]
timestamp: 2026-11-13
---

Learned on 2026-11-13 in review of `aw id create --no-address`. The creation
took its creation lock, which creates a lock file, before checking that the
home was its own. Every refusal test asserted `identity_exists` and zero
registrations, and all of them passed. Yet a refused foreign or complete
identity home gained a lock file. Reviewers asked for "no publication or
state change". Only a before-and-after byte snapshot of the home (files by
content, symlinks by target) then showed the side effect, in the unit cases
and the real-binary case at once. The fix (dafb75279, on main) runs the home
checks read-only before the lock and again under it.

# The rules

- **Assert both halves of "nothing happened".** A command that promises to
  refuse before acting is tested for no outbound request *and* for a
  byte-identical snapshot of every local directory it may touch. Counting
  requests alone misses local side effects.
- **Refuse before you mark.** Take locks and write markers only after the
  read-only checks that can refuse. Repeat those checks under the lock, for
  the race.
- **Rejected: removing the lock file after a refusal or a success.** Windows
  cannot remove a file while it is open.
- **A real-binary refusal fixture runs a positive control.** When the refusal
  test asserts that a side effect did *not* happen (for example, a due
  encryption assertion was not renewed), the same fixture also runs an
  ordinary command that does cause it. That proves the fixture would have
  seen the side effect. This is the control rule of
  [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)
  applied to refusal tests.

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/refusal-tests-snapshot-the-home.md. Commit dafb75279 is on main; its
message describes the pre-lock check, and its test adds the home snapshot and
the renewal control. The review NACKs and ACKs (4e687764, 6e5ca057) are the
source's report.
